// src/firewall/firewall_backend.cpp
#include "firewall_backend.hpp"
#include "../common/logger.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sstream>

// ════════════════════════════════════════════════════════════════════════════
// Helpers (file-scope)
// ════════════════════════════════════════════════════════════════════════════

static bool hasRoot() { return ::geteuid() == 0; }

static bool cmdExists(const std::string& bin) {
    return ::system(("command -v " + bin + " >/dev/null 2>&1").c_str()) == 0;
}

// Chạy shell command, log, trả về true nếu exit 0
static bool sh(const std::string& cmd) {
    LOG_INFO("[fw] " + cmd);
    return ::system(cmd.c_str()) == 0;
}

// Chạy, bỏ qua lỗi (luôn thành công)
static void shOk(const std::string& cmd) {
    LOG_INFO("[fw] " + cmd);
    ::system((cmd + " 2>/dev/null || true").c_str());
}

// ════════════════════════════════════════════════════════════════════════════
// NftablesBackend
// ════════════════════════════════════════════════════════════════════════════

// Gửi script nhiều dòng vào stdin của "nft -f -"
bool NftablesBackend::nftBatch(const std::string& script) const {
    LOG_INFO("[nft batch]\n" + script);
    FILE* fp = ::popen("nft -f - 2>&1", "w");
    if (!fp) {
        LOG_WARN("NftablesBackend: popen failed");
        return false;
    }
    ::fwrite(script.c_str(), 1, script.size(), fp);
    const int ret = ::pclose(fp);
    if (ret != 0)
        LOG_WARN("NftablesBackend: batch failed (exit="
                 + std::to_string(ret) + ")");
    return ret == 0;
}

// Lệnh đơn không có { } — dùng system() bình thường
bool NftablesBackend::nftCmd(const std::string& args) const {
    const std::string cmd = "nft " + args + " 2>/dev/null";
    LOG_INFO("[nft] " + cmd);
    return ::system(cmd.c_str()) == 0;
}

// ─────────────────────────────────────────────────────────────────────────────

NftablesBackend::NftablesBackend() {
    if (!hasRoot()) {
        LOG_WARN("NftablesBackend: no root — unavailable");
        return;
    }
    if (!cmdExists("nft")) {
        LOG_WARN("NftablesBackend: nft binary not found");
        return;
    }
    available_   = true;
    chain_ready_ = ensureTable();
}

NftablesBackend::~NftablesBackend() = default;

bool NftablesBackend::isAvailable() const {
    return available_ && chain_ready_;
}

bool NftablesBackend::ensureTable() {
    // Tạo table + set + chain bằng batch script
    // Dùng "add" thay vì "create" → idempotent (không lỗi nếu đã tồn tại)
    const std::string setup = R"(
add table inet ids
add set inet ids blacklist { type ipv4_addr; flags interval; comment "IDS auto-block"; }
add set inet ids whitelist { type ipv4_addr; flags interval; comment "IDS whitelist"; }
add chain inet ids input { type filter hook input priority -10; policy accept; }
add chain inet ids forward { type filter hook forward priority -10; policy accept; }
)";

    if (!nftBatch(setup))
        LOG_INFO("NftablesBackend: setup batch non-zero"
                 " (table may already exist — continuing)");

    // Thêm rules vào chain — kiểm tra trước để idempotent
    if (!sh("nft list chain inet ids input 2>/dev/null"
            " | grep -q 'saddr @whitelist accept'"))
        nftBatch("add rule inet ids input  ip saddr @whitelist accept\n");

    if (!sh("nft list chain inet ids input 2>/dev/null"
            " | grep -q 'saddr @blacklist drop'"))
        nftBatch("add rule inet ids input  ip saddr @blacklist drop\n");

    if (!sh("nft list chain inet ids forward 2>/dev/null"
            " | grep -q 'saddr @whitelist accept'"))
        nftBatch("add rule inet ids forward ip saddr @whitelist accept\n");

    if (!sh("nft list chain inet ids forward 2>/dev/null"
            " | grep -q 'saddr @blacklist drop'"))
        nftBatch("add rule inet ids forward ip saddr @blacklist drop\n");

    // Verify — nft list table không cần -n (không có DNS lookup)
    if (!sh("nft list table inet ids >/dev/null 2>&1")) {
        LOG_WARN("NftablesBackend: table inet ids verify FAILED");
        return false;
    }

    LOG_INFO("NftablesBackend: table inet ids OK");
    return true;
}

bool NftablesBackend::applyRule(const FirewallRule& rule) {
    if (!available_) return false;
    if (!chain_ready_) chain_ready_ = ensureTable();
    if (!chain_ready_) return false;

    const std::string set =
        (rule.action == FirewallRule::Action::BLOCK) ? "blacklist" : "whitelist";

    // Dùng batch để tránh shell escape vấn đề với { }
    const std::string script =
        "add element inet ids " + set + " { " + rule.src_ip + " }\n";

    const bool ok = nftBatch(script);
    if (ok)
        LOG_INFO("NftablesBackend: [" + set + "] +++ " + rule.src_ip);
    else
        LOG_WARN("NftablesBackend: [" + set + "] FAILED +++ " + rule.src_ip);
    return ok;
}

bool NftablesBackend::removeRule(const FirewallRule& rule) {
    if (!available_) return false;

    const std::string set =
        (rule.action == FirewallRule::Action::BLOCK) ? "blacklist" : "whitelist";

    // Bỏ qua lỗi nếu IP không tồn tại trong set
    const std::string script =
        "delete element inet ids " + set + " { " + rule.src_ip + " }\n";

    nftBatch(script);
    LOG_INFO("NftablesBackend: [" + set + "] --- " + rule.src_ip);
    return true;
}

bool NftablesBackend::flush() {
    if (!available_) return false;
    nftBatch("flush set inet ids blacklist\nflush set inet ids whitelist\n");
    LOG_INFO("NftablesBackend: flushed blacklist + whitelist");
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// IptablesBackend  (fallback khi không có nftables)
// ════════════════════════════════════════════════════════════════════════════

bool IptablesBackend::shell(const std::string& cmd) const {
    LOG_INFO("[ipt] " + cmd);
    return ::system(cmd.c_str()) == 0;
}

IptablesBackend::IptablesBackend() {
    if (!hasRoot()) {
        LOG_WARN("IptablesBackend: no root — unavailable");
        return;
    }
    if (!cmdExists("iptables")) {
        LOG_WARN("IptablesBackend: iptables binary not found");
        return;
    }
    available_   = true;
    chain_ready_ = ensureChain();
}

IptablesBackend::~IptablesBackend() = default;

bool IptablesBackend::isAvailable() const {
    return available_ && chain_ready_;
}

bool IptablesBackend::ensureChain() {
    // Tạo chain — bỏ qua lỗi nếu đã tồn tại
    shOk("iptables -N IDS_WHITE");
    shOk("iptables -N IDS_BLOCK");

    // Gắn vào INPUT — whitelist (priority 1) trước, block (priority 2) sau
    shOk("iptables -C INPUT   -j IDS_WHITE 2>/dev/null"
         " || iptables -I INPUT   1 -j IDS_WHITE");
    shOk("iptables -C INPUT   -j IDS_BLOCK 2>/dev/null"
         " || iptables -I INPUT   2 -j IDS_BLOCK");

    // Gắn vào FORWARD
    shOk("iptables -C FORWARD -j IDS_WHITE 2>/dev/null"
         " || iptables -I FORWARD 1 -j IDS_WHITE");
    shOk("iptables -C FORWARD -j IDS_BLOCK 2>/dev/null"
         " || iptables -I FORWARD 2 -j IDS_BLOCK");

    // ── FIX: dùng -n để tắt DNS reverse lookup → không bao giờ treo ────────
    // iptables -L (không có -n) sẽ resolve từng IP trong chain → timeout
    // iptables -n -L → in IP thô, không gọi DNS, trả về ngay lập tức
    if (!sh("iptables -n -L IDS_BLOCK >/dev/null 2>&1")) {
        LOG_WARN("IptablesBackend: chain IDS_BLOCK verify FAILED");
        return false;
    }
    if (!sh("iptables -n -L IDS_WHITE >/dev/null 2>&1")) {
        LOG_WARN("IptablesBackend: chain IDS_WHITE verify FAILED");
        return false;
    }

    LOG_INFO("IptablesBackend: chains IDS_BLOCK + IDS_WHITE OK");
    return true;
}

bool IptablesBackend::applyRule(const FirewallRule& rule) {
    if (!available_) return false;
    if (!chain_ready_) chain_ready_ = ensureChain();
    if (!chain_ready_) return false;

    std::string cmd;

    if (rule.action == FirewallRule::Action::ALLOW) {
        // Whitelist: RETURN để thoát khỏi IDS_BLOCK
        cmd = "iptables -C IDS_WHITE -s " + rule.src_ip
            + " -j RETURN 2>/dev/null"
            + " || iptables -A IDS_WHITE -s " + rule.src_ip + " -j RETURN";
    } else {
        // Blacklist: DROP — có thể filter theo protocol
        if (rule.protocol != 0) {
            const std::string proto =
                rule.protocol == 6  ? "tcp"  :
                rule.protocol == 17 ? "udp"  :
                rule.protocol == 1  ? "icmp" :
                std::to_string(static_cast<int>(rule.protocol));

            cmd = "iptables -C IDS_BLOCK -s " + rule.src_ip
                + " -p " + proto + " -j DROP 2>/dev/null"
                + " || iptables -A IDS_BLOCK -s " + rule.src_ip
                + " -p " + proto + " -j DROP";
        } else {
            // Tất cả protocol
            cmd = "iptables -C IDS_BLOCK -s " + rule.src_ip
                + " -j DROP 2>/dev/null"
                + " || iptables -A IDS_BLOCK -s " + rule.src_ip + " -j DROP";
        }
    }

    const bool ok = shell(cmd);
    if (ok)
        LOG_INFO("IptablesBackend: +++ " + rule.src_ip);
    else
        LOG_WARN("IptablesBackend: FAILED +++ " + rule.src_ip);
    return ok;
}

bool IptablesBackend::removeRule(const FirewallRule& rule) {
    if (!available_) return false;

    if (rule.action == FirewallRule::Action::ALLOW) {
        shOk("iptables -D IDS_WHITE -s " + rule.src_ip + " -j RETURN");
    } else {
        if (rule.protocol != 0) {
            const std::string proto =
                rule.protocol == 6  ? "tcp"  :
                rule.protocol == 17 ? "udp"  :
                rule.protocol == 1  ? "icmp" :
                std::to_string(static_cast<int>(rule.protocol));
            shOk("iptables -D IDS_BLOCK -s " + rule.src_ip
                 + " -p " + proto + " -j DROP");
        } else {
            shOk("iptables -D IDS_BLOCK -s " + rule.src_ip + " -j DROP");
        }
    }

    LOG_INFO("IptablesBackend: --- " + rule.src_ip);
    return true;
}

bool IptablesBackend::flush() {
    if (!available_) return false;
    shOk("iptables -F IDS_BLOCK");
    shOk("iptables -F IDS_WHITE");
    LOG_INFO("IptablesBackend: flushed IDS_BLOCK + IDS_WHITE");
    return true;
}
