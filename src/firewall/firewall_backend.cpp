// src/firewall/firewall_backend.cpp
#include "firewall_backend.hpp"
#include "../common/logger.hpp"
#include <cstdlib>
#include <sstream>
#include <arpa/inet.h>

// ════════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════════

static std::string protoStr(uint8_t proto) {
    switch (proto) {
        case  1: return "icmp";
        case  6: return "tcp";
        case 17: return "udp";
        default: return "";
    }
}

// action → iptables target string
static std::string actionTarget(FirewallRule::Action action) {
    switch (action) {
        case FirewallRule::Action::BLOCK:
            return "-j DROP";
        case FirewallRule::Action::ALLOW:
            return "-j ACCEPT";
        case FirewallRule::Action::RATE_LIMIT:
            return "-m limit --limit 10/min --limit-burst 20 -j ACCEPT";
    }
    return "-j DROP";
}

// ════════════════════════════════════════════════════════════════════════════
// IptablesBackend
// ════════════════════════════════════════════════════════════════════════════

IptablesBackend::IptablesBackend(const std::string& chain)
    : chain_(chain)
{
    initialized_ = initChain();
}

bool IptablesBackend::isAvailable() const {
    return system("which iptables > /dev/null 2>&1") == 0;
}

bool IptablesBackend::execCmd(const std::string& cmd) const {
    LOG_INFO("iptables exec: " + cmd);
    const int ret = system(cmd.c_str());
    if (ret != 0)
        LOG_WARN("iptables failed (exit=" + std::to_string(ret) + "): " + cmd);
    return ret == 0;
}

bool IptablesBackend::initChain() {
    if (!isAvailable()) {
        LOG_WARN("iptables not found — firewall integration disabled");
        return false;
    }

    // Tạo chain IDS_BLOCK nếu chưa có (lỗi nếu đã tồn tại → bỏ qua)
    execCmd("iptables -N " + chain_ + " 2>/dev/null || true");

    // Gắn chain vào INPUT nếu chưa có jump rule
    const std::string check = "iptables -C INPUT -j " + chain_ + " 2>/dev/null";
    if (system(check.c_str()) != 0)
        execCmd("iptables -I INPUT 1 -j " + chain_);

    LOG_INFO("iptables chain '" + chain_ + "' ready");
    return true;
}

// ─── buildRuleArgs ────────────────────────────────────────────────────────────
// Trả về phần args sau "iptables <op> <chain>"
// Dùng chung cho applyRule() và removeRule()
std::string IptablesBackend::buildIptablesArgs(const FirewallRule& rule,
                                                const std::string& /*op*/) const {
    std::ostringstream ss;

    // Protocol
    const std::string proto = protoStr(rule.protocol);
    if (!proto.empty())
        ss << " -p " << proto;

    // Source IP / CIDR
    if (!rule.src_ip.empty())
        ss << " -s " << rule.src_ip;

    // Source port (chỉ có nghĩa khi có protocol TCP/UDP)
    if (rule.src_port > 0 && !proto.empty())
        ss << " --sport " << rule.src_port;

    // Destination IP
    if (!rule.dst_ip.empty())
        ss << " -d " << rule.dst_ip;

    // Destination port
    // Ưu tiên dst_port; fallback port (backward compat)
    const uint16_t dport = (rule.dst_port > 0) ? rule.dst_port : rule.port;
    if (dport > 0 && !proto.empty())
        ss << " --dport " << dport;

    // Action target
    ss << " " << actionTarget(rule.action);

    // Comment (iptables comment module)
    if (rule.id > 0)
        ss << " -m comment --comment \"IDS:" << rule.id << "\"";

    return ss.str();
}

bool IptablesBackend::applyRule(const FirewallRule& rule) {
    if (!initialized_) return false;

    std::ostringstream ss;
    ss << "iptables";

    // Whitelist (ALLOW) → INSERT đầu chain để ưu tiên hơn blacklist
    if (rule.action == FirewallRule::Action::ALLOW)
        ss << " -I " << chain_ << " 1";
    else
        ss << " -A " << chain_;

    ss << buildIptablesArgs(rule, "");
    return execCmd(ss.str());
}

bool IptablesBackend::removeRule(const FirewallRule& rule) {
    if (!initialized_) return false;

    std::ostringstream ss;
    ss << "iptables -D " << chain_;
    ss << buildIptablesArgs(rule, "");
    return execCmd(ss.str());
}

bool IptablesBackend::flushChain(const std::string& chain) {
    return execCmd("iptables -F " + chain);
}

// ════════════════════════════════════════════════════════════════════════════
// NftablesBackend
// ════════════════════════════════════════════════════════════════════════════

NftablesBackend::NftablesBackend(const std::string& table,
                                  const std::string& set)
    : table_(table), set_(set)
{
    initialized_ = initTable();
}

bool NftablesBackend::isAvailable() const {
    return system("which nft > /dev/null 2>&1") == 0;
}

bool NftablesBackend::execCmd(const std::string& cmd) const {
    LOG_INFO("nft exec: " + cmd);
    const int ret = system(cmd.c_str());
    if (ret != 0)
        LOG_WARN("nft failed (exit=" + std::to_string(ret) + "): " + cmd);
    return ret == 0;
}

bool NftablesBackend::initTable() {
    if (!isAvailable()) {
        LOG_WARN("nft not found — nftables backend disabled");
        return false;
    }

    // Tạo table inet ids
    execCmd("nft add table inet " + table_ + " 2>/dev/null || true");

    // Tạo set blacklist (type ipv4_addr, hỗ trợ CIDR với flags interval)
    execCmd("nft add set inet " + table_
            + " blacklist '{ type ipv4_addr; flags interval; }'"
            + " 2>/dev/null || true");

    // Tạo set whitelist
    execCmd("nft add set inet " + table_
            + " whitelist '{ type ipv4_addr; flags interval; }'"
            + " 2>/dev/null || true");

    // Tạo chain input hook
    execCmd("nft add chain inet " + table_
            + " input '{ type filter hook input priority 0; policy accept; }'"
            + " 2>/dev/null || true");

    // Whitelist rule → ACCEPT trước blacklist
    execCmd("nft add rule inet " + table_
            + " input ip saddr @whitelist accept 2>/dev/null || true");

    // Blacklist rule → DROP
    execCmd("nft add rule inet " + table_
            + " input ip saddr @blacklist drop 2>/dev/null || true");

    LOG_INFO("nftables table '" + table_ + "' ready");
    return true;
}

bool NftablesBackend::applyRule(const FirewallRule& rule) {
    if (!initialized_) return false;
    if (rule.src_ip.empty()) return false;

    // Chọn set dựa theo action
    const std::string set_name =
        (rule.action == FirewallRule::Action::ALLOW)
            ? "whitelist"
            : "blacklist";

    return execCmd("nft add element inet " + table_
                   + " " + set_name
                   + " { " + rule.src_ip + " }");
}

bool NftablesBackend::removeRule(const FirewallRule& rule) {
    if (!initialized_) return false;
    if (rule.src_ip.empty()) return false;

    const std::string set_name =
        (rule.action == FirewallRule::Action::ALLOW)
            ? "whitelist"
            : "blacklist";

    return execCmd("nft delete element inet " + table_
                   + " " + set_name
                   + " { " + rule.src_ip + " }");
}

bool NftablesBackend::flushChain(const std::string& chain) {
    return execCmd("nft flush set inet " + table_ + " " + chain);
}
