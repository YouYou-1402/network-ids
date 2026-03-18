// src/firewall/firewall_manager.cpp
#include "firewall_manager.hpp"
#include "../common/logger.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ─── Constructor / Destructor ─────────────────────────────────────────────────

FirewallManager::FirewallManager(bool use_nftables) {
    if (use_nftables) {
        auto nft = std::make_unique<NftablesBackend>();
        if (nft->isAvailable()) {
            backend_ = std::move(nft);
            LOG_INFO("FirewallManager: using nftables backend");
        }
    }

    if (!backend_) {
        auto ipt = std::make_unique<IptablesBackend>();
        if (ipt->isAvailable()) {
            backend_ = std::move(ipt);
            LOG_INFO("FirewallManager: using iptables backend");
        } else {
            LOG_WARN("FirewallManager: no firewall backend — kernel blocking disabled");
        }
    }

    expire_thread_ = std::thread(&FirewallManager::expireLoop, this);
}

FirewallManager::~FirewallManager() {
    running_ = false;
    if (expire_thread_.joinable())
        expire_thread_.join();
}

// ─── nextId ───────────────────────────────────────────────────────────────────

uint64_t FirewallManager::nextId() {
    return next_id_.fetch_add(1, std::memory_order_relaxed);
}

// ─── autoBlock ────────────────────────────────────────────────────────────────

uint64_t FirewallManager::autoBlock(const std::string& src_ip,
                                     uint8_t            protocol,
                                     uint16_t           src_port,
                                     const std::string& reason) {
    // Whitelisted → không block
    if (isWhitelisted(src_ip)) {
        LOG_INFO("FirewallManager: " + src_ip + " is whitelisted, skip auto-block");
        return 0;
    }

    // Đã block → gia hạn TTL (cập nhật created_at)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = ip_to_rule_.find(src_ip);
        if (it != ip_to_rule_.end()) {
            auto& rule = rules_[it->second];
            if (!rule.permanent) {
                rule.created_at = static_cast<uint64_t>(std::time(nullptr));
                rule.ttl_sec    = AUTO_BLOCK_TTL_SEC;
                LOG_INFO("FirewallManager: renewed block for " + src_ip);
            }
            return it->second;
        }
    }

    // Tạo rule mới
    FirewallRule rule = FirewallRule::makeBlacklist(
        src_ip, protocol, 0,
        /*perm=*/false, AUTO_BLOCK_TTL_SEC,
        reason.empty() ? "auto-blocked by IDS" : reason,
        FirewallRule::Source::AUTO);

    rule.id       = nextId();
    rule.src_port = src_port;

    if (applyToKernel(rule)) {
        std::lock_guard<std::mutex> lock(mutex_);
        ip_to_rule_[src_ip] = rule.id;
        rules_[rule.id]     = rule;
        notifyChange(rule, true);
        LOG_INFO("FirewallManager: AUTO-BLOCK " + src_ip
                 + " ttl=" + std::to_string(AUTO_BLOCK_TTL_SEC) + "s"
                 + " reason=" + rule.comment);
        return rule.id;
    }
    return 0;
}

// ─── manualBlock ──────────────────────────────────────────────────────────────

uint64_t FirewallManager::manualBlock(const std::string& src_ip,
                                       uint8_t            protocol,
                                       uint16_t           src_port,
                                       bool               permanent,
                                       uint32_t           ttl_sec,
                                       const std::string& comment) {
    if (isWhitelisted(src_ip)) {
        LOG_WARN("FirewallManager: cannot block whitelisted IP " + src_ip);
        return 0;
    }

    FirewallRule rule = FirewallRule::makeBlacklist(
        src_ip, protocol, 0,
        permanent, ttl_sec,
        comment.empty() ? "manual block" : comment,
        FirewallRule::Source::MANUAL);

    rule.id       = nextId();
    rule.src_port = src_port;

    if (applyToKernel(rule)) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Xóa rule cũ cho cùng IP nếu có
        auto it = ip_to_rule_.find(src_ip);
        if (it != ip_to_rule_.end()) {
            auto old = rules_.find(it->second);
            if (old != rules_.end()) {
                removeFromKernel(old->second);
                notifyChange(old->second, false);
                rules_.erase(old);
            }
            ip_to_rule_.erase(it);
        }

        ip_to_rule_[src_ip] = rule.id;
        rules_[rule.id]     = rule;
        notifyChange(rule, true);
        LOG_INFO("FirewallManager: MANUAL-BLOCK " + src_ip
                 + (permanent ? " (permanent)"
                              : " ttl=" + std::to_string(ttl_sec) + "s"));
        return rule.id;
    }
    return 0;
}

// ─── addWhitelist ─────────────────────────────────────────────────────────────

uint64_t FirewallManager::addWhitelist(const std::string& src_ip,
                                        const std::string& comment) {
    // Nếu đang bị block → gỡ trước
    removeByIp(src_ip);

    FirewallRule rule = FirewallRule::makeWhitelist(
        src_ip, comment.empty() ? "whitelisted" : comment);
    rule.id = nextId();

    if (applyToKernel(rule)) {
        std::lock_guard<std::mutex> lock(mutex_);
        whitelist_ips_.insert(src_ip);
        ip_to_rule_[src_ip] = rule.id;
        rules_[rule.id]     = rule;
        notifyChange(rule, true);
        LOG_INFO("FirewallManager: WHITELIST " + src_ip);
        return rule.id;
    }
    return 0;
}

// ─── removeWhitelist ──────────────────────────────────────────────────────────

bool FirewallManager::removeWhitelist(const std::string& src_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    whitelist_ips_.erase(src_ip);

    auto it = ip_to_rule_.find(src_ip);
    if (it == ip_to_rule_.end()) return false;

    auto rit = rules_.find(it->second);
    if (rit == rules_.end()) return false;

    // Chỉ xóa nếu là whitelist rule
    if (rit->second.action != FirewallRule::Action::ALLOW) return false;

    removeFromKernel(rit->second);
    notifyChange(rit->second, false);
    rules_.erase(rit);
    ip_to_rule_.erase(it);
    LOG_INFO("FirewallManager: removed whitelist " + src_ip);
    return true;
}

// ─── removeRule ───────────────────────────────────────────────────────────────

bool FirewallManager::removeRule(uint64_t rule_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(rule_id);
    if (it == rules_.end()) return false;

    removeFromKernel(it->second);
    ip_to_rule_.erase(it->second.src_ip);
    whitelist_ips_.erase(it->second.src_ip);
    notifyChange(it->second, false);
    rules_.erase(it);
    return true;
}

// ─── removeByIp ───────────────────────────────────────────────────────────────

bool FirewallManager::removeByIp(const std::string& src_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = ip_to_rule_.find(src_ip);
    if (it == ip_to_rule_.end()) return false;

    auto rit = rules_.find(it->second);
    if (rit != rules_.end()) {
        removeFromKernel(rit->second);
        notifyChange(rit->second, false);
        rules_.erase(rit);
    }
    whitelist_ips_.erase(src_ip);
    ip_to_rule_.erase(it);
    return true;
}

// ─── flushAll ─────────────────────────────────────────────────────────────────

void FirewallManager::flushAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (backend_) backend_->flushChain("IDS_BLOCK");
    rules_.clear();
    ip_to_rule_.clear();
    whitelist_ips_.clear();
    LOG_INFO("FirewallManager: flushed all rules");
}

// ─── Query ────────────────────────────────────────────────────────────────────

bool FirewallManager::isBlacklisted(const std::string& src_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = ip_to_rule_.find(src_ip);
    if (it == ip_to_rule_.end()) return false;
    auto rit = rules_.find(it->second);
    if (rit == rules_.end()) return false;
    return rit->second.action == FirewallRule::Action::BLOCK
        && !rit->second.isExpired();
}

bool FirewallManager::isWhitelisted(const std::string& src_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return whitelist_ips_.count(src_ip) > 0;
}

FirewallManager::QuickCheck
FirewallManager::quickCheck(const PacketInfo& pkt) const {
    // Chuyển src_ip (uint32_t host order) → string
    struct in_addr addr;
    addr.s_addr = htonl(pkt.src_ip);
    const std::string ip = inet_ntoa(addr);

    std::lock_guard<std::mutex> lock(mutex_);

    if (whitelist_ips_.count(ip))
        return QuickCheck::WHITELIST;

    auto it = ip_to_rule_.find(ip);
    if (it != ip_to_rule_.end()) {
        auto rit = rules_.find(it->second);
        if (rit != rules_.end()
            && rit->second.action == FirewallRule::Action::BLOCK
            && !rit->second.isExpired())
            return QuickCheck::BLACKLIST;
    }

    return QuickCheck::NONE;
}

std::vector<FirewallRule> FirewallManager::listRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FirewallRule> out;
    out.reserve(rules_.size());
    for (auto& [id, r] : rules_) out.push_back(r);
    return out;
}

std::vector<FirewallRule> FirewallManager::listBlacklist() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FirewallRule> out;
    for (auto& [id, r] : rules_)
        if (r.action == FirewallRule::Action::BLOCK) out.push_back(r);
    return out;
}

std::vector<FirewallRule> FirewallManager::listWhitelist() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FirewallRule> out;
    for (auto& [id, r] : rules_)
        if (r.action == FirewallRule::Action::ALLOW) out.push_back(r);
    return out;
}

size_t FirewallManager::blacklistSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t n = 0;
    for (auto& [id, r] : rules_)
        if (r.action == FirewallRule::Action::BLOCK) n++;
    return n;
}

size_t FirewallManager::whitelistSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return whitelist_ips_.size();
}

// ─── expireLoop ───────────────────────────────────────────────────────────────

void FirewallManager::expireLoop() {
    while (running_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(30));

        // Thu thập ID hết hạn (không giữ lock khi gọi removeRule)
        std::vector<uint64_t> expired;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [id, rule] : rules_)
                if (rule.isExpired()) expired.push_back(id);
        }

        for (uint64_t id : expired) {
            LOG_INFO("FirewallManager: rule #" + std::to_string(id)
                     + " expired, removing");
            removeRule(id);
        }
    }
}

// ─── applyToKernel / removeFromKernel ─────────────────────────────────────────

bool FirewallManager::applyToKernel(const FirewallRule& rule) {
    if (!backend_) {
        // Không có backend → lưu in-memory, coi như thành công
        return true;
    }
    return backend_->applyRule(rule);
}

bool FirewallManager::removeFromKernel(const FirewallRule& rule) {
    if (!backend_) return true;
    return backend_->removeRule(rule);
}

void FirewallManager::notifyChange(const FirewallRule& rule, bool added) {
    if (on_rule_change_) on_rule_change_(rule, added);
}

// ─── Persistence ──────────────────────────────────────────────────────────────

bool FirewallManager::saveRules(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    json arr = json::array();

    for (auto& [id, rule] : rules_) {
        // Không lưu auto-block tạm thời (sẽ expire sau khi restart)
        if (rule.source == FirewallRule::Source::AUTO && !rule.permanent)
            continue;

        json obj;
        obj["id"]        = rule.id;
        obj["src_ip"]    = rule.src_ip;
        obj["dst_ip"]    = rule.dst_ip;
        obj["src_port"]  = rule.src_port;
        obj["dst_port"]  = rule.dst_port;
        obj["protocol"]  = rule.protocol;
        obj["action"]    = static_cast<int>(rule.action);
        obj["type"]      = static_cast<int>(rule.type);
        obj["source"]    = static_cast<int>(rule.source);
        obj["permanent"] = rule.permanent;
        obj["ttl_sec"]   = rule.ttl_sec;
        obj["comment"]   = rule.comment;
        arr.push_back(obj);
    }

    std::ofstream f(path);
    if (!f.is_open()) {
        LOG_WARN("FirewallManager: cannot save rules to " + path);
        return false;
    }
    f << arr.dump(2);
    LOG_INFO("FirewallManager: saved "
             + std::to_string(arr.size()) + " rules to " + path);
    return true;
}

bool FirewallManager::loadRules(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return false;

    json arr;
    try { f >> arr; }
    catch (...) {
        LOG_WARN("FirewallManager: failed to parse " + path);
        return false;
    }

    for (auto& obj : arr) {
        FirewallRule rule;
        rule.id         = obj.value("id",        nextId());
        rule.src_ip     = obj.value("src_ip",    std::string{});
        rule.dst_ip     = obj.value("dst_ip",    std::string{});
        rule.src_port   = obj.value("src_port",  uint16_t{0});
        rule.dst_port   = obj.value("dst_port",  uint16_t{0});
        rule.protocol   = obj.value("protocol",  uint8_t{0});
        rule.action     = static_cast<FirewallRule::Action>(
                              obj.value("action",  0));
        rule.type       = static_cast<FirewallRule::Type>(
                              obj.value("type",    0));
        rule.source     = static_cast<FirewallRule::Source>(
                              obj.value("source",  1));   // default MANUAL
        rule.permanent  = obj.value("permanent", false);
        rule.ttl_sec    = obj.value("ttl_sec",   uint32_t{600});
        rule.comment    = obj.value("comment",   std::string{});
        rule.created_at = static_cast<uint64_t>(std::time(nullptr));

        if (rule.src_ip.empty()) continue;

        if (applyToKernel(rule)) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (rule.action == FirewallRule::Action::ALLOW)
                whitelist_ips_.insert(rule.src_ip);
            ip_to_rule_[rule.src_ip] = rule.id;
            rules_[rule.id]          = rule;
        }
    }

    LOG_INFO("FirewallManager: loaded rules from " + path);
    return true;
}
