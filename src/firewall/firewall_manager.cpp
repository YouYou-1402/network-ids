#include "firewall_manager.hpp"
#include "../common/logger.hpp"
#include <arpa/inet.h>
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ════════════════════════════════════════════════════════════════════════════
// Constructors
// ════════════════════════════════════════════════════════════════════════════

void FirewallManager::init(bool use_nftables) {
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
            LOG_WARN("FirewallManager: no kernel backend — in-memory only");
        }
    }
}

FirewallManager::FirewallManager(bool use_nftables) {
    init(use_nftables);
    expire_thread_ = std::thread(&FirewallManager::expireLoop, this);
}

// In-memory only constructor — không thử kernel backend
FirewallManager::FirewallManager(InMemoryTag) {
    LOG_INFO("FirewallManager: in-memory mode (no kernel backend)");
    expire_thread_ = std::thread(&FirewallManager::expireLoop, this);
}

FirewallManager::~FirewallManager() {
    running_ = false;
    if (expire_thread_.joinable())
        expire_thread_.join();
}

// ════════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════════

uint64_t FirewallManager::nextId() {
    return next_id_.fetch_add(1, std::memory_order_relaxed);
}

// KEY FIX: luôn trả true để lưu in-memory dù kernel fail
bool FirewallManager::applyToKernel(const FirewallRule& rule) {
    if (!backend_) return true;
    const bool ok = backend_->applyRule(rule);
    if (!ok)
        LOG_WARN("FirewallManager: kernel apply failed for "
                 + rule.src_ip + " — stored in-memory only");
    return true;   // ← luôn true
}

bool FirewallManager::removeFromKernel(const FirewallRule& rule) {
    if (!backend_) return true;
    backend_->removeRule(rule);   // best-effort
    return true;
}

void FirewallManager::notifyChange(const FirewallRule& rule, bool added) {
    std::lock_guard<std::mutex> lock(cb_mutex_);
    if (on_rule_change_) on_rule_change_(rule, added);
}

// ════════════════════════════════════════════════════════════════════════════
// autoBlock
// ════════════════════════════════════════════════════════════════════════════

uint64_t FirewallManager::autoBlock(const std::string& src_ip,
                                     uint8_t            protocol,
                                     uint16_t           src_port,
                                     const std::string& reason) {
    if (isWhitelisted(src_ip)) {
        LOG_INFO("FirewallManager: " + src_ip + " whitelisted, skip auto-block");
        return 0;
    }

    // Gia hạn nếu đã tồn tại
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

    FirewallRule rule = FirewallRule::makeBlacklist(
        src_ip, protocol, 0,
        false, AUTO_BLOCK_TTL_SEC,
        reason.empty() ? "auto-blocked by IDS" : reason,
        FirewallRule::Source::AUTO);
    rule.id       = nextId();
    rule.src_port = src_port;

    applyToKernel(rule);

    std::lock_guard<std::mutex> lock(mutex_);
    ip_to_rule_[src_ip] = rule.id;
    rules_[rule.id]     = rule;
    notifyChange(rule, true);
    LOG_INFO("FirewallManager: AUTO-BLOCK " + src_ip
             + " ttl=" + std::to_string(AUTO_BLOCK_TTL_SEC) + "s");
    return rule.id;
}

// ════════════════════════════════════════════════════════════════════════════
// manualBlock
// ════════════════════════════════════════════════════════════════════════════

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

    applyToKernel(rule);

    std::lock_guard<std::mutex> lock(mutex_);

    // Xóa rule cũ cùng IP nếu có
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

// ════════════════════════════════════════════════════════════════════════════
// Whitelist
// ════════════════════════════════════════════════════════════════════════════

uint64_t FirewallManager::addWhitelist(const std::string& src_ip,
                                        const std::string& comment) {
    removeByIp(src_ip);   // gỡ blacklist nếu có

    FirewallRule rule = FirewallRule::makeWhitelist(
        src_ip, comment.empty() ? "whitelisted" : comment);
    rule.id = nextId();

    applyToKernel(rule);

    std::lock_guard<std::mutex> lock(mutex_);
    whitelist_ips_.insert(src_ip);
    ip_to_rule_[src_ip] = rule.id;
    rules_[rule.id]     = rule;
    notifyChange(rule, true);
    LOG_INFO("FirewallManager: WHITELIST " + src_ip);
    return rule.id;
}

bool FirewallManager::removeWhitelist(const std::string& src_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    whitelist_ips_.erase(src_ip);

    auto it = ip_to_rule_.find(src_ip);
    if (it == ip_to_rule_.end()) return false;

    auto rit = rules_.find(it->second);
    if (rit == rules_.end()) return false;
    if (rit->second.action != FirewallRule::Action::ALLOW) return false;

    removeFromKernel(rit->second);
    notifyChange(rit->second, false);
    rules_.erase(rit);
    ip_to_rule_.erase(it);
    LOG_INFO("FirewallManager: removed whitelist " + src_ip);
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Rule management
// ════════════════════════════════════════════════════════════════════════════

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

void FirewallManager::flushAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (backend_) backend_->flushChain("IDS_BLOCK");
    rules_.clear();
    ip_to_rule_.clear();
    whitelist_ips_.clear();
    LOG_INFO("FirewallManager: flushed all rules");
}

// ════════════════════════════════════════════════════════════════════════════
// Query
// ════════════════════════════════════════════════════════════════════════════

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
    struct in_addr addr;
    addr.s_addr = htonl(pkt.src_ip);
    const std::string ip = inet_ntoa(addr);

    std::lock_guard<std::mutex> lock(mutex_);
    if (whitelist_ips_.count(ip))       return QuickCheck::WHITELIST;

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

// ════════════════════════════════════════════════════════════════════════════
// expireLoop
// ════════════════════════════════════════════════════════════════════════════

void FirewallManager::expireLoop() {
    while (running_.load(std::memory_order_relaxed)) {
        for (int i = 0; i < 30 && running_; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!running_) break;

        std::vector<uint64_t> expired;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [id, rule] : rules_)
                if (rule.isExpired()) expired.push_back(id);
        }
        for (uint64_t id : expired) {
            LOG_INFO("FirewallManager: rule #"
                     + std::to_string(id) + " expired");
            removeRule(id);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Persistence
// ════════════════════════════════════════════════════════════════════════════

bool FirewallManager::saveRules(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    json arr = json::array();

    for (auto& [id, rule] : rules_) {
        // Không lưu auto-block tạm thời
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
        LOG_WARN("FirewallManager: cannot save to " + path);
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

    int loaded = 0;
    for (auto& obj : arr) {
        FirewallRule rule;
        rule.src_ip    = obj.value("src_ip",   std::string{});
        if (rule.src_ip.empty()) continue;

        rule.id        = obj.value("id",       nextId());
        rule.dst_ip    = obj.value("dst_ip",   std::string{});
        rule.src_port  = obj.value("src_port", uint16_t{0});
        rule.dst_port  = obj.value("dst_port", uint16_t{0});
        rule.protocol  = obj.value("protocol", uint8_t{0});
        rule.action    = static_cast<FirewallRule::Action>(
                             obj.value("action",  0));
        rule.type      = static_cast<FirewallRule::Type>(
                             obj.value("type",    0));
        rule.source    = static_cast<FirewallRule::Source>(
                             obj.value("source",  1));
        rule.permanent = obj.value("permanent", false);
        rule.ttl_sec   = obj.value("ttl_sec",   uint32_t{600});
        rule.comment   = obj.value("comment",   std::string{});
        rule.created_at = static_cast<uint64_t>(std::time(nullptr));

        applyToKernel(rule);

        std::lock_guard<std::mutex> lock(mutex_);
        if (rule.action == FirewallRule::Action::ALLOW)
            whitelist_ips_.insert(rule.src_ip);
        ip_to_rule_[rule.src_ip] = rule.id;
        rules_[rule.id]          = rule;
        ++loaded;
    }

    LOG_INFO("FirewallManager: loaded " + std::to_string(loaded)
             + " rules from " + path);
    return true;
}
