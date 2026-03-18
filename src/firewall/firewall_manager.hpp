// src/firewall/firewall_manager.hpp
#pragma once
#include "firewall_rule.hpp"
#include "firewall_backend.hpp"
#include "../core/packet_info.hpp"
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>

class FirewallManager {
public:
    explicit FirewallManager(bool use_nftables = false);
    ~FirewallManager();

    // ── Blacklist ─────────────────────────────────────────────────────────────
    // Auto-block từ detection engine (TTL mặc định AUTO_BLOCK_TTL_SEC)
    uint64_t autoBlock  (const std::string& src_ip,
                         uint8_t            protocol = 0,
                         uint16_t           src_port = 0,
                         const std::string& reason   = "");

    // Manual block từ UI/API
    uint64_t manualBlock(const std::string& src_ip,
                         uint8_t            protocol  = 0,
                         uint16_t           src_port  = 0,
                         bool               permanent = false,
                         uint32_t           ttl_sec   = 3600,
                         const std::string& comment   = "");

    // ── Whitelist ─────────────────────────────────────────────────────────────
    uint64_t addWhitelist   (const std::string& src_ip,
                             const std::string& comment = "");
    bool     removeWhitelist(const std::string& src_ip);

    // ── Rule management ───────────────────────────────────────────────────────
    bool removeRule (uint64_t           rule_id);
    bool removeByIp (const std::string& src_ip);
    void flushAll   ();

    // ── Query ─────────────────────────────────────────────────────────────────
    bool isBlacklisted(const std::string& src_ip) const;
    bool isWhitelisted(const std::string& src_ip) const;

    enum class QuickCheck { WHITELIST, BLACKLIST, NONE };
    QuickCheck quickCheck(const PacketInfo& pkt) const;

    std::vector<FirewallRule> listRules     () const;
    std::vector<FirewallRule> listBlacklist () const;
    std::vector<FirewallRule> listWhitelist () const;

    // ── Persistence ───────────────────────────────────────────────────────────
    bool saveRules(const std::string& path) const;
    bool loadRules(const std::string& path);

    // ── Callback ──────────────────────────────────────────────────────────────
    void setRuleChangeCallback(RuleChangeCallback cb) {
        on_rule_change_ = std::move(cb);
    }

    // ── Stats ─────────────────────────────────────────────────────────────────
    size_t blacklistSize() const;
    size_t whitelistSize() const;

private:
    uint64_t nextId();
    void     expireLoop();
    bool     applyToKernel  (const FirewallRule& rule);
    bool     removeFromKernel(const FirewallRule& rule);
    void     notifyChange   (const FirewallRule& rule, bool added);

    std::unique_ptr<IFirewallBackend>              backend_;

    mutable std::mutex                             mutex_;
    std::unordered_map<uint64_t, FirewallRule>     rules_;         // id  → rule
    std::unordered_map<std::string, uint64_t>      ip_to_rule_;    // ip  → id
    std::unordered_set<std::string>                whitelist_ips_; // fast lookup

    std::atomic<uint64_t>  next_id_ {1};
    std::atomic<bool>      running_ {true};
    std::thread            expire_thread_;
    RuleChangeCallback     on_rule_change_;

    static constexpr uint32_t AUTO_BLOCK_TTL_SEC = 600; // 10 phút
};
