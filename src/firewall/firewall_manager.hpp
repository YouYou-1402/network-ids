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
    // ── Constructors ──────────────────────────────────────────────────────────
    // Mặc định: thử nftables/iptables, fallback in-memory
    explicit FirewallManager(bool use_nftables = false);

    // In-memory only — không cần root, dùng cho UI / testing
    struct InMemoryTag {};
    explicit FirewallManager(InMemoryTag);

    ~FirewallManager();

    // ── Blacklist ─────────────────────────────────────────────────────────────
    uint64_t autoBlock  (const std::string& src_ip,
                         uint8_t            protocol = 0,
                         uint16_t           src_port = 0,
                         const std::string& reason   = "");

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
        std::lock_guard<std::mutex> lock(cb_mutex_);
        on_rule_change_ = std::move(cb);
    }

    // ── Stats ─────────────────────────────────────────────────────────────────
    size_t blacklistSize() const;
    size_t whitelistSize() const;

    // ── Backend info ──────────────────────────────────────────────────────────
    std::string backendName() const {
        return backend_ ? backend_->name() : "in-memory";
    }

private:
    void     init       (bool use_nftables);
    uint64_t nextId     ();
    void     expireLoop ();
    bool     applyToKernel   (const FirewallRule& rule);
    bool     removeFromKernel(const FirewallRule& rule);
    void     notifyChange    (const FirewallRule& rule, bool added);

    std::unique_ptr<IFirewallBackend>          backend_;

    mutable std::mutex                         mutex_;
    std::unordered_map<uint64_t, FirewallRule> rules_;
    std::unordered_map<std::string, uint64_t>  ip_to_rule_;
    std::unordered_set<std::string>            whitelist_ips_;

    mutable std::mutex  cb_mutex_;
    RuleChangeCallback  on_rule_change_;

    std::atomic<uint64_t> next_id_ {1};
    std::atomic<bool>     running_ {true};
    std::thread           expire_thread_;

    static constexpr uint32_t AUTO_BLOCK_TTL_SEC = 600;
};
