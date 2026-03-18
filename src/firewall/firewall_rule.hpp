// src/firewall/firewall_rule.hpp
#pragma once
#include <string>
#include <cstdint>
#include <ctime>
#include <functional>

// ─── FirewallRule ─────────────────────────────────────────────────────────────
struct FirewallRule {

    // ── Enums ─────────────────────────────────────────────────────────────────
    enum class Source : uint8_t {
        AUTO   = 0,   // detection engine tự block
        MANUAL = 1,   // user block thủ công qua UI/API
    };

    enum class Type : uint8_t {
        BLACKLIST = 0,
        WHITELIST = 1,
    };

    enum class Action : uint8_t {
        BLOCK      = 0,   // -j DROP
        ALLOW      = 1,   // -j ACCEPT  (whitelist)
        RATE_LIMIT = 2,   // -m limit --limit 10/min -j ACCEPT
    };

    // ── Identity ──────────────────────────────────────────────────────────────
    uint64_t    id         = 0;
    Type        type       = Type::BLACKLIST;
    Source      source     = Source::MANUAL;
    Action      action     = Action::BLOCK;

    // ── Match fields ──────────────────────────────────────────────────────────
    std::string src_ip;                   // "192.168.1.1" hoặc "10.0.0.0/8"
    std::string dst_ip;                   // "" = any
    uint8_t     protocol   = 0;           // 0=ANY, 1=ICMP, 6=TCP, 17=UDP
    uint16_t    src_port   = 0;           // 0=ANY
    uint16_t    dst_port   = 0;           // 0=ANY
    uint16_t    port       = 0;           // alias dst_port (backward compat)

    // ── Lifetime ──────────────────────────────────────────────────────────────
    bool        permanent  = false;       // true → không expire
    uint32_t    ttl_sec    = 600;         // giây kể từ created_at, 0 nếu permanent
    uint64_t    created_at = 0;           // unix timestamp (std::time)

    // ── Metadata ──────────────────────────────────────────────────────────────
    std::string comment;

    // ── Helpers ───────────────────────────────────────────────────────────────
    bool isExpired() const {
        if (permanent || ttl_sec == 0) return false;
        return (created_at + ttl_sec) <= static_cast<uint64_t>(std::time(nullptr));
    }

    bool isBlacklist() const { return type   == Type::BLACKLIST; }
    bool isWhitelist() const { return type   == Type::WHITELIST; }
    bool isAuto()      const { return source == Source::AUTO;    }
    bool isManual()    const { return source == Source::MANUAL;  }

    // ── Factory helpers ───────────────────────────────────────────────────────
    static FirewallRule makeBlacklist(const std::string& ip,
                                      uint8_t            proto    = 0,
                                      uint16_t           dport    = 0,
                                      bool               perm     = false,
                                      uint32_t           ttl      = 600,
                                      const std::string& cmt      = "",
                                      Source             src      = Source::MANUAL) {
        FirewallRule r;
        r.type       = Type::BLACKLIST;
        r.action     = Action::BLOCK;
        r.source     = src;
        r.src_ip     = ip;
        r.protocol   = proto;
        r.dst_port   = dport;
        r.port       = dport;
        r.permanent  = perm;
        r.ttl_sec    = perm ? 0 : ttl;
        r.created_at = static_cast<uint64_t>(std::time(nullptr));
        r.comment    = cmt.empty() ? (src == Source::AUTO
                                      ? "auto-blocked by IDS"
                                      : "manual block") : cmt;
        return r;
    }

    static FirewallRule makeWhitelist(const std::string& ip,
                                      const std::string& cmt = "") {
        FirewallRule r;
        r.type       = Type::WHITELIST;
        r.action     = Action::ALLOW;
        r.source     = Source::MANUAL;
        r.src_ip     = ip;
        r.permanent  = true;
        r.ttl_sec    = 0;
        r.created_at = static_cast<uint64_t>(std::time(nullptr));
        r.comment    = cmt.empty() ? "whitelisted" : cmt;
        return r;
    }
};

// ─── RuleChangeCallback ───────────────────────────────────────────────────────
// Có thể được gọi từ worker thread
// → UI phải marshal về main thread (QMetaObject::invokeMethod)
using RuleChangeCallback = std::function<void(const FirewallRule& rule,
                                               bool               added)>;
