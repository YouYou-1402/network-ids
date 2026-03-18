// src/firewall/firewall_backend.hpp
#pragma once
#include "firewall_rule.hpp"
#include <string>
#include <vector>

// Interface — dễ swap backend (iptables ↔ nftables ↔ mock cho test)
class IFirewallBackend {
public:
    virtual ~IFirewallBackend() = default;

    virtual bool applyRule  (const FirewallRule& rule)   = 0;
    virtual bool removeRule (const FirewallRule& rule)   = 0;
    virtual bool flushChain (const std::string& chain)   = 0;
    virtual bool isAvailable()                     const = 0;
    virtual std::string name()                     const = 0;
};

// ── iptables backend ─────────────────────────────────────────────────────────
class IptablesBackend : public IFirewallBackend {
public:
    explicit IptablesBackend(const std::string& chain = "IDS_BLOCK");

    bool applyRule  (const FirewallRule& rule)   override;
    bool removeRule (const FirewallRule& rule)   override;
    bool flushChain (const std::string& chain)   override;
    bool isAvailable()                     const override;
    std::string name()                     const override { return "iptables"; }

private:
    std::string chain_;
    bool        initialized_ = false;

    bool        execCmd     (const std::string& cmd) const;
    bool        initChain   ();
    std::string buildIptablesArgs(const FirewallRule& rule,
                                  const std::string&  op) const;
};

// ── nftables backend ─────────────────────────────────────────────────────────
class NftablesBackend : public IFirewallBackend {
public:
    explicit NftablesBackend(const std::string& table = "ids",
                             const std::string& set   = "blacklist");

    bool applyRule  (const FirewallRule& rule)   override;
    bool removeRule (const FirewallRule& rule)   override;
    bool flushChain (const std::string& chain)   override;
    bool isAvailable()                     const override;
    std::string name()                     const override { return "nftables"; }

private:
    std::string table_;
    std::string set_;
    bool        initialized_ = false;

    bool initTable();
    bool execCmd(const std::string& cmd) const;
};
