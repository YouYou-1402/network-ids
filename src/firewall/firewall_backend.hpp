#pragma once
#include "firewall_rule.hpp"
#include <string>

// ════════════════════════════════════════════════════════════════════════════
// Interface
// ════════════════════════════════════════════════════════════════════════════

class IFirewallBackend {
public:
    virtual ~IFirewallBackend() = default;

    virtual bool        isAvailable() const = 0;
    virtual std::string name()        const = 0;
    virtual bool        applyRule (const FirewallRule& rule) = 0;
    virtual bool        removeRule(const FirewallRule& rule) = 0;
    virtual bool        flush()                              = 0;
};

// ════════════════════════════════════════════════════════════════════════════
// NftablesBackend
// ════════════════════════════════════════════════════════════════════════════

class NftablesBackend : public IFirewallBackend {
public:
    NftablesBackend();
    ~NftablesBackend() override;

    bool        isAvailable() const override;
    std::string name()        const override { return "nftables"; }
    bool        applyRule (const FirewallRule& rule) override;
    bool        removeRule(const FirewallRule& rule) override;
    bool        flush()                              override;

private:
    // Dùng nft -f - (heredoc qua stdin) để tránh shell escape
    bool nftBatch(const std::string& script) const;
    // Dùng cho lệnh đơn giản không có { }
    bool nftCmd  (const std::string& args)   const;
    bool ensureTable();

    bool available_   = false;
    bool chain_ready_ = false;
};

// ════════════════════════════════════════════════════════════════════════════
// IptablesBackend  (fallback)
// ════════════════════════════════════════════════════════════════════════════

class IptablesBackend : public IFirewallBackend {
public:
    IptablesBackend();
    ~IptablesBackend() override;

    bool        isAvailable() const override;
    std::string name()        const override { return "iptables"; }
    bool        applyRule (const FirewallRule& rule) override;
    bool        removeRule(const FirewallRule& rule) override;
    bool        flush()                              override;

private:
    bool shell(const std::string& cmd) const;
    bool ensureChain();

    bool available_   = false;
    bool chain_ready_ = false;
};
