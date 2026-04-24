#pragma once
// =============================================================================
//  src/common/config_loader.hpp
// =============================================================================

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include "../ml/ml_config.hpp"

// ─── TokenBucket ──────────────────────────────────────────────────────────────
struct BucketCfg {
    double capacity    = 100.0;
    double refill_rate = 10.0;
};
struct TokenBucketCfg {
    BucketCfg syn;
    BucketCfg udp;
    BucketCfg icmp;
};

// ─── Thresholds ───────────────────────────────────────────────────────────────
struct ThresholdCfg {
    double   flood_ratio               = 0.5;
    uint64_t min_pkt_before_flood      = 20;
    uint32_t syn_no_complete           = 50;
    uint64_t http_flood_req_per_window = 200;
    double   behavior_window_sec       = 10.0;
    uint32_t port_scan_ports           = 20;
    uint32_t port_scan_syn_no_ack_min  = 25;
    uint32_t dist_scan_src_threshold   = 10;
    double   ip_tracker_window_sec     = 30.0;
    double   ip_tracker_idle_cleanup   = 60.0;
    double   scan_idle_reset_sec       = 300.0;
    size_t   max_tracked_ip            = 65536;
    uint64_t global_syn_threshold      = 2000;
    uint64_t dst_syn_ratio_min_pkt     = 100;
    double   dst_syn_ack_ratio         = 10.0;
};

// ─── SignatureRule — 1 entry trong "signatures" array của rules.json ──────────
struct SignatureRule {
    std::string id;
    std::string name;
    std::string pattern;   // raw string để Aho-Corasick match
    std::string threat;    // "SLOW_DDOS" | "DDOS_VOLUMETRIC" | ...
    std::string action;    // "ALERT" | "DROP"
};

// ─── BehaviorRule — 1 entry trong "rules" array của rules.json ───────────────
struct BehaviorRule {
    std::string id;
    std::string name;
    std::string condition; // "syn_no_ack > 100 in 10s" v.v.
    std::string threat;
    std::string action;
};

// ─── SignatureCfg ─────────────────────────────────────────────────────────────
struct SignatureCfg {
    // Thresholds — backward compat với code cũ
    double   flood_ratio              = 0.5;
    uint32_t port_scan_ports          = 20;
    uint32_t port_scan_syn_no_ack_min = 25;
    uint64_t min_pkt_before_flood     = 20;

    // Rules load từ rules.json
    std::string                rules_file;      // path tới rules.json
    std::vector<SignatureRule> sig_rules;        // "signatures" array
    std::vector<BehaviorRule>  behavior_rules;   // "rules" array
};

// ─── ProtocolAnomalyEngine ────────────────────────────────────────────────────
struct ProtocolAnomalyCfg {
    double   http_header_timeout_sec    = 30.0;
    double   min_bytes_per_sec          = 50.0;
    uint32_t max_concurrent_conn        = 50;
    uint32_t slowloris_conn_min         = 30;
    double   slow_post_duration_min_sec = 60.0;
    uint32_t win_zero_count_threshold   = 5;
    std::vector<uint16_t> http_ports;
};

// ─── Media ports ──────────────────────────────────────────────────────────────
struct RtpHeuristicCfg {
    bool     enabled      = true;
    uint32_t min_pkt_size = 28;
    uint32_t max_pkt_size = 1400;
};
struct MediaPortsCfg {
    std::vector<uint16_t> quic;
    std::vector<uint16_t> stun;
    RtpHeuristicCfg       rtp_heuristic;
};

// ─── System ───────────────────────────────────────────────────────────────────
struct SystemCfg {
    int         num_workers           = 4;
    int         max_flows             = 10000;
    double      flow_idle_timeout_sec = 300.0;
    std::string log_file              = "logs/system.log";
    std::string alert_log_file        = "logs/alert.log";
    std::string log_level             = "INFO";
};

// ─── Capture ──────────────────────────────────────────────────────────────────
struct CaptureCfg {
    std::string interface      = "eth0";
    std::string bpf_filter     = "tcp or udp";
    uint32_t    snaplen        = 65535;
    bool        promiscuous    = true;
    uint32_t    ring_buffer_mb = 64;
};

// ─── Firewall ─────────────────────────────────────────────────────────────────
struct FirewallCfg {
    std::string rules_file         = "config/firewall_rules.json";
    bool        use_nftables       = false;
    bool        auto_block_enabled = true;
    uint32_t    block_duration_sec = 300;
};

// ─── Logging ──────────────────────────────────────────────────────────────────
struct LoggingCfg {
    std::string level  = "INFO";
    uint32_t    max_mb = 100;
    uint32_t    rotate = 5;
};

// =============================================================================
//  AppConfig
// =============================================================================
struct AppConfig {
    bool detection_enabled = true;
    bool ml_enabled        = false;

    SystemCfg          system;
    CaptureCfg         capture;
    TokenBucketCfg     token_bucket;
    ThresholdCfg       thresholds;
    SignatureCfg       signatures;   // chứa cả threshold lẫn sig/behavior rules
    ProtocolAnomalyCfg protocol_anomaly;
    MediaPortsCfg      media_ports;
    MLConfig           ml;
    FirewallCfg        firewall;
    LoggingCfg         logging;

    std::vector<std::string> whitelist_ips;
};

// =============================================================================
//  ConfigLoader
// =============================================================================
class ConfigLoader {
public:
    static AppConfig        load(const std::string& path);
    static const AppConfig& get();
    static bool             isLoaded() { return loaded_; }

private:
    static AppConfig cfg_;
    static bool      loaded_;
};

#define APP_CFG ConfigLoader::get()
