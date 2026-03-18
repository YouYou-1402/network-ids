// src/detection/signature_engine.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "flow_state.hpp"
#include "ip_tracker.hpp"
#include <vector>
#include <string>
#include <unordered_map>

// ─── Aho-Corasick ─────────────────────────────────────────────────────────────
struct ACNode {
    std::unordered_map<uint8_t, int> children;
    int              fail_link = 0;
    std::vector<int> outputs;
};

enum SignatureID {
    SIG_SLOWLORIS  = 0,
    SIG_SLOW_POST  = 1,
    SIG_COUNT      = 2
};

// ─── SignatureEngine ──────────────────────────────────────────────────────────
class SignatureEngine {
public:
    explicit SignatureEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt,
                            FlowState&        flow);

private:
    void             addPattern  (const std::string& pattern, int sig_id);
    void             buildFailLinks();
    std::vector<int> search      (const uint8_t* data, size_t len) const;

    DetectionResult checkDDoS       (const PacketInfo& pkt, IpStats& ip);
    DetectionResult checkPortScan   (const PacketInfo& pkt, IpStats& ip);
    DetectionResult checkFlagAbuse  (const PacketInfo& pkt);
    DetectionResult checkPayload    (const PacketInfo& pkt);

    void updateFlowState(const PacketInfo& pkt, FlowState& flow);

    IpTracker&          ip_tracker_;
    std::vector<ACNode> ac_nodes_;

    // ── Thresholds ────────────────────────────────────────────────────────────
    static constexpr uint64_t SYN_FLOOD_THRESHOLD  = 100;  // SYN/10s per IP
    static constexpr uint64_t UDP_FLOOD_THRESHOLD  = 1000; // UDP pkt/10s per IP
    static constexpr uint64_t ICMP_FLOOD_THRESHOLD = 500;  // ICMP pkt/10s per IP
    static constexpr size_t   PORT_SCAN_THRESHOLD  = 20;   // unique ports/10s per IP
    static constexpr uint32_t RST_SCAN_THRESHOLD   = 15;   // RST nhận/10s per IP

    // FIX BUG 2: Số unique port tối thiểu để RST-based rule kích hoạt
    // Tránh nhầm SYN flood (1 port, nhiều RST) với port scan
    static constexpr size_t   RST_SCAN_MIN_PORTS   = 5;    // ít nhất 5 port khác nhau
};