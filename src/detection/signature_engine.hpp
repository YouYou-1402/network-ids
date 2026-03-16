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
    SIG_SLOWLORIS  = 0,   // "X-a: b\r\n" pattern
    SIG_SLOW_POST  = 1,   // "Content-Length:" với body chậm
    SIG_COUNT      = 2
};

// ─── SignatureEngine ──────────────────────────────────────────────────────────
//
//  Detect:
//    1. DDoS volumetric: SYN flood, UDP flood, ICMP flood
//       → dùng IpStats.syn_count / udp_count / icmp_count (per-IP, không per-flow)
//    2. Port scan:       nhiều dst_port khác nhau từ 1 src_ip
//       → dùng IpStats.dst_ports_seen (per-IP)
//    3. TCP flag abuse:  XMAS scan, NULL scan
//    4. Payload:         Aho-Corasick match Slowloris header pattern
//
//  IpTracker được inject từ ngoài (shared với BehavioralEngine)
// ─────────────────────────────────────────────────────────────────────────────
class SignatureEngine {
public:
    explicit SignatureEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt,
                            FlowState&        flow);

private:
    // ── Aho-Corasick ──────────────────────────────────────────────────────────
    void             addPattern  (const std::string& pattern, int sig_id);
    void             buildFailLinks();
    std::vector<int> search      (const uint8_t* data, size_t len) const;

    // ── Rule checks ───────────────────────────────────────────────────────────
    DetectionResult checkDDoS       (const PacketInfo& pkt, IpStats& ip);
    DetectionResult checkPortScan   (const PacketInfo& pkt, IpStats& ip);
    DetectionResult checkFlagAbuse  (const PacketInfo& pkt);
    DetectionResult checkPayload    (const PacketInfo& pkt);

    // ── Flow state update ─────────────────────────────────────────────────────
    void updateFlowState(const PacketInfo& pkt, FlowState& flow);

    IpTracker&          ip_tracker_;
    std::vector<ACNode> ac_nodes_;

    // ── Thresholds ────────────────────────────────────────────────────────────
    // Tất cả tính trong WINDOW_SEC = 10s (IpTracker.WINDOW_SEC)
    static constexpr uint64_t SYN_FLOOD_THRESHOLD  = 100;   // SYN/10s per IP
    static constexpr uint64_t UDP_FLOOD_THRESHOLD  = 1000;  // UDP pkt/10s per IP
    static constexpr uint64_t ICMP_FLOOD_THRESHOLD = 500;   // ICMP pkt/10s per IP
    static constexpr size_t   PORT_SCAN_THRESHOLD  = 20;    // unique ports/10s per IP
    static constexpr uint32_t RST_SCAN_THRESHOLD   = 15;    // RST nhận/10s per IP
};
