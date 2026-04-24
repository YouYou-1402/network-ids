// =============================================================================
//  src/detection/signature_engine.hpp
// =============================================================================
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "../common/config_loader.hpp"
#include "flow_state.hpp"
#include "ip_tracker.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>

// ─── Aho-Corasick node ────────────────────────────────────────────────────────
struct AcNode {
    int  children[256];
    int  fail       = 0;
    int  output     = -1;   // sig_id nếu là terminal node, -1 nếu không
    bool is_end     = false;
    AcNode() { std::fill(children, children + 256, -1); }
};

// ─── Signature IDs ────────────────────────────────────────────────────────────
constexpr int SIG_NONE      = -1;
constexpr int SIG_SLOWLORIS =  0;
constexpr int SIG_SLOW_POST =  1;

class SignatureEngine {
public:
    explicit SignatureEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt, FlowState& flow);

private:
    // ── Aho-Corasick ──────────────────────────────────────────────────────
    void addPattern   (const std::string& pattern, int sig_id);
    void buildFailLinks();
    int  acSearch     (const uint8_t* data, size_t len) const;

    // ── Per-check methods ─────────────────────────────────────────────────
    DetectionResult checkFloodRate  (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkPortScan   (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkFlagAbuse  (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkPayload    (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkGlobalSyn  (const PacketInfo& pkt);
    DetectionResult checkDstSynRatio(const PacketInfo& pkt);

    IpTracker&  ip_tracker_;
    DstTracker  dst_tracker_;

    // ── Aho-Corasick state ────────────────────────────────────────────────
    std::vector<AcNode> ac_nodes_;

    // ── Rule metadata: sig_id → SignatureRule (từ rules.json) ─────────────
    //  Dùng để lấy threat/action khi alert thay vì hardcode
    std::unordered_map<int, SignatureRule> rule_map_;

    // ── Thresholds (đọc từ config lúc khởi tạo) ──────────────────────────
    double   flood_ratio_threshold_      = 0.5;
    uint32_t port_scan_threshold_        = 20;
    uint32_t port_scan_syn_no_ack_min_   = 25;
    uint64_t min_pkt_before_flood_check_ = 20;
    uint64_t global_syn_threshold_       = 2000;
    uint64_t dst_syn_ratio_min_pkt_      = 100;
    double   dst_syn_ack_ratio_          = 10.0;
    double   behavior_window_sec_        = 10.0;
};
