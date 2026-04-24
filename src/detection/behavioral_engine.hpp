// =============================================================================
//  src/detection/behavioral_engine.hpp
// =============================================================================
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "../common/config_loader.hpp"
#include "flow_state.hpp"
#include "ip_tracker.hpp"
#include <vector>
#include <cstdint>
#include <cstdio>

class BehavioralEngine {
public:
    explicit BehavioralEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt, FlowState& flow);

private:
    DetectionResult checkHttpFlood    (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkSynNoHandshake(const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkDistScan     (const PacketInfo& pkt, FlowState& flow);

    // Parse condition string từ rules.json → override threshold
    void parseConditionOverride(const BehaviorRule& rule);

    IpTracker& ip_tracker_;

    // ── Thresholds (đọc từ config, override bởi behavior_rules) ──────────
    uint64_t http_flood_threshold_    = 200;
    uint32_t syn_no_complete_thresh_  = 50;
    uint32_t dist_scan_src_threshold_ = 10;
    double   behavior_window_sec_     = 10.0;
    uint64_t udp_pps_threshold_       = 1000;   // từ RULE_002

    // ── Rules load từ rules.json ──────────────────────────────────────────
    std::vector<BehaviorRule> parsed_rules_;
};
