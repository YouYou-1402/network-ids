// src/detection/signature_engine.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "flow_state.hpp"
#include "ip_tracker.hpp"
#include <vector>
#include <string>
#include <unordered_map>

struct ACNode {
    std::unordered_map<uint8_t, int> children;
    int              fail_link = 0;
    std::vector<int> outputs;
};

enum SignatureID {
    SIG_SLOWLORIS = 0,
    SIG_SLOW_POST = 1,
    SIG_COUNT     = 2
};

class SignatureEngine {
public:
    explicit SignatureEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt, FlowState& flow);

private:
    void             addPattern  (const std::string& pattern, int sig_id);
    void             buildFailLinks();
    std::vector<int> search      (const uint8_t* data, size_t len) const;

    DetectionResult  checkFlagAbuse(const PacketInfo& pkt);
    DetectionResult  checkPayload  (const PacketInfo& pkt);
    void             updateFlowState(const PacketInfo& pkt, FlowState& flow);

    // checkDDoS + checkPortScan được gộp vào analyze()
    // chạy TRONG withStats callback → thread-safe

    IpTracker&          ip_tracker_;
    std::vector<ACNode> ac_nodes_;

    static constexpr double   FLOOD_RATIO_THRESHOLD      = 0.5;
    static constexpr size_t   PORT_SCAN_THRESHOLD        = 50;
    static constexpr uint32_t PORT_SCAN_SYN_NO_ACK_MIN   = 25;
    static constexpr uint64_t MIN_PKT_BEFORE_FLOOD_CHECK = 20;
};
