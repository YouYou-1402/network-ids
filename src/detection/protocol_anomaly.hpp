// src/detection/protocol_anomaly.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "../common/config_loader.hpp"
#include "flow_state.hpp"
#include "ip_tracker.hpp"
#include <vector>
#include <cstdint>

class ProtocolAnomalyEngine {
public:
    explicit ProtocolAnomalyEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt, FlowState& flow);

private:
    DetectionResult checkSlowloris(const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkSlowPost (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkSlowRead (const PacketInfo& pkt, FlowState& flow);

    bool isHttpPort(uint16_t port) const;

    IpTracker& ip_tracker_;

    // ── Đọc từ config lúc khởi tạo, KHÔNG còn constexpr ─────────────────
    double   http_header_timeout_sec_    = 30.0;
    double   min_bytes_per_sec_          = 50.0;
    uint32_t max_concurrent_conn_        = 50;
    uint32_t slowloris_conn_min_         = 30;
    double   slow_post_duration_min_sec_ = 60.0;
    uint32_t win_zero_count_threshold_   = 5;

    std::vector<uint16_t> http_ports_;   // {80, 8080} từ config
};
