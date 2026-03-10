//src/detection/protocol_anomaly.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "flow_state.hpp"

// Phát hiện Slow DDoS dựa trên hành vi giao thức
// Đây là điểm mà Layer 1 có thể phát hiện Slow DDoS
// (dù hạn chế — Layer 2 AI/ML sẽ bổ sung)
class ProtocolAnomalyEngine {
public:
    DetectionResult analyze(const PacketInfo& pkt,
                            FlowState&        flow);

private:
    DetectionResult checkSlowDDoS(const PacketInfo& pkt,
                                  FlowState&        flow);
    DetectionResult checkHTTPAnomaly(const PacketInfo& pkt,
                                     FlowState&        flow);

    // Thresholds
    static constexpr double   HTTP_HEADER_TIMEOUT_SEC = 30.0;
    static constexpr double   MIN_BYTES_PER_SEC       = 10.0;
    static constexpr uint32_t MAX_CONCURRENT_CONN     = 50;
    static constexpr uint16_t HTTP_PORT               = 80;
    static constexpr uint16_t HTTPS_PORT              = 443;
};
