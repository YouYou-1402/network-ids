// src/detection/protocol_anomaly.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "flow_state.hpp"
#include "ip_tracker.hpp"

// ─── ProtocolAnomalyEngine ────────────────────────────────────────────────────
//
//  Detect Slow DDoS dựa trên hành vi giao thức HTTP/TCP:
//
//    Slowloris:  HTTP header không hoàn chỉnh sau HTTP_HEADER_TIMEOUT_SEC
//    Slow POST:  Content-Length khai báo nhưng body/s < MIN_BYTES_PER_SEC
//    Slow Read:  TCP window = 0 kéo dài (client không đọc response)
//
//  Cần IpTracker để check concurrent_conn per src_ip
// ─────────────────────────────────────────────────────────────────────────────
class ProtocolAnomalyEngine {
public:
    explicit ProtocolAnomalyEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt,
                            FlowState&        flow);

private:
    DetectionResult checkSlowloris (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkSlowPost  (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkSlowRead  (const PacketInfo& pkt, FlowState& flow);

    IpTracker& ip_tracker_;

    static constexpr double   HTTP_HEADER_TIMEOUT_SEC = 30.0;
    static constexpr double   MIN_BYTES_PER_SEC       = 10.0;
    static constexpr uint32_t MAX_CONCURRENT_CONN     = 50;
    static constexpr uint16_t HTTP_PORT               = 80;
    static constexpr uint16_t HTTPS_PORT              = 443;
    static constexpr uint16_t HTTP_ALT_PORT           = 8080;
};
