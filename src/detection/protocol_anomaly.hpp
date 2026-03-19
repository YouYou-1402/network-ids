// src/detection/protocol_anomaly.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "flow_state.hpp"
#include "ip_tracker.hpp"

class ProtocolAnomalyEngine {
public:
    explicit ProtocolAnomalyEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt, FlowState& flow);

private:
    DetectionResult checkSlowloris(const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkSlowPost (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkSlowRead (const PacketInfo& pkt, FlowState& flow);

    IpTracker& ip_tracker_;

    static constexpr double   HTTP_HEADER_TIMEOUT_SEC   = 30.0;

    // FIX: 10.0 → 50.0 B/s
    // Mobile 3G yếu = ~500 B/s → cũ false positive với upload chậm hợp lệ
    static constexpr double   MIN_BYTES_PER_SEC         = 50.0;

    static constexpr uint32_t MAX_CONCURRENT_CONN       = 50;

    // FIX: 10 → 30
    // HTTP/1.1 browser: 6 conn/domain × 3 domain = 18 conn → cũ false positive
    // Slowloris thực sự cần 50-200 conn để hiệu quả
    static constexpr uint32_t SLOWLORIS_CONN_MIN        = 30;

    // FIX: thêm mới — chỉ alert Slow POST khi connection kéo dài > 60s
    // Loại bỏ false positive với upload file chậm hợp lệ trong 30s đầu
    static constexpr double   SLOW_POST_DURATION_MIN_SEC = 60.0;

    // FIX: thêm mới — Slow Read cần win=0 kéo dài liên tiếp
    // TCP window=0 tạm thời là BÌNH THƯỜNG khi buffer đầy
    // Chỉ alert khi win=0 xuất hiện >= WIN_ZERO_COUNT_THRESHOLD lần
    static constexpr uint32_t WIN_ZERO_COUNT_THRESHOLD  = 5;

    static constexpr uint16_t HTTP_PORT      = 80;
    static constexpr uint16_t HTTPS_PORT     = 443;
    static constexpr uint16_t HTTP_ALT_PORT  = 8080;
};
