#pragma once
#include "../layer1/flow_state.hpp"
#include "../common/packet_info.hpp"
#include <array>
#include <string>

// Feature vector 20 chiều — thiết kế theo báo cáo
// Thứ tự cố định, phải khớp với model training
struct FeatureVector {
    // ── Flow-based (0–4) ──────────────────────────────────────────────────────
    float flow_duration        = 0.f; // seconds
    float total_pkt_fwd        = 0.f; // packets client→server
    float total_pkt_bwd        = 0.f; // packets server→client
    float total_byte_fwd       = 0.f; // bytes client→server
    float total_byte_bwd       = 0.f; // bytes server→client

    // ── TCP Flags (5–9) ───────────────────────────────────────────────────────
    float syn_count            = 0.f;
    float ack_count            = 0.f;
    float rst_count            = 0.f;
    float fin_count            = 0.f;
    float syn_no_ack_ratio     = 0.f; // syn_no_ack / syn_count

    // ── Rate-based (10–12) ────────────────────────────────────────────────────
    float pkt_rate             = 0.f; // packets/sec
    float byte_rate            = 0.f; // bytes/sec
    float pkt_per_flow         = 0.f; // total_packets / flow_duration

    // ── Slow DDoS specific (13–17) ────────────────────────────────────────────
    float conn_duration        = 0.f; // seconds (alias flow_duration cho HTTP)
    float bytes_per_second     = 0.f; // total_bytes / duration
    float inter_arrival_mean   = 0.f; // mean IAT (ms)
    float inter_arrival_std    = 0.f; // std IAT (ms)
    float header_complete      = 0.f; // 1.0 = complete, 0.0 = incomplete
    float concurrent_conn      = 0.f; // số kết nối đồng thời từ src_ip

    // ── Port Scan specific (18–19) ────────────────────────────────────────────
    float unique_dst_ports     = 0.f; // số port đích khác nhau
    float rst_ratio            = 0.f; // rst_count / total_packets

    // ── Helpers ───────────────────────────────────────────────────────────────
    static constexpr size_t SIZE = 21;

    // Convert sang array để feed vào ONNX
    std::array<float, SIZE> toArray() const;

    // Debug string
    std::string toString() const;
};

// Trích xuất FeatureVector từ FlowState
class FeatureExtractor {
public:
    // Trích xuất features từ flow state hiện tại
    FeatureVector extract(const FlowState& flow) const;

    // Normalize features về [0, 1] dựa trên lab baseline
    // (đơn giản hóa — production cần StandardScaler fit trên training data)
    FeatureVector normalize(const FeatureVector& raw) const;

private:
    // Min-max bounds ước lượng từ CICIDS2017 (lab baseline)
    struct Bounds {
        float min_val;
        float max_val;
    };

    static const std::array<Bounds, FeatureVector::SIZE> BOUNDS;

    float clampNormalize(float val,
                         float min_val,
                         float max_val) const;
};
