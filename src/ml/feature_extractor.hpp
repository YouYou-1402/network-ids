#pragma once
#include "../detection/flow_state.hpp"
#include "../core/packet_info.hpp"
#include <array>
#include <string>
#include <fstream>
#include <algorithm>
#include <cmath>


struct FeatureVector {
    // Group 1: Flow-based (0–4)
    float flow_duration        = 0.f;
    float total_pkt_fwd        = 0.f;
    float total_pkt_bwd        = 0.f;
    float total_byte_fwd       = 0.f;
    float total_byte_bwd       = 0.f;

    // Group 2: TCP Flags (5–9)
    float syn_count            = 0.f;
    float ack_count            = 0.f;
    float rst_count            = 0.f;
    float fin_count            = 0.f;
    float syn_no_ack_ratio     = 0.f;

    // Group 3: Rate-based (10–12)
    float pkt_rate             = 0.f;
    float byte_rate            = 0.f;
    float pkt_per_flow         = 0.f;

    // Group 4: Slow DDoS (13–18)
    float conn_duration        = 0.f;
    float bytes_per_second     = 0.f;
    float inter_arrival_mean   = 0.f;   // ms — Welford's mean
    float inter_arrival_std    = 0.f;   // ms — Welford's std
    float header_complete      = 0.f;
    float concurrent_conn      = 0.f;

    // Group 5: Port Scan (19–20)
    float unique_dst_ports     = 0.f;
    float rst_ratio            = 0.f;

    static constexpr size_t SIZE = 21;

    std::array<float, SIZE> toArray() const;
    std::string toString() const;
};

// =============================================================================
//  StandardScaler — fit offline trên CICIDS2017, load từ file .bin
//
//  Tại sao StandardScaler thay vì MinMax?
//    - MinMax nhạy cảm với outlier (1 packet rate=1M pps compress toàn bộ)
//    - StandardScaler (z-score) robust hơn với outlier trong network traffic
//    - ONNX model được train với StandardScaler → phải dùng cùng scaler
//
//  File format (binary, little-endian):
//    [float32 mean×21][float32 std×21]  = 168 bytes total
// =============================================================================
struct StandardScaler {
    std::array<float, FeatureVector::SIZE> mean_{};
    std::array<float, FeatureVector::SIZE> std_ {};

    bool load(const std::string& path);
    bool save(const std::string& path) const;

    // Transform: z = (x - mean) / std, clamp [-5, 5]
    std::array<float, FeatureVector::SIZE>
    transform(const std::array<float, FeatureVector::SIZE>& raw) const;

    bool isLoaded() const { return loaded_; }

private:
    bool loaded_ = false;
};

// =============================================================================
//  FeatureExtractor
// =============================================================================
class 
FeatureExtractor {
public:
    bool loadScaler(const std::string& scaler_path);

    FeatureVector extract(const FlowState& flow) const;

    // Normalize từ FlowState trực tiếp
    std::array<float, FeatureVector::SIZE>
    extractAndNormalize(const FlowState& flow) const;

    // Normalize từ FeatureVector đã có sẵn (dùng trong MLEngine::processJob)
    std::array<float, FeatureVector::SIZE>
    normalizeRaw(const FeatureVector& fv) const;

    bool scalerLoaded() const { return scaler_.isLoaded(); }

private:
    StandardScaler scaler_;
};
