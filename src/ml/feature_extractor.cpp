//src/ml/feature_extractor.cpp
#include "feature_extractor.hpp"
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>

// ─── Min-Max bounds từ CICIDS2017 (ước lượng cho lab) ────────────────────────
// Format: {min, max} cho từng feature theo thứ tự FeatureVector
const std::array<FeatureExtractor::Bounds, FeatureVector::SIZE>
FeatureExtractor::BOUNDS = {{
    {0.f,    3600.f},   // flow_duration       (0 – 1 giờ)
    {0.f,    100000.f}, // total_pkt_fwd
    {0.f,    100000.f}, // total_pkt_bwd
    {0.f,    1e8f},     // total_byte_fwd
    {0.f,    1e8f},     // total_byte_bwd
    {0.f,    10000.f},  // syn_count
    {0.f,    10000.f},  // ack_count
    {0.f,    10000.f},  // rst_count
    {0.f,    10000.f},  // fin_count
    {0.f,    1.f},      // syn_no_ack_ratio    (0 – 1)
    {0.f,    50000.f},  // pkt_rate            (pps)
    {0.f,    1e9f},     // byte_rate           (bps)
    {0.f,    1000.f},   // pkt_per_flow
    {0.f,    3600.f},   // conn_duration
    {0.f,    1e7f},     // bytes_per_second
    {0.f,    60000.f},  // inter_arrival_mean  (ms)
    {0.f,    60000.f},  // inter_arrival_std   (ms)
    {0.f,    1.f},      // header_complete     (binary)
    {0.f,    200.f},    // concurrent_conn
    {0.f,    65535.f},  // unique_dst_ports
    {0.f,    1.f},      // rst_ratio           (0 – 1)
}};

// ─── Extract ──────────────────────────────────────────────────────────────────
FeatureVector FeatureExtractor::extract(const FlowState& flow) const {
    FeatureVector fv;

    // ── Flow-based ────────────────────────────────────────────────────────────
    fv.flow_duration  = static_cast<float>(flow.durationSeconds());
    fv.total_pkt_fwd  = static_cast<float>(flow.fwd_packets);
    fv.total_pkt_bwd  = static_cast<float>(flow.bwd_packets);
    fv.total_byte_fwd = static_cast<float>(flow.total_bytes * 0.6f); // ước lượng
    fv.total_byte_bwd = static_cast<float>(flow.total_bytes * 0.4f);

    // ── TCP Flags ─────────────────────────────────────────────────────────────
    fv.syn_count  = static_cast<float>(flow.syn_count);
    fv.ack_count  = static_cast<float>(flow.ack_count);
    fv.rst_count  = static_cast<float>(flow.rst_count);
    fv.fin_count  = static_cast<float>(flow.fin_count);

    fv.syn_no_ack_ratio = (flow.syn_count > 0)
        ? static_cast<float>(flow.syn_no_ack) /
          static_cast<float>(flow.syn_count)
        : 0.f;

    // ── Rate-based ────────────────────────────────────────────────────────────
    double dur = std::max(flow.durationSeconds(), 0.001); // tránh chia 0
    fv.pkt_rate     = static_cast<float>(flow.total_packets / dur);
    fv.byte_rate    = static_cast<float>(flow.total_bytes   / dur);
    fv.pkt_per_flow = static_cast<float>(flow.total_packets);

    // ── Slow DDoS specific ────────────────────────────────────────────────────
    fv.conn_duration    = fv.flow_duration;
    fv.bytes_per_second = static_cast<float>(flow.bytesPerSecond());

    // Inter-arrival time: ước lượng từ duration và packet count
    // Production: cần track timestamp từng gói tin
    if (flow.total_packets > 1) {
        float avg_iat = static_cast<float>(
            (dur * 1000.0) / (flow.total_packets - 1)); // ms
        fv.inter_arrival_mean = avg_iat;
        // Std ước lượng (simplified — production cần Welford's algorithm)
        fv.inter_arrival_std  = avg_iat * 0.3f;
    }

    fv.header_complete  = flow.http_header_complete ? 1.f : 0.f;
    fv.concurrent_conn  = static_cast<float>(flow.concurrent_conn);

    // ── Port Scan specific ────────────────────────────────────────────────────
    fv.unique_dst_ports = static_cast<float>(flow.dst_ports_seen.size());
    fv.rst_ratio = (flow.total_packets > 0)
        ? static_cast<float>(flow.rst_count) /
          static_cast<float>(flow.total_packets)
        : 0.f;

    return fv;
}

// ─── Normalize ────────────────────────────────────────────────────────────────
FeatureVector FeatureExtractor::normalize(const FeatureVector& raw) const {
    auto arr = raw.toArray();
    FeatureVector norm;
    auto norm_arr = norm.toArray();

    for (size_t i = 0; i < FeatureVector::SIZE; i++) {
        norm_arr[i] = clampNormalize(
            arr[i], BOUNDS[i].min_val, BOUNDS[i].max_val);
    }

    // Copy back từ array → struct
    // (đơn giản hóa — production dùng reflection hoặc macro)
    norm.flow_duration      = norm_arr[0];
    norm.total_pkt_fwd      = norm_arr[1];
    norm.total_pkt_bwd      = norm_arr[2];
    norm.total_byte_fwd     = norm_arr[3];
    norm.total_byte_bwd     = norm_arr[4];
    norm.syn_count          = norm_arr[5];
    norm.ack_count          = norm_arr[6];
    norm.rst_count          = norm_arr[7];
    norm.fin_count          = norm_arr[8];
    norm.syn_no_ack_ratio   = norm_arr[9];
    norm.pkt_rate           = norm_arr[10];
    norm.byte_rate          = norm_arr[11];
    norm.pkt_per_flow       = norm_arr[12];
    norm.conn_duration      = norm_arr[13];
    norm.bytes_per_second   = norm_arr[14];
    norm.inter_arrival_mean = norm_arr[15];
    norm.inter_arrival_std  = norm_arr[16];
    norm.header_complete    = norm_arr[17];
    norm.concurrent_conn    = norm_arr[18];
    norm.unique_dst_ports   = norm_arr[19];
    norm.rst_ratio          = norm_arr[20]; // index 19

    return norm;
}

float FeatureExtractor::clampNormalize(float val,
                                        float min_val,
                                        float max_val) const {
    if (max_val <= min_val) return 0.f;
    float normalized = (val - min_val) / (max_val - min_val);
    return std::clamp(normalized, 0.f, 1.f);
}

// ─── FeatureVector helpers ────────────────────────────────────────────────────
std::array<float, FeatureVector::SIZE> FeatureVector::toArray() const {
    return {
        flow_duration, total_pkt_fwd, total_pkt_bwd,
        total_byte_fwd, total_byte_bwd,
        syn_count, ack_count, rst_count, fin_count,
        syn_no_ack_ratio,
        pkt_rate, byte_rate, pkt_per_flow,
        conn_duration, bytes_per_second,
        inter_arrival_mean, inter_arrival_std,
        header_complete, concurrent_conn,
        unique_dst_ports, rst_ratio
    };
}

std::string FeatureVector::toString() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3);
    oss << "FeatureVector {\n"
        << "  flow_duration      : " << flow_duration      << "s\n"
        << "  pkt_rate           : " << pkt_rate           << " pps\n"
        << "  byte_rate          : " << byte_rate          << " bps\n"
        << "  syn_no_ack_ratio   : " << syn_no_ack_ratio   << "\n"
        << "  conn_duration      : " << conn_duration      << "s\n"
        << "  bytes_per_second   : " << bytes_per_second   << "\n"
        << "  inter_arrival_mean : " << inter_arrival_mean << "ms\n"
        << "  header_complete    : " << header_complete    << "\n"
        << "  unique_dst_ports   : " << unique_dst_ports   << "\n"
        << "  rst_ratio          : " << rst_ratio          << "\n"
        << "}";
    return oss.str();
}
