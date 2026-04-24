// src/ml/feature_extractor.cpp

#include "feature_extractor.hpp"
#include "../common/logger.hpp"
#include <sstream>
#include <iomanip>

// =============================================================================
//  StandardScaler
// =============================================================================

bool StandardScaler::load(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        LOG_WARN("StandardScaler: cannot open " + path);
        return false;
    }

    f.read(reinterpret_cast<char*>(mean_.data()),
           sizeof(float) * FeatureVector::SIZE);
    f.read(reinterpret_cast<char*>(std_.data()),
           sizeof(float) * FeatureVector::SIZE);

    if (!f) {
        LOG_WARN("StandardScaler: read error from " + path);
        return false;
    }

    for (size_t i = 0; i < FeatureVector::SIZE; ++i) {
        if (std_[i] <= 0.f) {
            LOG_WARN("StandardScaler: std[" + std::to_string(i)
                     + "]=" + std::to_string(std_[i]) + " <= 0, clamping to 1");
            std_[i] = 1.f;
        }
    }

    loaded_ = true;
    LOG_INFO("StandardScaler loaded from " + path);
    return true;
}

bool StandardScaler::save(const std::string& path) const {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(mean_.data()),
            sizeof(float) * FeatureVector::SIZE);
    f.write(reinterpret_cast<const char*>(std_.data()),
            sizeof(float) * FeatureVector::SIZE);
    return f.good();
}

std::array<float, FeatureVector::SIZE>
StandardScaler::transform(
    const std::array<float, FeatureVector::SIZE>& raw) const
{
    if (!loaded_) {
        LOG_DEBUG("StandardScaler: not loaded — using raw features (identity)");
        return raw;
    }
    std::array<float, FeatureVector::SIZE> out;
    for (size_t i = 0; i < FeatureVector::SIZE; ++i) {
        float z = (raw[i] - mean_[i]) / std_[i];
        out[i]  = std::clamp(z, -5.f, 5.f);
    }
    return out;
}

// =============================================================================
//  FeatureExtractor
// =============================================================================

bool FeatureExtractor::loadScaler(const std::string& scaler_path) {
    return scaler_.load(scaler_path);
}

// TLS ports — unique_dst_ports không có ý nghĩa với encrypted traffic
static constexpr std::array<uint16_t, 6> TLS_PORTS_FE = {
    443, 8443, 9443, 465, 993, 995
};
static bool isTlsPortFE(uint16_t port) {
    for (auto p : TLS_PORTS_FE) if (p == port) return true;
    return false;
}

FeatureVector FeatureExtractor::extract(const FlowState& flow) const {
    FeatureVector fv;

    // [FIX-C] Guard: flow chưa có packet nào → trả về zero vector
    // Tránh chia 0 và NaN trong tất cả các tính toán bên dưới
    if (flow.total_packets == 0)
        return fv;

    // ── Group 1: Flow-based ───────────────────────────────────────────────────
    //
    // [FIX-A] rate_valid guard:
    //   Không tính rate khi flow quá mới (total_packets <= 2 hoặc dur <= 1ms)
    //
    //   Tại sao threshold total_packets > 2?
    //     n=1: chỉ có SYN, raw_dur ≈ 0 → rate = 1/ε = ∞ → sau scaler = +5
    //     n=2: SYN + SYN-ACK, raw_dur = 1 RTT ≈ vài ms
    //          rate = 2/0.002 = 1000 pps → sau scaler vẫn rất cao
    //     n>=3: flow đã có ít nhất 1 data exchange → rate có nghĩa
    //
    //   Tại sao threshold raw_dur > 0.001s (1ms)?
    //     Dưới 1ms: flow quá mới, clock resolution artifact
    //     → rate không đáng tin cậy
    //
    //   Tác động với Slowloris (n=1-3 per flow):
    //     rate_valid = false → pkt_rate = 0, byte_rate = 0
    //     Pattern: {syn=1, ack=0, pkt_rate=0, bytes=0, conn_duration≈0}
    //     → Khác với port scan {pkt_rate=high} → model phân biệt được
    //
    const double raw_dur   = flow.durationSeconds();
    const bool   rate_valid = (flow.total_packets > 2 && raw_dur > 0.001);
    const double dur        = rate_valid ? raw_dur : 1.0;  // tránh chia 0

    fv.flow_duration  = static_cast<float>(raw_dur);
    fv.total_pkt_fwd  = static_cast<float>(flow.fwd_packets);  // [FIX-B]
    fv.total_pkt_bwd  = static_cast<float>(flow.bwd_packets);  // [FIX-B]
    fv.total_byte_fwd = static_cast<float>(flow.fwd_bytes);
    fv.total_byte_bwd = static_cast<float>(flow.bwd_bytes);

    // ── Group 2: TCP Flags ────────────────────────────────────────────────────
    //
    // Các field này giờ được update đúng trong worker_thread.cpp step 2b
    // [FIX-2 trong worker_thread.cpp]
    fv.syn_count = static_cast<float>(flow.syn_count);
    fv.ack_count = static_cast<float>(flow.ack_count);
    fv.rst_count = static_cast<float>(flow.rst_count);
    fv.fin_count = static_cast<float>(flow.fin_count);
    fv.syn_no_ack_ratio = (flow.syn_count > 0)
        ? static_cast<float>(flow.syn_no_ack) /
          static_cast<float>(flow.syn_count)
        : 0.f;

    // ── Group 3: Rate-based ───────────────────────────────────────────────────
    //
    // [FIX-A] Chỉ tính rate khi rate_valid = true
    // Khi false: set = 0.f thay vì ∞ → tránh false positive PORT_SCAN
    fv.pkt_rate     = rate_valid
                    ? static_cast<float>(flow.total_packets / dur)
                    : 0.f;
    fv.byte_rate    = rate_valid
                    ? static_cast<float>(flow.total_bytes / dur)
                    : 0.f;
    fv.pkt_per_flow = static_cast<float>(flow.total_packets);

    // ── Group 4: Slow DDoS ────────────────────────────────────────────────────
    fv.conn_duration    = fv.flow_duration;
    fv.bytes_per_second = rate_valid
                        ? static_cast<float>(flow.bytesPerSecond())
                        : 0.f;

    fv.inter_arrival_mean = static_cast<float>(flow.iat_mean_ms);
    fv.inter_arrival_std  = static_cast<float>(
        (flow.iat_m2 > 0.0 && flow.total_packets > 1)
        ? std::sqrt(flow.iat_m2 / static_cast<double>(flow.total_packets - 1))
        : 0.0);

    fv.header_complete = flow.http_header_complete ? 1.f : 0.f;
    fv.concurrent_conn = static_cast<float>(flow.concurrent_conn);

    // ── Group 5: Port Scan ────────────────────────────────────────────────────
    //
    // [FIX-D] dst_ports_seen.size() giờ có giá trị thực:
    //   worker_thread.cpp [FIX-4] insert mọi SYN (no-ACK) probe
    //   → size() = số dst_port khác nhau đã probe
    //
    //   Port scan thực: nhiều dst_port khác nhau → size() lớn
    //   Slowloris: dst_port=80 luôn cố định → size() = 1
    //   Normal flow: dst_port cố định trong 5-tuple → size() = 1
    //
    // TLS suppression vẫn giữ:
    //   Encrypted traffic → feature không có ý nghĩa
    //   → tránh AE nhầm TLS entropy cao = port scan pattern
    const bool is_tls = isTlsPortFE(flow.dst_port)
                     || isTlsPortFE(flow.src_port);

    if (is_tls) {
        fv.unique_dst_ports = 0.f;
    } else {
#ifdef FLOW_HAS_SRC_PORTS_SEEN
        fv.unique_dst_ports = static_cast<float>(flow.src_ports_seen.size());
#else
        // [FIX-D] dst_ports_seen giờ có giá trị thực
        fv.unique_dst_ports = static_cast<float>(flow.dst_ports_seen.size());
#endif
    }

    fv.rst_ratio = (flow.total_packets > 0)
        ? static_cast<float>(flow.rst_count) /
          static_cast<float>(flow.total_packets)
        : 0.f;

    return fv;
}

std::array<float, FeatureVector::SIZE>
FeatureExtractor::extractAndNormalize(const FlowState& flow) const {
    return scaler_.transform(extract(flow).toArray());
}

std::array<float, FeatureVector::SIZE>
FeatureExtractor::normalizeRaw(const FeatureVector& fv) const {
    return scaler_.transform(fv.toArray());
}

// =============================================================================
//  FeatureVector helpers
// =============================================================================

std::array<float, FeatureVector::SIZE> FeatureVector::toArray() const {
    return {
        flow_duration,      total_pkt_fwd,       total_pkt_bwd,
        total_byte_fwd,     total_byte_bwd,
        syn_count,          ack_count,            rst_count,
        fin_count,          syn_no_ack_ratio,
        pkt_rate,           byte_rate,            pkt_per_flow,
        conn_duration,      bytes_per_second,
        inter_arrival_mean, inter_arrival_std,
        header_complete,    concurrent_conn,
        unique_dst_ports,   rst_ratio
    };
}

std::string FeatureVector::toString() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(4);
    oss << "FeatureVector {\n"
        << "  [0]  flow_duration      : " << flow_duration      << " s\n"
        << "  [1]  total_pkt_fwd      : " << total_pkt_fwd      << "\n"
        << "  [2]  total_pkt_bwd      : " << total_pkt_bwd      << "\n"
        << "  [3]  total_byte_fwd     : " << total_byte_fwd     << "\n"
        << "  [4]  total_byte_bwd     : " << total_byte_bwd     << "\n"
        << "  [5]  syn_count          : " << syn_count          << "\n"
        << "  [6]  ack_count          : " << ack_count          << "\n"
        << "  [7]  rst_count          : " << rst_count          << "\n"
        << "  [8]  fin_count          : " << fin_count          << "\n"
        << "  [9]  syn_no_ack_ratio   : " << syn_no_ack_ratio   << "\n"
        << "  [10] pkt_rate           : " << pkt_rate           << " pps\n"
        << "  [11] byte_rate          : " << byte_rate          << " bps\n"
        << "  [12] pkt_per_flow       : " << pkt_per_flow       << "\n"
        << "  [13] conn_duration      : " << conn_duration      << " s\n"
        << "  [14] bytes_per_second   : " << bytes_per_second   << "\n"
        << "  [15] inter_arrival_mean : " << inter_arrival_mean << " ms\n"
        << "  [16] inter_arrival_std  : " << inter_arrival_std  << " ms\n"
        << "  [17] header_complete    : " << header_complete    << "\n"
        << "  [18] concurrent_conn    : " << concurrent_conn    << "\n"
        << "  [19] unique_dst_ports   : " << unique_dst_ports   << "\n"
        << "  [20] rst_ratio          : " << rst_ratio          << "\n"
        << "}";
    return oss.str();
}
