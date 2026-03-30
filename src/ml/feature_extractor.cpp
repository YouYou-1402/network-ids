// =============================================================================
//  src/ml/feature_extractor.cpp
//
//  Fix so với phiên bản cũ:
//    [FIX-5] unique_dst_ports: không dùng dst_ports_seen.size() nữa
//            vì trong 1 flow (5-tuple), dst_port đã cố định trong flow key
//            → dst_ports_seen.size() luôn = 1 → feature vô nghĩa
//            Thay bằng src_ports_seen.size() (nếu FlowState có field này)
//    [FIX-6] TLS suppression: nếu dst_port là TLS port
//            → set unique_dst_ports = 0.f
//            Lý do: encrypted traffic, feature không có ý nghĩa,
//            tránh AE nhầm TLS entropy cao = port scan pattern
// =============================================================================

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

    // ── Group 1: Flow-based ───────────────────────────────────────────────
    const double dur = std::max(flow.durationSeconds(), 1e-6);

    fv.flow_duration  = static_cast<float>(flow.durationSeconds());
    fv.total_pkt_fwd  = static_cast<float>(flow.fwd_packets);
    fv.total_pkt_bwd  = static_cast<float>(flow.bwd_packets);
    fv.total_byte_fwd = static_cast<float>(flow.fwd_bytes);
    fv.total_byte_bwd = static_cast<float>(flow.bwd_bytes);

    // ── Group 2: TCP Flags ────────────────────────────────────────────────
    fv.syn_count = static_cast<float>(flow.syn_count);
    fv.ack_count = static_cast<float>(flow.ack_count);
    fv.rst_count = static_cast<float>(flow.rst_count);
    fv.fin_count = static_cast<float>(flow.fin_count);
    fv.syn_no_ack_ratio = (flow.syn_count > 0)
        ? static_cast<float>(flow.syn_no_ack) /
          static_cast<float>(flow.syn_count)
        : 0.f;

    // ── Group 3: Rate-based ───────────────────────────────────────────────
    fv.pkt_rate     = static_cast<float>(flow.total_packets / dur);
    fv.byte_rate    = static_cast<float>(flow.total_bytes   / dur);
    fv.pkt_per_flow = static_cast<float>(flow.total_packets);

    // ── Group 4: Slow DDoS ────────────────────────────────────────────────
    fv.conn_duration    = fv.flow_duration;
    fv.bytes_per_second = static_cast<float>(flow.bytesPerSecond());

    fv.inter_arrival_mean = static_cast<float>(flow.iat_mean_ms);
    fv.inter_arrival_std  = static_cast<float>(
        (flow.iat_m2 > 0.0 && flow.total_packets > 1)
        ? std::sqrt(flow.iat_m2 / static_cast<double>(flow.total_packets - 1))
        : 0.0);

    fv.header_complete = flow.http_header_complete ? 1.f : 0.f;
    fv.concurrent_conn = static_cast<float>(flow.concurrent_conn);

    // ── Group 5: Port Scan ────────────────────────────────────────────────
    //
    // [FIX-5] unique_dst_ports cũ = dst_ports_seen.size()
    //
    // Bug: trong 1 flow (5-tuple = src_ip, dst_ip, src_port, dst_port, proto),
    //      dst_port đã cố định trong flow key → dst_ports_seen.size() = 1
    //      → feature luôn = 1 → vô nghĩa với model.
    //
    // Fix: dùng src_ports_seen.size() — số src_port khác nhau trong flow.
    //   - Port scan thực: attacker mở nhiều conn từ nhiều src_port → lớn
    //   - YouTube CDN: cùng src_ip:443, mỗi flow có 1 src_port → = 1
    //
    // [FIX-6] TLS suppression:
    //   Nếu dst_port hoặc src_port là TLS port → set = 0.f
    //   Encrypted traffic: feature không có ý nghĩa, tránh AE false positive.
    //
    const bool is_tls = isTlsPortFE(flow.dst_port)
                     || isTlsPortFE(flow.src_port);

    if (is_tls) {
        // [FIX-6] TLS port → suppress port-scan feature
        fv.unique_dst_ports = 0.f;
    } else {
#ifdef FLOW_HAS_SRC_PORTS_SEEN
        // [FIX-5] Dùng src_ports_seen nếu FlowState đã được update
        fv.unique_dst_ports = static_cast<float>(flow.src_ports_seen.size());
#else
        // Fallback: giữ backward compat nếu FlowState chưa có src_ports_seen
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
