// =============================================================================
//  src/detection/protocol_anomaly.cpp
// =============================================================================
#include "protocol_anomaly.hpp"
#include "../common/logger.hpp"
#include "../common/config_loader.hpp"
#include <cstring>
#include <netinet/in.h>
#include <algorithm>

// ─── Constructor ──────────────────────────────────────────────────────────────
ProtocolAnomalyEngine::ProtocolAnomalyEngine(IpTracker& ip_tracker)
    : ip_tracker_(ip_tracker)
{
    const auto& pa = APP_CFG.protocol_anomaly;
    http_header_timeout_sec_    = pa.http_header_timeout_sec;
    min_bytes_per_sec_          = pa.min_bytes_per_sec;
    max_concurrent_conn_        = pa.max_concurrent_conn;
    slowloris_conn_min_         = pa.slowloris_conn_min;
    slow_post_duration_min_sec_ = pa.slow_post_duration_min_sec;
    win_zero_count_threshold_   = pa.win_zero_count_threshold;
    http_ports_                 = pa.http_ports;

    LOG_INFO("ProtocolAnomalyEngine: initialized"
             " header_timeout=" + std::to_string(http_header_timeout_sec_) + "s"
           + " min_bps="        + std::to_string(min_bytes_per_sec_)
           + " max_conn="       + std::to_string(max_concurrent_conn_)
           + " slowloris_min="  + std::to_string(slowloris_conn_min_)
           + " slow_post_min="  + std::to_string(slow_post_duration_min_sec_) + "s"
           + " win_zero_thr="   + std::to_string(win_zero_count_threshold_));
}

// ─── isHttpPort ───────────────────────────────────────────────────────────────
bool ProtocolAnomalyEngine::isHttpPort(uint16_t port) const {
    return std::find(http_ports_.begin(), http_ports_.end(), port)
           != http_ports_.end();
}

// =============================================================================
//  onSyn — gọi từ WorkerThread TRƯỚC tất cả detection engine
//
//  Tách riêng khỏi analyze() để đảm bảo http_start luôn được set
//  ngay cả khi sig_engine_ detect DDOS_VOLUMETRIC và return sớm.
//
//  Lý do:
//    WorkerThread pipeline:
//      5. sig_engine_.analyze()      ← có thể return DDOS_VOLUMETRIC
//      6. anomaly_engine_.analyze()  ← bị skip nếu step 5 detect
//
//    Nếu http_start không được set tại step 5 (SYN packet),
//    thì khi packet tiếp theo tới (keep-alive header),
//    flow.http_start == TimePoint{} → checkSlowloris() return NORMAL ngay.
//
//  Giải pháp: gọi onSyn() tại step 2c (sau flow lookup, trước detection)
//  → http_start luôn được set bất kể engine nào detect trước.
// =============================================================================
void ProtocolAnomalyEngine::onSyn(const PacketInfo& pkt, FlowState& flow) {
    if (!pkt.hasSYN() || pkt.hasACK())
        return;

    // Chỉ track HTTP/HTTPS port
    if (!isHttpPort(pkt.dst_port) && pkt.dst_port != 443)
        return;

    // Set http_start — đây là điểm khởi đầu đo timeout Slowloris
    flow.http_start           = Clock::now();
    flow.http_bytes_received  = 0;
    flow.http_header_complete = false;
    flow.slowloris_alerted    = false;
    flow.slow_post_alerted    = false;

    ip_tracker_.withStats(pkt.src_ip, [](IpStats& ip) {
        ip.concurrent_conn++;
    });

    LOG_DEBUG("ProtocolAnomalyEngine::onSyn: http_start set"
              " flow=" + pkt.flowKey()
              + " dst_port=" + std::to_string(pkt.dst_port));
}

// ─── analyze ──────────────────────────────────────────────────────────────────
DetectionResult ProtocolAnomalyEngine::analyze(const PacketInfo& pkt,
                                                FlowState&        flow) {
    if (pkt.protocol != IPPROTO_TCP)
        return DetectionResult::NORMAL;

    const bool is_http_port = isHttpPort(pkt.dst_port)
                           || (pkt.dst_port == 443);
    if (!is_http_port)
        return DetectionResult::NORMAL;

    // ── SYN đã được handle bởi onSyn() — chỉ return NORMAL ──────────────
    // onSyn() được gọi từ WorkerThread trước detection pipeline
    // Không xử lý SYN ở đây nữa để tránh double-increment concurrent_conn
    if (pkt.hasSYN() && !pkt.hasACK())
        return DetectionResult::NORMAL;

    // ── FIN/RST: giảm concurrent_conn ────────────────────────────────────
    if (pkt.hasFIN() || pkt.hasRST()) {
        ip_tracker_.withStats(pkt.src_ip, [](IpStats& ip) {
            if (ip.concurrent_conn > 0) ip.concurrent_conn--;
        });
        return DetectionResult::NORMAL;
    }

    // Guard: http_start chưa được set → bỏ qua
    // Trường hợp này xảy ra khi IDS khởi động giữa chừng,
    // bắt được packet giữa flow (không có SYN)
    if (flow.http_start == TimePoint{})
        return DetectionResult::NORMAL;

    flow.http_bytes_received += pkt.payload_len;

    // ── Detect header completion (HTTP plaintext only) ────────────────────
    if (!flow.http_header_complete
        && isHttpPort(pkt.dst_port)
        && pkt.payload_len > 0
        && pkt.payload() != nullptr) {
        if (memmem(pkt.payload(), pkt.payload_len, "\r\n\r\n", 4) != nullptr)
            flow.http_header_complete = true;
    }

    // ── Concurrent connection flood ───────────────────────────────────────
    uint32_t concurrent_conn_snap = 0;
    ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
        concurrent_conn_snap = ip.concurrent_conn;
    });

    if (concurrent_conn_snap > max_concurrent_conn_) {
        LOG_WARN("ProtocolAnomalyEngine: conn flood"
                 " src="        + pkt.flowKey()
                 + " concurrent=" + std::to_string(concurrent_conn_snap)
                 + " max="        + std::to_string(max_concurrent_conn_));
        return DetectionResult::SLOW_DDOS;
    }

    auto r = checkSlowloris(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    r = checkSlowPost(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    return checkSlowRead(pkt, flow);
}

// ─── checkSlowloris ───────────────────────────────────────────────────────────
DetectionResult ProtocolAnomalyEngine::checkSlowloris(const PacketInfo& pkt,
                                                        FlowState&        flow) {
    if (flow.slowloris_alerted)
        return DetectionResult::NORMAL;

    const double elapsed = std::chrono::duration<double>(
        Clock::now() - flow.http_start).count();

    // Chưa đủ thời gian timeout → chưa kết luận
    if (elapsed < http_header_timeout_sec_)
        return DetectionResult::NORMAL;

    if (pkt.dst_port == 443) {
        // ── HTTPS: heuristic throughput + concurrent conn ─────────────────
        if (flow.http_bytes_received == 0)
            return DetectionResult::NORMAL;

        const double bps = static_cast<double>(flow.http_bytes_received)
                         / elapsed;
        const bool low_throughput = (bps < min_bytes_per_sec_);
        const bool has_activity   = (flow.total_packets > 5);

        uint32_t conn_snap = 0;
        ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
            conn_snap = ip.concurrent_conn;
        });
        const bool many_conn = (conn_snap >= slowloris_conn_min_);

        if (low_throughput && has_activity && many_conn) {
            flow.slowloris_alerted = true;
            LOG_WARN("ProtocolAnomalyEngine: Slowloris/TLS"
                     " bps="     + std::to_string(static_cast<int>(bps))
                     + " elapsed=" + std::to_string(static_cast<int>(elapsed)) + "s"
                     + " conn="    + std::to_string(conn_snap)
                     + " from "    + pkt.flowKey());
            return DetectionResult::SLOW_DDOS;
        }

    } else {
        // ── HTTP plaintext: header chưa hoàn chỉnh sau timeout ───────────
        //
        // Slowloris gửi header từng dòng, cố tình không gửi "\r\n\r\n"
        // → http_header_complete = false mãi mãi
        // → Sau http_header_timeout_sec_ giây → SLOW_DDOS
        //
        // Điều kiện:
        //   1. http_header_complete == false  : header chưa xong
        //   2. http_bytes_received > 0        : đã nhận được gì đó
        //                                       (tránh false positive với
        //                                        connection idle hoàn toàn)
        //   3. total_packets >= 2             : ít nhất SYN + 1 data packet
        //                                       (tránh false positive với
        //                                        half-open connection)
        if (!flow.http_header_complete
            && flow.http_bytes_received > 0
            && flow.total_packets >= 2)
        {
            flow.slowloris_alerted = true;
            LOG_WARN("ProtocolAnomalyEngine: Slowloris detected"
                     " header incomplete after "
                     + std::to_string(static_cast<int>(elapsed)) + "s"
                     + " timeout="  + std::to_string(http_header_timeout_sec_)
                     + " bytes_rx=" + std::to_string(flow.http_bytes_received)
                     + " packets="  + std::to_string(flow.total_packets)
                     + " from "     + pkt.flowKey());
            return DetectionResult::SLOW_DDOS;
        }
    }

    return DetectionResult::NORMAL;
}

// ─── checkSlowPost ────────────────────────────────────────────────────────────
DetectionResult ProtocolAnomalyEngine::checkSlowPost(const PacketInfo& pkt,
                                                       FlowState&        flow) {
    if (flow.slow_post_alerted)
        return DetectionResult::NORMAL;

    if (!isHttpPort(pkt.dst_port))
        return DetectionResult::NORMAL;

    if (!flow.http_header_complete)
        return DetectionResult::NORMAL;

    const double elapsed = std::chrono::duration<double>(
        Clock::now() - flow.http_start).count();

    if (elapsed < slow_post_duration_min_sec_)
        return DetectionResult::NORMAL;

    const double bps = (elapsed > 0.0)
                       ? static_cast<double>(flow.http_bytes_received) / elapsed
                       : 0.0;

    if (bps < min_bytes_per_sec_ && flow.http_bytes_received > 0) {
        flow.slow_post_alerted = true;
        LOG_WARN("ProtocolAnomalyEngine: Slow POST"
                 " bps="     + std::to_string(static_cast<int>(bps))
                 + " elapsed=" + std::to_string(static_cast<int>(elapsed)) + "s"
                 + " min_bps=" + std::to_string(min_bytes_per_sec_)
                 + " from "    + pkt.flowKey());
        return DetectionResult::SLOW_DDOS;
    }
    return DetectionResult::NORMAL;
}

// ─── checkSlowRead ────────────────────────────────────────────────────────────
DetectionResult ProtocolAnomalyEngine::checkSlowRead(const PacketInfo& pkt,
                                                       FlowState&        flow) {
    if (!pkt.hasACK() || flow.total_packets <= 5)
        return DetectionResult::NORMAL;

    if (pkt.win_size == 0) {
        flow.win_zero_count++;
        if (flow.win_zero_count >= win_zero_count_threshold_) {
            LOG_WARN("ProtocolAnomalyEngine: Slow Read"
                     " win=0 x"   + std::to_string(flow.win_zero_count)
                     + " thresh="   + std::to_string(win_zero_count_threshold_)
                     + " from "     + pkt.flowKey()
                     + " packets="  + std::to_string(flow.total_packets));
            return DetectionResult::SLOW_DDOS;
        }
    } else {
        flow.win_zero_count = 0;
    }

    return DetectionResult::NORMAL;
}
