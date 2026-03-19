// src/detection/protocol_anomaly.cpp
#include "protocol_anomaly.hpp"
#include "../common/logger.hpp"
#include <cstring>
#include <netinet/in.h>

ProtocolAnomalyEngine::ProtocolAnomalyEngine(IpTracker& ip_tracker)
    : ip_tracker_(ip_tracker)
{
    LOG_INFO("ProtocolAnomalyEngine initialized");
}

// ─── analyze ──────────────────────────────────────────────────────────────────
DetectionResult ProtocolAnomalyEngine::analyze(const PacketInfo& pkt,
                                                FlowState&        flow) {
    if (pkt.protocol != IPPROTO_TCP)
        return DetectionResult::NORMAL;

    const bool is_http_port = (pkt.dst_port == HTTP_PORT
                            || pkt.dst_port == HTTPS_PORT
                            || pkt.dst_port == HTTP_ALT_PORT);
    if (!is_http_port)
        return DetectionResult::NORMAL;

    // ── SYN: khởi tạo HTTP tracking ──────────────────────────────────────────
    if (pkt.hasSYN() && !pkt.hasACK()) {
        flow.http_start           = Clock::now();
        flow.http_bytes_received  = 0;
        flow.http_header_complete = false;
        flow.slowloris_alerted    = false;
        flow.slow_post_alerted    = false;

        // Tăng concurrent_conn TRONG withStats callback → thread-safe
        ip_tracker_.withStats(pkt.src_ip, [](IpStats& ip) {
            ip.concurrent_conn++;
        });

        return DetectionResult::NORMAL;
    }

    // ── FIN/RST: giảm concurrent_conn ────────────────────────────────────────
    if (pkt.hasFIN() || pkt.hasRST()) {
        ip_tracker_.withStats(pkt.src_ip, [](IpStats& ip) {
            if (ip.concurrent_conn > 0)
                ip.concurrent_conn--;
        });
        return DetectionResult::NORMAL;
    }

    // ── Guard: http_start chưa được set ──────────────────────────────────────
    if (flow.http_start == TimePoint{})
        return DetectionResult::NORMAL;

    flow.http_bytes_received += pkt.payload_len;

    // ── Detect header completion (chỉ HTTP plaintext) ─────────────────────────
    if (!flow.http_header_complete
        && pkt.dst_port != HTTPS_PORT
        && pkt.payload_len > 0
        && pkt.payload() != nullptr) {
        if (memmem(pkt.payload(), pkt.payload_len, "\r\n\r\n", 4) != nullptr)
            flow.http_header_complete = true;
    }

    // ── Concurrent connection flood ───────────────────────────────────────────
    // Đọc concurrent_conn TRONG withStats, lưu ra ngoài để dùng sau
    uint32_t concurrent_conn_snap = 0;
    ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
        concurrent_conn_snap = ip.concurrent_conn;
    });

    if (concurrent_conn_snap > MAX_CONCURRENT_CONN) {
        LOG_WARN("Slow DDoS (conn flood): src=" + pkt.flowKey()
                 + " concurrent=" + std::to_string(concurrent_conn_snap));
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

    if (elapsed < HTTP_HEADER_TIMEOUT_SEC)
        return DetectionResult::NORMAL;

    if (pkt.dst_port == HTTPS_PORT) {
        if (flow.http_bytes_received == 0)
            return DetectionResult::NORMAL;

        const double bps = static_cast<double>(flow.http_bytes_received) / elapsed;
        const bool low_throughput = (bps < MIN_BYTES_PER_SEC);
        const bool has_activity   = (flow.total_packets > 5);

        // Đọc concurrent_conn TRONG withStats
        uint32_t conn_snap = 0;
        ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
            conn_snap = ip.concurrent_conn;
        });

        const bool many_conn = (conn_snap > SLOWLORIS_CONN_MIN);

        if (low_throughput && has_activity && many_conn) {
            flow.slowloris_alerted = true;
            LOG_WARN("Slow DDoS (Slowloris/TLS): "
                     + std::to_string(static_cast<int>(bps)) + " B/s"
                     + ", elapsed=" + std::to_string(static_cast<int>(elapsed)) + "s"
                     + ", concurrent=" + std::to_string(conn_snap)
                     + " from " + pkt.flowKey());
            return DetectionResult::SLOW_DDOS;
        }
    } else {
        if (!flow.http_header_complete && flow.http_bytes_received > 0) {
            flow.slowloris_alerted = true;
            LOG_WARN("Slow DDoS (Slowloris): header incomplete after "
                     + std::to_string(static_cast<int>(elapsed))
                     + "s from " + pkt.flowKey());
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

    if (pkt.dst_port == HTTPS_PORT)
        return DetectionResult::NORMAL;

    if (!flow.http_header_complete)
        return DetectionResult::NORMAL;

    const double elapsed = std::chrono::duration<double>(
        Clock::now() - flow.http_start).count();

    if (elapsed < SLOW_POST_DURATION_MIN_SEC)
        return DetectionResult::NORMAL;

    const double bps = (elapsed > 0.0)
                       ? static_cast<double>(flow.http_bytes_received) / elapsed
                       : 0.0;

    if (bps < MIN_BYTES_PER_SEC && flow.http_bytes_received > 0) {
        flow.slow_post_alerted = true;
        LOG_WARN("Slow DDoS (Slow POST): "
                 + std::to_string(static_cast<int>(bps))
                 + " B/s, elapsed=" + std::to_string(static_cast<int>(elapsed))
                 + "s from " + pkt.flowKey());
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
        if (flow.win_zero_count >= WIN_ZERO_COUNT_THRESHOLD) {
            LOG_WARN("Slow DDoS (Slow Read): win=0 x"
                     + std::to_string(flow.win_zero_count)
                     + " from " + pkt.flowKey()
                     + " packets=" + std::to_string(flow.total_packets));
            return DetectionResult::SLOW_DDOS;
        }
    } else {
        flow.win_zero_count = 0;
    }

    return DetectionResult::NORMAL;
}
