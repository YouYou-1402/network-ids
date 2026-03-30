// src/detection/protocol_anomaly.cpp
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
    // ── Đọc threshold từ config thay vì constexpr ─────────────────────────
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

// ─── analyze ──────────────────────────────────────────────────────────────────
DetectionResult ProtocolAnomalyEngine::analyze(const PacketInfo& pkt,
                                                FlowState&        flow) {
    if (pkt.protocol != IPPROTO_TCP)
        return DetectionResult::NORMAL;

    // Dùng isHttpPort() thay vì so sánh hardcode
    // HTTPS (443) vẫn được check nhưng chỉ qua heuristic (không parse header)
    const bool is_http_port = isHttpPort(pkt.dst_port)
                           || (pkt.dst_port == 443);
    if (!is_http_port)
        return DetectionResult::NORMAL;

    // ── SYN: khởi tạo HTTP tracking ──────────────────────────────────────────
    if (pkt.hasSYN() && !pkt.hasACK()) {
        flow.http_start           = Clock::now();
        flow.http_bytes_received  = 0;
        flow.http_header_complete = false;
        flow.slowloris_alerted    = false;
        flow.slow_post_alerted    = false;

        ip_tracker_.withStats(pkt.src_ip, [](IpStats& ip) {
            ip.concurrent_conn++;
        });
        return DetectionResult::NORMAL;
    }

    // ── FIN/RST: giảm concurrent_conn ────────────────────────────────────────
    if (pkt.hasFIN() || pkt.hasRST()) {
        ip_tracker_.withStats(pkt.src_ip, [](IpStats& ip) {
            if (ip.concurrent_conn > 0) ip.concurrent_conn--;
        });
        return DetectionResult::NORMAL;
    }

    if (flow.http_start == TimePoint{})
        return DetectionResult::NORMAL;

    flow.http_bytes_received += pkt.payload_len;

    // ── Detect header completion (chỉ HTTP plaintext) ─────────────────────────
    if (!flow.http_header_complete
        && isHttpPort(pkt.dst_port)          // không check HTTPS
        && pkt.payload_len > 0
        && pkt.payload() != nullptr) {
        if (memmem(pkt.payload(), pkt.payload_len, "\r\n\r\n", 4) != nullptr)
            flow.http_header_complete = true;
    }

    // ── Concurrent connection flood ───────────────────────────────────────────
    uint32_t concurrent_conn_snap = 0;
    ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
        concurrent_conn_snap = ip.concurrent_conn;
    });

    if (concurrent_conn_snap > max_concurrent_conn_) {
        LOG_WARN("Slow DDoS (conn flood): src=" + pkt.flowKey()
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

    if (elapsed < http_header_timeout_sec_)
        return DetectionResult::NORMAL;

    if (pkt.dst_port == 443) {
        // HTTPS: heuristic dựa trên throughput + concurrent conn
        if (flow.http_bytes_received == 0)
            return DetectionResult::NORMAL;

        const double bps = static_cast<double>(flow.http_bytes_received) / elapsed;
        const bool low_throughput = (bps < min_bytes_per_sec_);
        const bool has_activity   = (flow.total_packets > 5);

        uint32_t conn_snap = 0;
        ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
            conn_snap = ip.concurrent_conn;
        });
        const bool many_conn = (conn_snap > slowloris_conn_min_);

        if (low_throughput && has_activity && many_conn) {
            flow.slowloris_alerted = true;
            LOG_WARN("Slow DDoS (Slowloris/TLS): "
                     + std::to_string(static_cast<int>(bps)) + " B/s"
                     + " elapsed=" + std::to_string(static_cast<int>(elapsed)) + "s"
                     + " conn="    + std::to_string(conn_snap)
                     + " min_bps=" + std::to_string(min_bytes_per_sec_)
                     + " from "    + pkt.flowKey());
            return DetectionResult::SLOW_DDOS;
        }
    } else {
        // HTTP plaintext: header chưa hoàn chỉnh sau timeout
        if (!flow.http_header_complete && flow.http_bytes_received > 0) {
            flow.slowloris_alerted = true;
            LOG_WARN("Slow DDoS (Slowloris): header incomplete after "
                     + std::to_string(static_cast<int>(elapsed)) + "s"
                     + " timeout=" + std::to_string(http_header_timeout_sec_)
                     + " from "    + pkt.flowKey());
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

    // Chỉ check HTTP plaintext
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
        LOG_WARN("Slow DDoS (Slow POST): "
                 + std::to_string(static_cast<int>(bps)) + " B/s"
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
            LOG_WARN("Slow DDoS (Slow Read): win=0 x"
                     + std::to_string(flow.win_zero_count)
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
