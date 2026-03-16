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

    // Khởi tạo HTTP tracking khi nhận SYN
    if (pkt.hasSYN() && !pkt.hasACK()) {
        flow.http_start           = Clock::now();
        flow.http_bytes_received  = 0;
        flow.http_header_complete = false;

        // Tăng concurrent_conn per IP
        IpStats* ip = ip_tracker_.getOrCreate(pkt.src_ip);
        if (ip) ip->concurrent_conn++;

        return DetectionResult::NORMAL;
    }

    // Giảm concurrent_conn khi FIN/RST
    if (pkt.hasFIN() || pkt.hasRST()) {
        IpStats* ip = ip_tracker_.get(pkt.src_ip);
        if (ip && ip->concurrent_conn > 0)
            ip->concurrent_conn--;
        return DetectionResult::NORMAL;
    }

    // Cập nhật bytes
    flow.http_bytes_received += pkt.payload_len;

    // Detect header completion ("\r\n\r\n")
    if (!flow.http_header_complete && pkt.payload_len > 0
        && pkt.payload() != nullptr) {
        if (memmem(pkt.payload(), pkt.payload_len, "\r\n\r\n", 4) != nullptr)
            flow.http_header_complete = true;
    }

    // Check concurrent connection flood per IP
    {
        IpStats* ip = ip_tracker_.get(pkt.src_ip);
        if (ip && ip->concurrent_conn > MAX_CONCURRENT_CONN) {
            LOG_WARN("Slow DDoS (conn flood): src=" + pkt.flowKey()
                     + " concurrent=" + std::to_string(ip->concurrent_conn));
            return DetectionResult::SLOW_DDOS;
        }
    }

    // 3 kiểu Slow DDoS
    auto r = checkSlowloris(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    r = checkSlowPost(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    r = checkSlowRead(pkt, flow);
    return r;
}

// ─── checkSlowloris ───────────────────────────────────────────────────────────
//  HTTP header không hoàn chỉnh sau HTTP_HEADER_TIMEOUT_SEC
DetectionResult ProtocolAnomalyEngine::checkSlowloris(const PacketInfo& pkt,
                                                        FlowState&        flow) {
    if (flow.http_header_complete) return DetectionResult::NORMAL;

    const double elapsed = std::chrono::duration<double>(
        Clock::now() - flow.http_start).count();

    if (elapsed > HTTP_HEADER_TIMEOUT_SEC) {
        LOG_WARN("Slow DDoS (Slowloris): header incomplete after "
                 + std::to_string(static_cast<int>(elapsed))
                 + "s from " + pkt.flowKey());
        return DetectionResult::SLOW_DDOS;
    }
    return DetectionResult::NORMAL;
}

// ─── checkSlowPost ────────────────────────────────────────────────────────────
//  Header đã xong nhưng body/s < MIN_BYTES_PER_SEC sau timeout
DetectionResult ProtocolAnomalyEngine::checkSlowPost(const PacketInfo& pkt,
                                                       FlowState&        flow) {
    if (!flow.http_header_complete) return DetectionResult::NORMAL;

    const double elapsed = std::chrono::duration<double>(
        Clock::now() - flow.http_start).count();

    if (elapsed < HTTP_HEADER_TIMEOUT_SEC) return DetectionResult::NORMAL;

    const double bps = (elapsed > 0.0)
                       ? static_cast<double>(flow.http_bytes_received) / elapsed
                       : 0.0;

    if (bps < MIN_BYTES_PER_SEC && flow.http_bytes_received > 0) {
        LOG_WARN("Slow DDoS (Slow POST): "
                 + std::to_string(static_cast<int>(bps))
                 + " B/s from " + pkt.flowKey());
        return DetectionResult::SLOW_DDOS;
    }
    return DetectionResult::NORMAL;
}

// ─── checkSlowRead ────────────────────────────────────────────────────────────
//  Client advertise TCP window = 0 sau khi đã nhận data (Slow Read)
DetectionResult ProtocolAnomalyEngine::checkSlowRead(const PacketInfo& pkt,
                                                       FlowState&        flow) {
    // Chỉ check sau khi đã có ít nhất vài packet trao đổi
    if (pkt.win_size == 0 && flow.total_packets > 5 && pkt.hasACK()) {
        LOG_WARN("Slow DDoS (Slow Read): win=0 from " + pkt.flowKey()
                 + " packets=" + std::to_string(flow.total_packets));
        return DetectionResult::SLOW_DDOS;
    }
    return DetectionResult::NORMAL;
}
