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
    // FIX BUG 1a: chỉ set http_start khi SYN, đảm bảo không bị epoch mặc định
    if (pkt.hasSYN() && !pkt.hasACK()) {
        flow.http_start           = Clock::now();   // ← set đúng thời điểm
        flow.http_bytes_received  = 0;
        flow.http_header_complete = false;
        flow.slowloris_alerted    = false;           // reset alert flag
        flow.slow_post_alerted    = false;

        IpStats* ip = ip_tracker_.getOrCreate(pkt.src_ip);
        if (ip) ip->concurrent_conn++;

        return DetectionResult::NORMAL;
    }

    // ── FIN/RST: giảm concurrent_conn ────────────────────────────────────────
    if (pkt.hasFIN() || pkt.hasRST()) {
        IpStats* ip = ip_tracker_.get(pkt.src_ip);
        if (ip && ip->concurrent_conn > 0)
            ip->concurrent_conn--;
        return DetectionResult::NORMAL;
    }

    // ── Guard: http_start chưa được set (packet đến trước SYN bị miss) ───────
    // FIX BUG 1b: tránh elapsed = hàng nghìn giây do TimePoint{} mặc định
    if (flow.http_start == TimePoint{})
        return DetectionResult::NORMAL;

    // ── Cập nhật bytes ────────────────────────────────────────────────────────
    flow.http_bytes_received += pkt.payload_len;

    // ── Detect header completion (chỉ HTTP plaintext) ─────────────────────────
    if (!flow.http_header_complete
        && pkt.dst_port != HTTPS_PORT          // không inspect TLS
        && pkt.payload_len > 0
        && pkt.payload() != nullptr) {
        if (memmem(pkt.payload(), pkt.payload_len, "\r\n\r\n", 4) != nullptr)
            flow.http_header_complete = true;
    }

    // ── Concurrent connection flood (áp dụng cả HTTP + HTTPS) ────────────────
    {
        IpStats* ip = ip_tracker_.get(pkt.src_ip);
        if (ip && ip->concurrent_conn > MAX_CONCURRENT_CONN) {
            LOG_WARN("Slow DDoS (conn flood): src=" + pkt.flowKey()
                     + " concurrent=" + std::to_string(ip->concurrent_conn));
            return DetectionResult::SLOW_DDOS;
        }
    }

    // ── 3 kiểu Slow DDoS ─────────────────────────────────────────────────────
    auto r = checkSlowloris(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    r = checkSlowPost(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    return checkSlowRead(pkt, flow);
}

// ─── checkSlowloris ───────────────────────────────────────────────────────────
//
//  HTTP  (port 80/8080): header không hoàn chỉnh sau HTTP_HEADER_TIMEOUT_SEC
//  HTTPS (port 443)    : không thể inspect TLS payload
//                        → detect qua TCP behavior:
//                          connection sống lâu + throughput cực thấp
//                          + nhiều concurrent connection từ cùng IP
//
//  FIX BUG 1c: thêm flag slowloris_alerted để chỉ alert 1 lần / flow
//              tránh spam log mỗi packet sau khi đã alert
// ─────────────────────────────────────────────────────────────────────────────
DetectionResult ProtocolAnomalyEngine::checkSlowloris(const PacketInfo& pkt,
                                                        FlowState&        flow) {
    // Đã alert rồi → không lặp lại
    if (flow.slowloris_alerted)
        return DetectionResult::NORMAL;

    const double elapsed = std::chrono::duration<double>(
        Clock::now() - flow.http_start).count();

    if (elapsed < HTTP_HEADER_TIMEOUT_SEC)
        return DetectionResult::NORMAL;

    if (pkt.dst_port == HTTPS_PORT) {
        // ── HTTPS: TCP behavior detection ────────────────────────────────────
        //
        //  Không thể check "\r\n\r\n" (TLS encrypted)
        //  Dùng 3 điều kiện kết hợp để giảm false positive:
        //    1. Throughput cực thấp (bytes/s < MIN_BYTES_PER_SEC)
        //    2. Đã có activity thực sự (total_packets > 5)
        //    3. Nhiều concurrent conn từ IP này (đặc trưng Slowloris)

        if (flow.http_bytes_received == 0)
            return DetectionResult::NORMAL;

        const double bps = static_cast<double>(flow.http_bytes_received) / elapsed;

        const bool low_throughput  = (bps < MIN_BYTES_PER_SEC);
        const bool has_activity    = (flow.total_packets > 5);

        // Concurrent conn: Slowloris cần nhiều connection đồng thời
        IpStats* ip = ip_tracker_.get(pkt.src_ip);
        const bool many_conn = ip && (ip->concurrent_conn > SLOWLORIS_CONN_MIN);

        if (low_throughput && has_activity && many_conn) {
            flow.slowloris_alerted = true;
            LOG_WARN("Slow DDoS (Slowloris/TLS): "
                     + std::to_string(static_cast<int>(bps)) + " B/s"
                     + ", elapsed=" + std::to_string(static_cast<int>(elapsed)) + "s"
                     + ", concurrent=" + std::to_string(ip->concurrent_conn)
                     + " from " + pkt.flowKey());
            return DetectionResult::SLOW_DDOS;
        }

    } else {
        // ── HTTP plaintext: payload inspection ───────────────────────────────
        //
        //  Header chưa hoàn chỉnh sau timeout → Slowloris
        //  Cần có ít nhất 1 byte data (loại trừ connection idle)

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
//  Header đã xong nhưng body/s < MIN_BYTES_PER_SEC sau timeout
//  FIX: thêm flag slow_post_alerted để chỉ alert 1 lần / flow
DetectionResult ProtocolAnomalyEngine::checkSlowPost(const PacketInfo& pkt,
                                                       FlowState&        flow) {
    if (flow.slow_post_alerted)
        return DetectionResult::NORMAL;

    // HTTPS: không thể biết header đã xong chưa → bỏ qua Slow POST cho TLS
    // (Slow POST qua TLS sẽ được ML layer xử lý)
    if (pkt.dst_port == HTTPS_PORT)
        return DetectionResult::NORMAL;

    if (!flow.http_header_complete)
        return DetectionResult::NORMAL;

    const double elapsed = std::chrono::duration<double>(
        Clock::now() - flow.http_start).count();

    if (elapsed < HTTP_HEADER_TIMEOUT_SEC)
        return DetectionResult::NORMAL;

    const double bps = (elapsed > 0.0)
                       ? static_cast<double>(flow.http_bytes_received) / elapsed
                       : 0.0;

    if (bps < MIN_BYTES_PER_SEC && flow.http_bytes_received > 0) {
        flow.slow_post_alerted = true;
        LOG_WARN("Slow DDoS (Slow POST): "
                 + std::to_string(static_cast<int>(bps))
                 + " B/s from " + pkt.flowKey());
        return DetectionResult::SLOW_DDOS;
    }
    return DetectionResult::NORMAL;
}

// ─── checkSlowRead ────────────────────────────────────────────────────────────
//  TCP window = 0 sau khi đã có data exchange (client không đọc response)
//  Không phụ thuộc payload → áp dụng được cả HTTPS
DetectionResult ProtocolAnomalyEngine::checkSlowRead(const PacketInfo& pkt,
                                                       FlowState&        flow) {
    if (pkt.win_size == 0 && flow.total_packets > 5 && pkt.hasACK()) {
        LOG_WARN("Slow DDoS (Slow Read): win=0 from " + pkt.flowKey()
                 + " packets=" + std::to_string(flow.total_packets));
        return DetectionResult::SLOW_DDOS;
    }
    return DetectionResult::NORMAL;
}