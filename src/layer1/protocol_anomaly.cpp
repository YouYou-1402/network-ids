#include "protocol_anomaly.hpp"
#include "../common/logger.hpp"
#include <cstring>
#include <netinet/in.h>

DetectionResult ProtocolAnomalyEngine::analyze(const PacketInfo& pkt,
                                                FlowState&        flow) {
    // Chỉ phân tích TCP traffic đến HTTP port
    if (pkt.protocol != IPPROTO_TCP)
        return DetectionResult::NORMAL;

    if (pkt.dst_port == HTTP_PORT || pkt.dst_port == HTTPS_PORT)
        return checkSlowDDoS(pkt, flow);

    return DetectionResult::NORMAL;
}

DetectionResult ProtocolAnomalyEngine::checkSlowDDoS(const PacketInfo& pkt,
                                                       FlowState&        flow) {
    auto now = Clock::now();

    // Khởi tạo HTTP tracking khi nhận SYN
    if (pkt.hasSYN() && !pkt.hasACK()) {
        flow.http_start          = now;
        flow.http_bytes_received = 0;
        flow.http_header_complete = false;
        return DetectionResult::NORMAL;
    }

    // Cập nhật bytes nhận được
    flow.http_bytes_received += pkt.payload_len;

    // Kiểm tra HTTP header hoàn chỉnh
    if (!flow.http_header_complete && pkt.payload_len > 0) {
        // Tìm "\r\n\r\n" — dấu hiệu kết thúc HTTP header
        const char* header_end = "\r\n\r\n";
        if (pkt.payload() != nullptr) {
            const uint8_t* found = static_cast<const uint8_t*>(
                memmem(pkt.payload(), pkt.payload_len,
                       header_end, 4));
            if (found)
                flow.http_header_complete = true;
        }
    }

    // Rule 1: HTTP header chưa hoàn chỉnh sau timeout
    if (!flow.http_header_complete) {
        double elapsed = std::chrono::duration<double>(
            now - flow.http_start).count();

        if (elapsed > HTTP_HEADER_TIMEOUT_SEC) {
            LOG_WARN("Slow DDoS (Slowloris): HTTP header incomplete after "
                     + std::to_string(elapsed) + "s from "
                     + pkt.flowKey());
            return DetectionResult::SLOW_DDOS;
        }
    }

    // Rule 2: Bytes per second quá thấp sau 30s
    double duration = std::chrono::duration<double>(
        now - flow.http_start).count();

    if (duration > HTTP_HEADER_TIMEOUT_SEC) {
        double bps = flow.http_bytes_received / duration;
        if (bps < MIN_BYTES_PER_SEC) {
            LOG_WARN("Slow DDoS (Slow POST): "
                     + std::to_string(bps) + " bytes/s from "
                     + pkt.flowKey());
            return DetectionResult::SLOW_DDOS;
        }
    }

    // Rule 3: TCP window size = 0 (Slow Read)
    if (pkt.win_size == 0 && flow.total_packets > 5) {
        LOG_WARN("Slow DDoS (Slow Read): TCP window=0 from "
                 + pkt.flowKey());
        return DetectionResult::SLOW_DDOS;
    }

    return DetectionResult::NORMAL;
}
