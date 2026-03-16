// src/detection/behavioral_engine.cpp
#include "behavioral_engine.hpp"
#include "../common/logger.hpp"
#include <netinet/in.h>
#include <cstring>

// Static members
std::unordered_map<uint32_t, BehavioralEngine::DstScanEntry>
    BehavioralEngine::dst_scan_map_;
std::mutex BehavioralEngine::dst_scan_mutex_;

BehavioralEngine::BehavioralEngine(IpTracker& ip_tracker)
    : ip_tracker_(ip_tracker)
{
    LOG_INFO("BehavioralEngine initialized");
}

// ─── analyze ──────────────────────────────────────────────────────────────────
DetectionResult BehavioralEngine::analyze(const PacketInfo& pkt,
                                           FlowState&        flow) {
    // 1. HTTP Flood (chỉ check HTTP port)
    const bool is_http = (pkt.dst_port == HTTP_PORT
                       || pkt.dst_port == HTTPS_PORT
                       || pkt.dst_port == HTTP_ALT_PORT);
    if (is_http && pkt.protocol == IPPROTO_TCP) {
        auto r = checkHttpFlood(pkt, flow);
        if (r != DetectionResult::NORMAL) return r;
    }

    // 2. SYN không hoàn thành handshake (bổ sung cho signature rate check)
    if (pkt.protocol == IPPROTO_TCP) {
        auto r = checkSynNoHandshake(pkt, flow);
        if (r != DetectionResult::NORMAL) return r;
    }

    // 3. Distributed port scan
    if (pkt.protocol == IPPROTO_TCP || pkt.protocol == IPPROTO_UDP) {
        auto r = checkDistributedScan(pkt);
        if (r != DetectionResult::NORMAL) return r;
    }

    return DetectionResult::NORMAL;
}

// ─── checkHttpFlood ───────────────────────────────────────────────────────────
//  Đếm HTTP request hoàn chỉnh (có "\r\n\r\n") từ src_ip
//  Khác Slowloris: request hoàn chỉnh nhưng số lượng quá lớn
DetectionResult BehavioralEngine::checkHttpFlood(const PacketInfo& pkt,
                                                  FlowState&        flow) {
    if (pkt.payload_len == 0 || pkt.payload() == nullptr)
        return DetectionResult::NORMAL;

    // Chỉ count khi thấy GET/POST (HTTP request hoàn chỉnh)
    const uint8_t* p   = pkt.payload();
    const size_t   len = pkt.payload_len;

    const bool is_get  = (len >= 3 && memcmp(p, "GET",  3) == 0);
    const bool is_post = (len >= 4 && memcmp(p, "POST", 4) == 0);
    if (!is_get && !is_post) return DetectionResult::NORMAL;

    // Phải có header kết thúc "\r\n\r\n"
    if (memmem(p, len, "\r\n\r\n", 4) == nullptr)
        return DetectionResult::NORMAL;

    // Cập nhật rate per src_ip
    auto& entry = http_rate_map_[pkt.src_ip];
    const auto now = Clock::now();

    const double elapsed = std::chrono::duration<double>(
        now - entry.window_start).count();

    if (elapsed > BEHAVIOR_WINDOW_SEC) {
        entry.request_count = 0;
        entry.window_start  = now;
    }
    entry.request_count++;

    if (entry.request_count > HTTP_FLOOD_THRESHOLD) {
        LOG_WARN("HTTP Flood: src=" + pkt.flowKey()
                 + " req=" + std::to_string(entry.request_count)
                 + "/" + std::to_string(static_cast<int>(BEHAVIOR_WINDOW_SEC))
                 + "s");
        return DetectionResult::DDOS_VOLUMETRIC;
    }
    return DetectionResult::NORMAL;
}

// ─── checkSynNoHandshake ──────────────────────────────────────────────────────
//  SYN gửi đi nhưng flow không bao giờ thấy SYN-ACK hoặc ACK
//  → Bổ sung cho SYN flood rate check ở SignatureEngine
DetectionResult BehavioralEngine::checkSynNoHandshake(const PacketInfo& pkt,
                                                        FlowState&        flow) {
    // Ghi nhận SYN không có ACK
    if (pkt.hasSYN() && !pkt.hasACK()) {
        flow.syn_no_ack++;
    }

    // Nếu thấy ACK → handshake đang tiến hành, reset counter
    if (pkt.hasACK() && !pkt.hasSYN()) {
        flow.syn_no_ack = 0;
    }

    if (flow.syn_no_ack > SYN_NO_COMPLETE_THRESH) {
        LOG_WARN("SYN flood (no handshake): src=" + pkt.flowKey()
                 + " syn_no_ack=" + std::to_string(flow.syn_no_ack));
        return DetectionResult::DDOS_VOLUMETRIC;
    }
    return DetectionResult::NORMAL;
}

// ─── checkDistributedScan ─────────────────────────────────────────────────────
//  Nhiều src_ip khác nhau probe cùng 1 dst_ip → coordinated scan
DetectionResult BehavioralEngine::checkDistributedScan(const PacketInfo& pkt) {
    // Chỉ quan tâm SYN probe (không có ACK)
    if (pkt.protocol == IPPROTO_TCP && !(pkt.hasSYN() && !pkt.hasACK()))
        return DetectionResult::NORMAL;

    std::lock_guard<std::mutex> lock(dst_scan_mutex_);

    auto& entry     = dst_scan_map_[pkt.dst_ip];
    const auto now  = Clock::now();

    const double elapsed = std::chrono::duration<double>(
        now - entry.window_start).count();

    if (elapsed > BEHAVIOR_WINDOW_SEC || entry.window_start == TimePoint{}) {
        entry.src_count.clear();
        entry.window_start = now;
    }

    entry.src_count[pkt.src_ip]++;

    if (entry.src_count.size() > DIST_SCAN_SRC_THRESHOLD) {
        LOG_WARN("Distributed Port Scan: dst=" + std::to_string(pkt.dst_ip)
                 + " unique_src=" + std::to_string(entry.src_count.size()));
        return DetectionResult::PORT_SCAN;
    }
    return DetectionResult::NORMAL;
}
