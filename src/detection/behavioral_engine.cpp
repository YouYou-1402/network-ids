// src/detection/behavioral_engine.cpp
#include "behavioral_engine.hpp"
#include "../common/logger.hpp"
#include "../common/config_loader.hpp"
#include <netinet/in.h>
#include <cstring>

// ─── Static members ───────────────────────────────────────────────────────────
std::unordered_map<uint32_t, BehavioralEngine::DstScanEntry>
    BehavioralEngine::dst_scan_map_;
std::mutex BehavioralEngine::dst_scan_mutex_;

// ─── Constructor ──────────────────────────────────────────────────────────────
BehavioralEngine::BehavioralEngine(IpTracker& ip_tracker)
    : ip_tracker_(ip_tracker)
{
    // ── Đọc threshold từ config thay vì constexpr ─────────────────────────
    const auto& th = APP_CFG.thresholds;
    http_flood_threshold_    = th.http_flood_req_per_window;
    dist_scan_src_threshold_ = th.dist_scan_src_threshold;
    syn_no_complete_thresh_  = th.syn_no_complete;
    behavior_window_sec_     = th.behavior_window_sec;

    LOG_INFO("BehavioralEngine: initialized"
             " http_flood="  + std::to_string(http_flood_threshold_)
           + " dist_scan="   + std::to_string(dist_scan_src_threshold_)
           + " syn_thresh="  + std::to_string(syn_no_complete_thresh_)
           + " window="      + std::to_string(behavior_window_sec_) + "s");
}

// ─── analyze ──────────────────────────────────────────────────────────────────
DetectionResult BehavioralEngine::analyze(const PacketInfo& pkt,
                                           FlowState&        flow) {
    // 1. HTTP Flood — chỉ check plaintext HTTP (không check 443)
    const bool is_http = (pkt.dst_port == HTTP_PORT
                       || pkt.dst_port == HTTP_ALT_PORT);
    if (is_http && pkt.protocol == IPPROTO_TCP) {
        auto r = checkHttpFlood(pkt, flow);
        if (r != DetectionResult::NORMAL) return r;
    }

    // 2. SYN không hoàn thành handshake
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
DetectionResult BehavioralEngine::checkHttpFlood(const PacketInfo& pkt,
                                                  FlowState&        flow) {
    if (pkt.payload_len == 0 || pkt.payload() == nullptr)
        return DetectionResult::NORMAL;

    const uint8_t* p   = pkt.payload();
    const size_t   len = pkt.payload_len;

    const bool is_get  = (len >= 3 && memcmp(p, "GET",  3) == 0);
    const bool is_post = (len >= 4 && memcmp(p, "POST", 4) == 0);
    if (!is_get && !is_post) return DetectionResult::NORMAL;

    if (memmem(p, len, "\r\n\r\n", 4) == nullptr)
        return DetectionResult::NORMAL;

    auto& entry    = http_rate_map_[pkt.src_ip];
    const auto now = Clock::now();

    const double elapsed = std::chrono::duration<double>(
        now - entry.window_start).count();

    if (elapsed > behavior_window_sec_) {
        entry.request_count = 0;
        entry.window_start  = now;
    }
    entry.request_count++;

    if (entry.request_count > http_flood_threshold_) {
        LOG_WARN("HTTP Flood: src=" + pkt.flowKey()
                 + " req="    + std::to_string(entry.request_count)
                 + "/"        + std::to_string(static_cast<int>(behavior_window_sec_))
                 + "s thresh=" + std::to_string(http_flood_threshold_));
        return DetectionResult::DDOS_VOLUMETRIC;
    }
    return DetectionResult::NORMAL;
}

// ─── checkSynNoHandshake ──────────────────────────────────────────────────────
DetectionResult BehavioralEngine::checkSynNoHandshake(const PacketInfo& pkt,
                                                        FlowState&        flow) {
    if (pkt.hasSYN() && !pkt.hasACK())
        flow.syn_no_ack++;

    if (pkt.hasACK() && !pkt.hasSYN())
        flow.syn_no_ack = 0;

    if (flow.syn_no_ack > syn_no_complete_thresh_) {
        LOG_WARN("SYN flood (no handshake): src=" + pkt.flowKey()
                 + " syn_no_ack=" + std::to_string(flow.syn_no_ack)
                 + " thresh="     + std::to_string(syn_no_complete_thresh_));
        return DetectionResult::DDOS_VOLUMETRIC;
    }
    return DetectionResult::NORMAL;
}

// ─── checkDistributedScan ─────────────────────────────────────────────────────
DetectionResult BehavioralEngine::checkDistributedScan(const PacketInfo& pkt) {
    if (pkt.protocol == IPPROTO_TCP && !(pkt.hasSYN() && !pkt.hasACK()))
        return DetectionResult::NORMAL;

    std::lock_guard<std::mutex> lock(dst_scan_mutex_);

    auto& entry    = dst_scan_map_[pkt.dst_ip];
    const auto now = Clock::now();

    const double elapsed = std::chrono::duration<double>(
        now - entry.window_start).count();

    if (elapsed > behavior_window_sec_ || entry.window_start == TimePoint{}) {
        entry.src_count.clear();
        entry.window_start = now;
    }

    entry.src_count[pkt.src_ip]++;

    if (entry.src_count.size() > dist_scan_src_threshold_) {
        LOG_WARN("Distributed Port Scan: dst=" + std::to_string(pkt.dst_ip)
                 + " unique_src=" + std::to_string(entry.src_count.size())
                 + " thresh="     + std::to_string(dist_scan_src_threshold_));
        return DetectionResult::PORT_SCAN;
    }
    return DetectionResult::NORMAL;
}
