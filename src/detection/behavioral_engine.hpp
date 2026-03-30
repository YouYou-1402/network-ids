// src/detection/behavioral_engine.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "../common/config_loader.hpp"
#include "flow_state.hpp"
#include "ip_tracker.hpp"
#include <unordered_map>
#include <mutex>
#include <chrono>

class BehavioralEngine {
public:
    explicit BehavioralEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt, FlowState& flow);

private:
    DetectionResult checkHttpFlood       (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkSynNoHandshake  (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkDistributedScan (const PacketInfo& pkt);

    IpTracker& ip_tracker_;

    struct HttpRateEntry {
        uint64_t  request_count = 0;
        TimePoint window_start;
    };
    std::unordered_map<uint32_t, HttpRateEntry> http_rate_map_;

    struct DstScanEntry {
        std::unordered_map<uint32_t, uint32_t> src_count;
        TimePoint window_start;
    };
    static std::unordered_map<uint32_t, DstScanEntry> dst_scan_map_;
    static std::mutex                                  dst_scan_mutex_;

    // ── Đọc từ config lúc khởi tạo, KHÔNG còn constexpr ─────────────────
    uint64_t http_flood_threshold_    = 200;
    uint32_t dist_scan_src_threshold_ = 10;
    uint32_t syn_no_complete_thresh_  = 50;
    double   behavior_window_sec_     = 10.0;

    // HTTP ports: không check 443 (TLS không parse được)
    static constexpr uint16_t HTTP_PORT     = 80;
    static constexpr uint16_t HTTP_ALT_PORT = 8080;
    // ↑ Giữ lại 2 cái này vì là protocol constant, không phải tunable threshold
};
