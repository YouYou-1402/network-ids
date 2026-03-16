// src/detection/behavioral_engine.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "flow_state.hpp"
#include "ip_tracker.hpp"
#include <unordered_map>
#include <deque>
#include <mutex>
#include <chrono>

// ─── BehavioralEngine ─────────────────────────────────────────────────────────
//
//  Detect các pattern cần quan sát NHIỀU PACKET theo thời gian:
//
//  1. HTTP Flood (Layer 7 DDoS):
//       Header hợp lệ, request hoàn chỉnh, nhưng rate quá cao
//       → GET/POST flood, bypass Slowloris detection
//
//  2. Distributed Port Scan:
//       Nhiều src_ip khác nhau cùng scan 1 dst_ip
//       → Coordinated scan, bypass per-IP threshold
//
//  3. SYN → no handshake completion (SYN flood variant):
//       SYN gửi đi nhưng không bao giờ hoàn thành 3-way handshake
//       → Bổ sung cho SignatureEngine (rate-based)
//
//  Thread safety:
//    - Mỗi WorkerThread có BehavioralEngine riêng (không share)
//    - dst_scan_map_ cần mutex vì nhiều worker có thể ghi cùng dst_ip
//    - http_rate_map_ per-worker → không cần lock
// ─────────────────────────────────────────────────────────────────────────────
class BehavioralEngine {
public:
    explicit BehavioralEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt,
                            FlowState&        flow);

private:
    DetectionResult checkHttpFlood       (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkSynNoHandshake  (const PacketInfo& pkt, FlowState& flow);
    DetectionResult checkDistributedScan (const PacketInfo& pkt);

    IpTracker& ip_tracker_;

    // ── HTTP Flood tracking (per src_ip, per-worker) ──────────────────────────
    struct HttpRateEntry {
        uint64_t  request_count = 0;
        TimePoint window_start;
    };
    std::unordered_map<uint32_t, HttpRateEntry> http_rate_map_;

    // ── Distributed scan: dst_ip → set of src_ip ─────────────────────────────
    // Shared across workers → cần mutex
    struct DstScanEntry {
        std::unordered_map<uint32_t, uint32_t> src_count; // src_ip → probe count
        TimePoint window_start;
    };
    static std::unordered_map<uint32_t, DstScanEntry> dst_scan_map_;
    static std::mutex                                  dst_scan_mutex_;

    // ── Thresholds ────────────────────────────────────────────────────────────
    static constexpr uint64_t HTTP_FLOOD_THRESHOLD   = 200;  // req/10s per IP
    static constexpr uint32_t DIST_SCAN_SRC_THRESHOLD = 10;  // unique src IPs
    static constexpr uint32_t SYN_NO_COMPLETE_THRESH  = 50;  // SYN không complete
    static constexpr double   BEHAVIOR_WINDOW_SEC     = 10.0;
    static constexpr uint16_t HTTP_PORT               = 80;
    static constexpr uint16_t HTTPS_PORT              = 443;
    static constexpr uint16_t HTTP_ALT_PORT           = 8080;
};
