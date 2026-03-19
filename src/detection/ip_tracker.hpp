// src/detection/ip_tracker.hpp
#pragma once
#include <cstdint>
#include <chrono>
#include <set>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <functional>

using Clock     = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

// ═══════════════════════════════════════════════════════════════════════════
//  TokenBucket
// ═══════════════════════════════════════════════════════════════════════════
struct TokenBucket {
    static constexpr double CAPACITY    = 100.0;
    static constexpr double REFILL_RATE = 10.0;

    double    tokens      = CAPACITY;
    TimePoint last_refill;
    bool      initialized = false;

    bool consume(double amount = 1.0) {
        const auto now = Clock::now();
        if (!initialized) { last_refill = now; initialized = true; }
        const double elapsed = std::chrono::duration<double>(
            now - last_refill).count();
        tokens      = std::min(CAPACITY, tokens + elapsed * REFILL_RATE);
        last_refill = now;
        tokens     -= amount;
        return (tokens <= 0.0);
    }
    void reset() { tokens = CAPACITY; initialized = false; }
};

// ═══════════════════════════════════════════════════════════════════════════
//  IpStats
// ═══════════════════════════════════════════════════════════════════════════
struct IpStats {
    uint32_t src_ip = 0;

    TokenBucket syn_bucket;
    TokenBucket udp_bucket;
    TokenBucket icmp_bucket;

    // ── Window counters (reset mỗi WINDOW_SEC) ────────────────────────────
    uint64_t  pkt_count       = 0;
    uint64_t  syn_count       = 0;
    uint64_t  syn_flood_count = 0;
    uint64_t  udp_count       = 0;
    uint64_t  icmp_count      = 0;
    TimePoint window_start;

    // ── flood_ports_seen: reset mỗi window ────────────────────────────────
    std::set<uint16_t> flood_ports_seen;

    // ── scan_ports_seen: persistent, reset sau detect/idle ────────────────
    std::set<uint16_t> scan_ports_seen;

    uint32_t syn_no_ack   = 0;
    uint32_t rst_received = 0;
    uint32_t concurrent_conn = 0;

    void resetWindow() {
        pkt_count       = 0;
        syn_count       = 0;
        syn_flood_count = 0;
        udp_count       = 0;
        icmp_count      = 0;
        flood_ports_seen.clear();
        window_start    = Clock::now();
    }

    void resetScanTracking() {
        scan_ports_seen.clear();
        syn_no_ack   = 0;
        rst_received = 0;
    }

    double windowElapsed() const {
        return std::chrono::duration<double>(
            Clock::now() - window_start).count();
    }
};

// ═══════════════════════════════════════════════════════════════════════════
//  IpTracker
//
//  THREAD SAFETY:
//    - Mọi truy cập vào IpStats đều qua withStats(ip, callback)
//    - Callback chạy TRONG lock → không có race condition
//    - KHÔNG trả về raw pointer ra ngoài lock
// ═══════════════════════════════════════════════════════════════════════════
class IpTracker {
public:
    static constexpr double WINDOW_SEC          = 30.0;
    static constexpr double SCAN_IDLE_RESET_SEC = 300.0;
    static constexpr size_t MAX_TRACKED_IP      = 65536;

    // Thực thi callback(IpStats&) trong lock, tạo entry nếu chưa có
    // Trả về false nếu bảng đầy và IP chưa tồn tại
    bool withStats(uint32_t src_ip,
                   const std::function<void(IpStats&)>& fn);

    size_t cleanup(double idle_sec = 60.0);
    size_t size()  const;

private:
    mutable std::mutex                      mutex_;
    std::unordered_map<uint32_t, IpStats>   table_;
    std::unordered_map<uint32_t, TimePoint> last_seen_;
};
