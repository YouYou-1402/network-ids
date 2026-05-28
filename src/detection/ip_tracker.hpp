//src/detection/ip_tracker.hpp
#pragma once
#include <cstdint>
#include <chrono>
#include <set>
#include <unordered_map>
#include <mutex>
#include <atomic>
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

    uint64_t  pkt_count       = 0;   // tổng packet từ IP này (mọi protocol)
    uint64_t  syn_count       = 0;
    uint64_t  syn_flood_count = 0;
    uint64_t  udp_count       = 0;
    uint64_t  icmp_count      = 0;
    // FIX #3: Tách http_req_count riêng — pkt_count và http_req_count
    // có ngữ nghĩa khác nhau, không được dùng chung một counter.
    // SignatureEngine dùng pkt_count (tổng packet) để tính flood ratio.
    // BehavioralEngine dùng http_req_count (chỉ HTTP GET/POST/HEAD).
    uint64_t  http_req_count  = 0;
    TimePoint window_start;

    std::set<uint16_t> flood_ports_seen;
    std::set<uint16_t> scan_ports_seen;

    uint32_t syn_no_ack      = 0;
    uint32_t rst_received    = 0;
    uint32_t concurrent_conn = 0;

    void resetWindow() {
        pkt_count       = 0;
        syn_count       = 0;
        syn_flood_count = 0;
        udp_count       = 0;
        icmp_count      = 0;
        http_req_count  = 0;   // FIX #3: reset cùng với window
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
//  DstStats — track per destination IP (detect distributed SYN flood)
//
//  Key insight: distributed flood có random src nhưng dst cố định
//  → đếm SYN/ACK ratio theo dst thay vì src
// ═══════════════════════════════════════════════════════════════════════════
struct DstStats {
    uint64_t  syn_count  = 0;
    uint64_t  ack_count  = 0;
    TimePoint window_start;

    void resetWindow() {
        syn_count    = 0;
        ack_count    = 0;
        window_start = Clock::now();
    }

    double windowElapsed() const {
        return std::chrono::duration<double>(
            Clock::now() - window_start).count();
    }

    // SYN/ACK ratio — cao → nhiều SYN không được ACK lại → flood
    double synAckRatio() const {
        return static_cast<double>(syn_count) /
               static_cast<double>(std::max((uint64_t)1, ack_count));
    }
};

// ═══════════════════════════════════════════════════════════════════════════
//  GlobalSynStats — đếm tổng SYN toàn hệ thống trong sliding window
//
//  Detect distributed flood mà per-IP và per-DST đều bỏ sót
//  (vd: rate thấp mỗi dst nhưng tổng hệ thống rất cao)
// ═══════════════════════════════════════════════════════════════════════════
struct GlobalSynStats {
    // FIX #13: Dùng atomic<uint64_t> thay uint64_t thường để
    // getWindowSyns() có thể đọc an toàn không cần lock.
    std::atomic<uint64_t> window_syns{0};
    std::atomic<uint64_t> total_syns {0};
    TimePoint window_start;
    std::mutex mu;

    // Trả về true nếu window_syns vượt threshold
    // Reset window tự động khi hết window_sec
    bool record(uint64_t threshold, double window_sec) {
        std::lock_guard<std::mutex> lk(mu);
        const auto now = Clock::now();

        if (window_start == TimePoint{})
            window_start = now;

        const double elapsed = std::chrono::duration<double>(
            now - window_start).count();

        if (elapsed > window_sec) {
            window_syns.store(0, std::memory_order_relaxed);
            window_start = now;
        }

        const uint64_t cur = window_syns.fetch_add(1, std::memory_order_relaxed) + 1;
        total_syns.fetch_add(1, std::memory_order_relaxed);
        return (cur >= threshold);
    }

    // FIX #13: Đọc an toàn không cần lock nhờ atomic
    uint64_t getWindowSyns() const {
        return window_syns.load(std::memory_order_relaxed);
    }

    void reset() {
        std::lock_guard<std::mutex> lk(mu);
        window_syns.store(0, std::memory_order_relaxed);
        window_start = Clock::now();
    }
};

// ═══════════════════════════════════════════════════════════════════════════
//  IpTracker
// ═══════════════════════════════════════════════════════════════════════════
class IpTracker {
public:
    static constexpr double WINDOW_SEC          = 30.0;
    static constexpr double SCAN_IDLE_RESET_SEC = 300.0;
    static constexpr size_t MAX_TRACKED_IP      = 65536;

    bool   withStats(uint32_t src_ip,
                     const std::function<void(IpStats&)>& fn);
    size_t cleanup(double idle_sec = 60.0);
    size_t size() const;

    // Singleton global SYN counter — dùng chung toàn bộ engine
    static GlobalSynStats& globalSyn() {
        static GlobalSynStats s;
        return s;
    }

private:
    mutable std::mutex                     mutex_;
    std::unordered_map<uint32_t, IpStats>  table_;
    std::unordered_map<uint32_t, TimePoint> last_seen_;
};

// ═══════════════════════════════════════════════════════════════════════════
//  DstTracker — giống IpTracker nhưng key = dst_ip
//  Mỗi SignatureEngine instance có 1 DstTracker riêng (không cần singleton)
// ═══════════════════════════════════════════════════════════════════════════
class DstTracker {
public:
    bool   withStats(uint32_t dst_ip,
                     const std::function<void(DstStats&)>& fn);
    size_t cleanup(double idle_sec = 60.0);
    size_t size() const;

private:
    mutable std::mutex                      mutex_;
    std::unordered_map<uint32_t, DstStats>  table_;
    std::unordered_map<uint32_t, TimePoint> last_seen_;
};
