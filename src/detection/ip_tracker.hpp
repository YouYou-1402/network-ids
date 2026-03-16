// src/detection/ip_tracker.hpp
#pragma once
#include <cstdint>
#include <chrono>
#include <set>
#include <unordered_map>
#include <mutex>
#include <string>

using Clock     = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

// ─── IpStats ──────────────────────────────────────────────────────────────────
//
//  Theo dõi hành vi theo từng src_ip (không phải per-flow)
//  Dùng cho:
//    - Port Scan:  dst_ports_seen tích lũy qua nhiều flow khác nhau
//    - DDoS:       pkt_count trong sliding window
//    - Slow DDoS:  concurrent_conn từ 1 IP
//
//  Thread safety: IpTracker giữ mutex riêng — không dùng FlowTable mutex
// ─────────────────────────────────────────────────────────────────────────────
struct IpStats {
    uint32_t  src_ip = 0;

    // ── Sliding window (reset mỗi WINDOW_SEC) ────────────────────────────────
    uint64_t  pkt_count      = 0;   // tổng packet trong window
    uint64_t  syn_count      = 0;   // SYN không có ACK
    uint64_t  udp_count      = 0;
    uint64_t  icmp_count     = 0;
    TimePoint window_start;

    // ── Port scan tracking ────────────────────────────────────────────────────
    // Tích lũy qua tất cả flow từ src_ip này
    // Reset khi window hết hạn
    std::set<uint16_t> dst_ports_seen;
    uint32_t           syn_no_ack    = 0;  // SYN gửi không nhận ACK
    uint32_t           rst_received  = 0;  // RST nhận về (port closed)

    // ── Slow DDoS tracking ────────────────────────────────────────────────────
    uint32_t  concurrent_conn = 0;   // số flow TCP đang mở từ IP này

    // ── Helpers ───────────────────────────────────────────────────────────────
    void resetWindow() {
        pkt_count     = 0;
        syn_count     = 0;
        udp_count     = 0;
        icmp_count    = 0;
        syn_no_ack    = 0;
        rst_received  = 0;
        dst_ports_seen.clear();
        window_start  = Clock::now();
    }

    double windowElapsed() const {
        return std::chrono::duration<double>(
            Clock::now() - window_start).count();
    }
};

// ─── IpTracker ────────────────────────────────────────────────────────────────
//
//  Singleton-style, được inject vào SignatureEngine và BehavioralEngine
//  Cleanup định kỳ để tránh memory leak
// ─────────────────────────────────────────────────────────────────────────────
class IpTracker {
public:
    static constexpr double WINDOW_SEC     = 10.0;
    static constexpr size_t MAX_TRACKED_IP = 65536;

    // Lấy hoặc tạo IpStats cho src_ip
    // Trả về nullptr nếu bảng đầy
    IpStats* getOrCreate(uint32_t src_ip);

    // Lấy IpStats đã tồn tại (nullptr nếu không có)
    IpStats* get(uint32_t src_ip);

    // Cleanup IP không hoạt động quá idle_sec
    size_t cleanup(double idle_sec = 60.0);

    size_t size() const;

private:
    mutable std::mutex                          mutex_;
    std::unordered_map<uint32_t, IpStats>       table_;

    // last_seen per IP để cleanup
    std::unordered_map<uint32_t, TimePoint>     last_seen_;
};
