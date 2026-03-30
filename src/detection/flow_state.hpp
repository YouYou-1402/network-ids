//src/detection/flow_state.hpp
#pragma once
#include <cstdint>
#include <string>
#include <chrono>
#include <set>

using Clock     = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

// =============================================================================
//  FlowState
//  Trạng thái của một luồng TCP/UDP
//  Được lưu trong FlowTable, cập nhật bởi WorkerThread
// =============================================================================
struct FlowState {

    // ── Identity ──────────────────────────────────────────────────────────────
    std::string flow_key;       // "srcIP:srcPort-dstIP:dstPort-proto"
    uint32_t    src_ip   = 0;
    uint32_t    dst_ip   = 0;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    uint8_t     protocol = 0;
    uint32_t    win_zero_count = 0;

    // ── Flow Direction ────────────────────────────────────────────────────────
    // true  = packet đầu tiên là SYN (không ACK) → attacker khởi tạo
    // false = packet đầu tiên là response (RST/SYN-ACK/ACK) → server response
    // Được set 1 lần duy nhất trong FlowTable::createFlow()
    // SignatureEngine chỉ analyze flow có is_initiator = true
    bool        is_initiator = false;

    // ── Timing ────────────────────────────────────────────────────────────────
    TimePoint   first_seen;
    TimePoint   last_seen;

    // ── Volume ────────────────────────────────────────────────────────────────
    uint64_t    total_packets = 0;
    uint64_t    total_bytes   = 0;
    uint64_t    fwd_packets   = 0;   // Client → Server
    uint64_t    bwd_packets   = 0;   // Server → Client

    // ── ML: Per-direction bytes ───────────────────────────────────────────────
    // Cập nhật trong WorkerThread::processPacket() block 2b
    // Dựa trên is_initiator (set 1 lần trong FlowTable::createFlow):
    //   is_initiator = true  → packet thuộc hướng fwd (client→server)
    //   is_initiator = false → packet thuộc hướng bwd (server→client)
    //
    // Khác với fwd_packets/bwd_packets (đếm số packet):
    //   fwd_bytes/bwd_bytes đếm payload bytes → dùng cho feature extraction
    uint64_t    fwd_bytes = 0;
    uint64_t    bwd_bytes = 0;

    // ── TCP Flags (cumulative) ────────────────────────────────────────────────
    uint32_t    syn_count = 0;
    uint32_t    ack_count = 0;
    uint32_t    rst_count = 0;
    uint32_t    fin_count = 0;

    // ── DDoS Detection — sliding window 10 giây ──────────────────────────────
    uint64_t    pkt_rate_window = 0;   // Packets trong 10s gần nhất
    TimePoint   window_start;

    // ── Slow DDoS Detection ───────────────────────────────────────────────────
    // FIX BUG 1a: http_start chỉ được set khi nhận SYN packet
    //             Mặc định = TimePoint{} (epoch) → guard bằng http_start == TimePoint{}
    bool        http_header_complete = false;
    TimePoint   http_start;             // Khi nhận SYN đầu tiên (không phải epoch)
    uint64_t    http_bytes_received  = 0;
    uint32_t    concurrent_conn      = 0;

    // Alert suppression: mỗi flow chỉ sinh 1 alert / loại
    // FIX BUG 1c: tránh spam log mỗi packet sau khi đã alert
    bool        slowloris_alerted = false;
    bool        slow_post_alerted = false;

    // ── Port Scan Detection ───────────────────────────────────────────────────
    // dst_ports_seen: chỉ chứa dst_port của SYN probe (is_initiator = true)
    // Không còn bị nhiễm bởi RST response nhờ filter ở SignatureEngine::analyze()
    std::set<uint16_t> dst_ports_seen;
    uint32_t           syn_no_ack = 0;   // SYN gửi đi không có ACK phản hồi

    // ── ML: Inter-Arrival Time — Welford's online algorithm ──────────────────
    // Cập nhật trong WorkerThread::processPacket() block 2b mỗi packet
    //
    // Welford's one-pass (numerically stable):
    //   Với packet thứ n:
    //     iat_ms        = (pkt.timestamp_d - prev_pkt_timestamp_d) * 1000
    //     delta         = iat_ms - iat_mean_ms
    //     iat_mean_ms  += delta / n
    //     delta2        = iat_ms - iat_mean_ms        ← sau khi update mean
    //     iat_m2       += delta * delta2
    //
    //   Khi cần std:
    //     std = sqrt(iat_m2 / (total_packets - 1))    ← sample std
    //
    // Lý do dùng Welford's thay vì lưu vector<double>:
    //   - O(1) memory, O(1) update per packet
    //   - Numerically stable hơn naive: sum_sq - n*mean^2
    //     (tránh catastrophic cancellation khi mean >> std)
    double      iat_mean_ms = 0.0;   // running mean IAT (ms)
    double      iat_m2      = 0.0;   // sum of squared deviations (cho variance)

    // Timestamp của packet trước — dùng DUY NHẤT để tính IAT trong Welford's
    // Được update cuối block 2b sau khi tính IAT
    // Không dùng cho mục đích nào khác
    double      prev_pkt_timestamp_d = 0.0;

    // ── State ─────────────────────────────────────────────────────────────────
    bool        is_malicious = false;
    std::string threat_type;            // "DDOS" / "SLOW_DDOS" / "PORT_SCAN"

    // ── Helper methods ────────────────────────────────────────────────────────

    // Thời gian tồn tại kết nối (seconds)
    double durationSeconds() const {
        return std::chrono::duration<double>(last_seen - first_seen).count();
    }

    // Bytes per second
    double bytesPerSecond() const {
        double dur = durationSeconds();
        return (dur > 0) ? total_bytes / dur : 0.0;
    }

    // Packets per second trong window
    double packetRate() const {
        double elapsed = std::chrono::duration<double>(
            Clock::now() - window_start).count();
        return (elapsed > 0) ? pkt_rate_window / elapsed : 0.0;
    }

    // Reset sliding window
    void resetWindow() {
        pkt_rate_window = 0;
        window_start    = Clock::now();
    }
};
