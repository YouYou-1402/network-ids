// src/detection/flow_state.hpp
#pragma once
#include <cstdint>
#include <string>
#include <chrono>
#include <set>

using Clock     = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

// Trạng thái của một luồng TCP/UDP
// Được lưu trong FlowTable, cập nhật bởi WorkerThread
struct FlowState {
    // --- Identity ---
    std::string flow_key;       // "srcIP:srcPort-dstIP:dstPort-proto"
    uint32_t    src_ip   = 0;
    uint32_t    dst_ip   = 0;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    uint8_t     protocol = 0;
    uint32_t win_zero_count = 0;
    // --- Flow Direction ---
    // true  = packet đầu tiên là SYN (không ACK) → attacker khởi tạo
    // false = packet đầu tiên là response (RST/SYN-ACK/ACK) → server response
    // Được set 1 lần duy nhất trong FlowTable::createFlow()
    // SignatureEngine chỉ analyze flow có is_initiator = true
    bool        is_initiator = false;

    // --- Timing ---
    TimePoint   first_seen;
    TimePoint   last_seen;

    // --- Volume ---
    uint64_t    total_packets    = 0;
    uint64_t    total_bytes      = 0;
    uint64_t    fwd_packets      = 0;   // Client → Server
    uint64_t    bwd_packets      = 0;   // Server → Client

    // --- TCP Flags (cumulative) ---
    uint32_t    syn_count  = 0;
    uint32_t    ack_count  = 0;
    uint32_t    rst_count  = 0;
    uint32_t    fin_count  = 0;

    // --- DDoS Detection ---
    // Dùng sliding window 10 giây
    uint64_t    pkt_rate_window  = 0;   // Packets trong 10s gần nhất
    TimePoint   window_start;

    // --- Slow DDoS Detection ---
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

    // --- Port Scan Detection ---
    // dst_ports_seen: chỉ chứa dst_port của SYN probe (is_initiator = true)
    // Không còn bị nhiễm bởi RST response nhờ filter ở SignatureEngine::analyze()
    std::set<uint16_t> dst_ports_seen;
    uint32_t           syn_no_ack      = 0; // SYN gửi đi không có ACK phản hồi

    // --- State ---
    bool        is_malicious = false;
    std::string threat_type;            // "DDOS" / "SLOW_DDOS" / "PORT_SCAN"

    // --- Helper methods ---

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