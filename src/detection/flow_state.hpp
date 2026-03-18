#pragma once
#include <cstdint>
#include <string>
#include <chrono>
#include <set>

using Clock     = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

struct FlowState {
    // --- Identity ---
    std::string flow_key;
    uint32_t    src_ip   = 0;
    uint32_t    dst_ip   = 0;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    uint8_t     protocol = 0;

    // --- Timing ---
    TimePoint   first_seen;
    TimePoint   last_seen;

    // --- Volume ---
    uint64_t    total_packets    = 0;
    uint64_t    total_bytes      = 0;
    uint64_t    fwd_packets      = 0;
    uint64_t    bwd_packets      = 0;

    // --- TCP Flags (cumulative) ---
    uint32_t    syn_count  = 0;
    uint32_t    ack_count  = 0;
    uint32_t    rst_count  = 0;
    uint32_t    fin_count  = 0;

    // --- DDoS Detection ---
    uint64_t    pkt_rate_window  = 0;
    TimePoint   window_start;

    // --- Slow DDoS Detection ---
    bool        http_header_complete = false;
    TimePoint   http_start;
    uint64_t    http_bytes_received  = 0;
    uint32_t    concurrent_conn      = 0;

    // FIX BUG 1: Alert suppression flags
    // Mỗi flow chỉ sinh 1 alert cho mỗi loại → tránh spam log
    bool        slowloris_alerted    = false;
    bool        slow_post_alerted    = false;

    // --- Port Scan Detection ---
    std::set<uint16_t> dst_ports_seen;
    uint32_t           rst_received    = 0;
    uint32_t           syn_no_ack      = 0;

    // --- State ---
    bool        is_malicious = false;
    std::string threat_type;

    // --- Helper methods ---
    double durationSeconds() const {
        return std::chrono::duration<double>(last_seen - first_seen).count();
    }

    double bytesPerSecond() const {
        double dur = durationSeconds();
        return (dur > 0) ? total_bytes / dur : 0.0;
    }

    double packetRate() const {
        double elapsed = std::chrono::duration<double>(
            Clock::now() - window_start).count();
        return (elapsed > 0) ? pkt_rate_window / elapsed : 0.0;
    }

    void resetWindow() {
        pkt_rate_window = 0;
        window_start    = Clock::now();
    }
};