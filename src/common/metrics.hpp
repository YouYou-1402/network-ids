//src/common/metrics.hpp
#pragma once
#include <atomic>
#include <cstdint>
#include <string>

// Thread-safe metrics counters dùng atomic
// Được đọc bởi UI layer qua UiBridge
struct SystemMetrics {
    // Packet counters
    std::atomic<uint64_t> packets_captured  {0};
    std::atomic<uint64_t> packets_dropped   {0};
    std::atomic<uint64_t> packets_passed    {0};
    std::atomic<uint64_t> packets_alerted   {0};

    // Threat counters
    std::atomic<uint64_t> ddos_detected     {0};
    std::atomic<uint64_t> slow_ddos_detected{0};
    std::atomic<uint64_t> port_scan_detected{0};
    std::atomic<uint64_t> malformed_detected{0};

    // Performance
    std::atomic<uint64_t> active_flows      {0};
    std::atomic<uint64_t> queue_drops       {0};  

    // Singleton
    static SystemMetrics& instance() {
        static SystemMetrics inst;
        return inst;
    }

    void printStats() const;
    void reset();

private:
    SystemMetrics() = default;
};

#define METRICS SystemMetrics::instance()
