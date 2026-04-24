#include "metrics.hpp"
#include <iostream>

void SystemMetrics::printStats() const {
    std::cout << "\n=== System Metrics ===\n"
              << "Packets captured : " << packets_captured  .load() << "\n"
              << "Packets dropped  : " << packets_dropped   .load() << "\n"
              << "Packets passed   : " << packets_passed    .load() << "\n"
              << "Packets alerted  : " << packets_alerted   .load() << "\n"
              << "--- Threats ---\n"
              << "DDoS detected    : " << ddos_detected     .load() << "\n"
              << "Slow DDoS        : " << slow_ddos_detected.load() << "\n"
              << "Port Scan        : " << port_scan_detected.load() << "\n"
              << "Malformed        : " << malformed_detected.load() << "\n"
              << "--- System ---\n"
              << "Active flows     : " << active_flows      .load() << "\n"
              << "Queue drops      : " << queue_drops       .load() << "\n"
              << "======================\n";
}

void SystemMetrics::reset() noexcept {
    packets_captured  .store(0, std::memory_order_relaxed);
    packets_dropped   .store(0, std::memory_order_relaxed);
    packets_passed    .store(0, std::memory_order_relaxed);
    packets_alerted   .store(0, std::memory_order_relaxed);
    ddos_detected     .store(0, std::memory_order_relaxed);
    slow_ddos_detected.store(0, std::memory_order_relaxed);
    port_scan_detected.store(0, std::memory_order_relaxed);
    malformed_detected.store(0, std::memory_order_relaxed);
    active_flows      .store(0, std::memory_order_relaxed);
    queue_drops       .store(0, std::memory_order_relaxed);
}
