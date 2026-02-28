#include "metrics.hpp"
#include <iostream>

void SystemMetrics::printStats() const {
    std::cout << "\n=== System Metrics ===\n"
              << "Packets captured : " << packets_captured  << "\n"
              << "Packets dropped  : " << packets_dropped   << "\n"
              << "Packets passed   : " << packets_passed    << "\n"
              << "Packets alerted  : " << packets_alerted   << "\n"
              << "--- Threats ---\n"
              << "DDoS detected    : " << ddos_detected      << "\n"
              << "Slow DDoS        : " << slow_ddos_detected << "\n"
              << "Port Scan        : " << port_scan_detected << "\n"
              << "Malformed        : " << malformed_detected << "\n"
              << "--- System ---\n"
              << "Active flows     : " << active_flows       << "\n"
              << "Queue drops      : " << queue_drops        << "\n"
              << "======================\n";
}

void SystemMetrics::reset() {
    packets_captured  = 0;
    packets_dropped   = 0;
    packets_passed    = 0;
    packets_alerted   = 0;
    ddos_detected     = 0;
    slow_ddos_detected= 0;
    port_scan_detected= 0;
    malformed_detected= 0;
    active_flows      = 0;
    queue_drops       = 0;
}
