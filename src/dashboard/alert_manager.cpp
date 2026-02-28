#include "alert_manager.hpp"
#include "../common/logger.hpp"
#include <arpa/inet.h>
#include <chrono>

// ─── UnifiedAlert helpers ─────────────────────────────────────────────────────
std::string UnifiedAlert::srcIpString() const {
    struct in_addr addr;
    addr.s_addr = src_ip;
    return inet_ntoa(addr);
}

std::string UnifiedAlert::colorCode() const {
    switch (result) {
        case DetectionResult::DDOS_VOLUMETRIC: return "\033[31m"; // Đỏ
        case DetectionResult::SLOW_DDOS:       return "\033[33m"; // Vàng
        case DetectionResult::PORT_SCAN:       return "\033[38;5;208m"; // Cam
        default:                               return "\033[32m"; // Xanh
    }
}

// ─── AlertManager ─────────────────────────────────────────────────────────────
AlertManager::AlertManager(size_t max_alerts)
    : max_alerts_(max_alerts) {}

void AlertManager::addL1Alert(const DetectionEvent& event) {
    UnifiedAlert alert;
    alert.source     = UnifiedAlert::Source::LAYER1;
    alert.result     = event.result;
    alert.action     = event.action;
    alert.src_ip     = event.src_ip;
    alert.dst_ip     = event.dst_ip;
    alert.src_port   = event.src_port;
    alert.dst_port   = event.dst_port;
    alert.confidence = 1.0f; // L1 rule-based → deterministic
    alert.detail     = "[L1] " + event.detail;
    alert.timestamp  = event.timestamp;
    addAlert(std::move(alert));
}

void AlertManager::addL2Alert(const MLResult& result) {
    UnifiedAlert alert;
    alert.source     = UnifiedAlert::Source::LAYER2;
    alert.result     = result.final_result;
    alert.action     = PacketAction::ALERT; // L2 chỉ alert, không DROP
    alert.src_ip     = result.src_ip;
    alert.dst_ip     = result.dst_ip;
    alert.src_port   = result.src_port;
    alert.dst_port   = result.dst_port;
    alert.confidence = result.confidence;
    alert.detail     = result.detail;
    alert.timestamp  = result.timestamp;
    addAlert(std::move(alert));
}

void AlertManager::addAlert(UnifiedAlert alert) {
    // Cập nhật counters
    total_alerts_++;
    switch (alert.result) {
        case DetectionResult::DDOS_VOLUMETRIC: ddos_alerts_++;     break;
        case DetectionResult::SLOW_DDOS:       slow_ddos_alerts_++; break;
        case DetectionResult::PORT_SCAN:       scan_alerts_++;     break;
        default: break;
    }

    // Log với màu
    LOG_INFO(alert.colorCode()
             + "[ALERT] "
             + threatToString(alert.result)
             + " | " + alert.srcIpString()
             + ":" + std::to_string(alert.src_port)
             + " | " + alert.detail
             + "\033[0m");

    // Lưu vào deque
    std::lock_guard<std::mutex> lock(mutex_);
    alerts_.push_back(std::move(alert));

    // Giữ tối đa max_alerts_
    while (alerts_.size() > max_alerts_)
        alerts_.pop_front();
}

std::vector<UnifiedAlert> AlertManager::getRecent(size_t n) const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = std::min(n, alerts_.size());
    return std::vector<UnifiedAlert>(
        alerts_.end() - count,
        alerts_.end()
    );
}
