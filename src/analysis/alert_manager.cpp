//src/analysis/alert_manager.cpp

#include "alert_manager.hpp"
#include "../common/logger.hpp"
#include <arpa/inet.h>
#include <sstream>

// ─── UnifiedAlert helpers ─────────────────────────────────────────────────────
std::string UnifiedAlert::srcIpString() const {
    struct in_addr addr{};
    addr.s_addr = src_ip;
    return inet_ntoa(addr);
}

std::string UnifiedAlert::colorCode() const {
    switch (result) {
        case DetectionResult::DDOS_VOLUMETRIC: return "\033[31m";        // Đỏ
        case DetectionResult::SLOW_DDOS:       return "\033[33m";        // Vàng
        case DetectionResult::PORT_SCAN:       return "\033[38;5;208m";  // Cam
        default:                               return "\033[32m";        // Xanh
    }
}

// ─── Constructor ──────────────────────────────────────────────────────────────
AlertManager::AlertManager(size_t max_alerts)
    : max_alerts_(max_alerts)
{}

// ─── addL1Alert ───────────────────────────────────────────────────────────────
void AlertManager::addL1Alert(const DetectionEvent& event) {
    UnifiedAlert alert;
    alert.source     = UnifiedAlert::Source::LAYER1;
    alert.result     = event.result;
    alert.action     = event.action;
    alert.src_ip     = event.src_ip;
    alert.dst_ip     = event.dst_ip;
    alert.src_port   = event.src_port;
    alert.dst_port   = event.dst_port;
    alert.confidence = 1.0f;   
    alert.detail     = "[L1] " + event.detail;
    alert.timestamp  = event.timestamp;
    addAlert(std::move(alert));
}

// ─── addL2Alert ───────────────────────────────────────────────────────────────
void AlertManager::addL2Alert(const MLResult& result) {
    UnifiedAlert alert;
    alert.source     = UnifiedAlert::Source::LAYER2;
    alert.result     = result.final_result;
    alert.action     = PacketAction::ALERT;   
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
    std::ostringstream oss;
    oss << alert.src_ip   << ":" << alert.src_port << "->"
        << alert.dst_ip   << ":" << alert.dst_port << "|"
        << static_cast<int>(alert.result);
    const std::string dedup_key = oss.str();

    LOG_INFO(alert.colorCode()
             + "[ALERT] " + threatToString(alert.result)
             + " | " + alert.srcIpString()
             + ":" + std::to_string(alert.src_port)
             + " | " + alert.detail + "\033[0m");

    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Suppress check TRƯỚC khi tăng counter
        if (shouldSuppress(dedup_key))
            return;

        // Lấy thời gian thực để suppress
        double now_sec = std::chrono::duration<double>(
            Clock::now().time_since_epoch()).count();
        suppress_map_[dedup_key] = now_sec;

        if (alerts_.size() >= max_alerts_)
            alerts_.pop_front();

        alerts_.push_back(alert); // copy trước khi move
    }

    // Tăng counter SAU KHI đã push thành công
    total_alerts_++;
    switch (alert.result) {
        case DetectionResult::DDOS_VOLUMETRIC: ddos_alerts_++;      break;
        case DetectionResult::SLOW_DDOS:       slow_ddos_alerts_++; break;
        case DetectionResult::PORT_SCAN:       scan_alerts_++;      break;
        default: break;
    }
}

bool AlertManager::shouldSuppress(const std::string& key) {
    // Gọi khi đang giữ mutex_
    auto it = suppress_map_.find(key);
    if (it == suppress_map_.end()) return false;

    // Dùng Clock::now() thay vì alerts_.back().timestamp
    double now_sec = std::chrono::duration<double>(
        Clock::now().time_since_epoch()).count();

    return (now_sec - it->second) < static_cast<double>(SUPPRESS_SEC);
}


// ─── getRecent ────────────────────────────────────────────────────────────────
std::vector<UnifiedAlert> AlertManager::getRecent(size_t n) const {
    std::lock_guard lock(mutex_);
    size_t count = std::min(n, alerts_.size());
    return std::vector<UnifiedAlert>(
        alerts_.end() - count,   // ← luôn lấy từ cuối deque
        alerts_.end()
    );
}

std::vector<UnifiedAlert> AlertManager::getLatest(size_t n) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const size_t count = std::min(n, alerts_.size());
    return std::vector<UnifiedAlert>(
        alerts_.end() - static_cast<ptrdiff_t>(count),
        alerts_.end());
}

std::vector<UnifiedAlert> AlertManager::getRecentFrom(uint64_t from_seq,
                                                        size_t   max_n) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // total_alerts_ là số alert đã push thành công vào deque
    // alerts_[0] tương ứng với seq = (total_alerts_ - alerts_.size())
    const uint64_t base_seq = total_alerts_.load() - alerts_.size();

    if (from_seq <= base_seq) {
        // Lấy từ đầu deque
        size_t count = std::min(max_n, alerts_.size());
        return std::vector<UnifiedAlert>(
            alerts_.begin(),
            alerts_.begin() + static_cast<std::ptrdiff_t>(count));
    }

    const size_t offset = static_cast<size_t>(from_seq - base_seq);
    if (offset >= alerts_.size()) return {};

    size_t count = std::min(max_n, alerts_.size() - offset);
    return std::vector<UnifiedAlert>(
        alerts_.begin() + static_cast<std::ptrdiff_t>(offset),
        alerts_.begin() + static_cast<std::ptrdiff_t>(offset + count));
}