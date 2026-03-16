// src/analysis/alert_manager.cpp
#include "alert_manager.hpp"
#include "../common/logger.hpp"
#include <arpa/inet.h>
#include <sstream>
#include <chrono>

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
        default:                               return "\033[32m";        // Xanh lá
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

// ─── addAlert ─────────────────────────────────────────────────────────────────
// FIX: lưu local copy trước khi move alert vào deque
//      → tránh dùng alerts_.back() sau khi release lock
void AlertManager::addAlert(UnifiedAlert alert) {
    // ── Lưu local trước khi move ──────────────────────────────────────────────
    const DetectionResult result_copy = alert.result;
    const std::string     log_str     = alert.colorCode()
                                      + "[ALERT] " + threatToString(alert.result)
                                      + " | "      + alert.srcIpString()
                                      + ":"        + std::to_string(alert.src_port)
                                      + " | "      + alert.detail
                                      + "\033[0m";

    // ── Build dedup key ───────────────────────────────────────────────────────
    std::ostringstream oss;
    oss << alert.src_ip  << ":" << alert.src_port << "->"
        << alert.dst_ip  << ":" << alert.dst_port << "|"
        << static_cast<int>(alert.result);
    const std::string dedup_key = oss.str();

    // ── Log NGOÀI lock → không block worker thread ────────────────────────────
    LOG_INFO(log_str);

    // ── Critical section: ngắn nhất có thể ───────────────────────────────────
    bool did_push = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (shouldSuppress(dedup_key)) return;

        // Ghi suppress timestamp
        const double now_sec = std::chrono::duration<double>(
            Clock::now().time_since_epoch()).count();
        suppress_map_[dedup_key] = now_sec;

        // Gán seq tăng dần TRONG lock (đảm bảo thứ tự)
        alert.seq = ++seq_;

        // Evict oldest nếu đầy
        if (alerts_.size() >= max_alerts_)
            alerts_.pop_front();

        alerts_.push_back(std::move(alert));
        did_push = true;
    }
    // ── Hết lock ──────────────────────────────────────────────────────────────

    // ── Tăng counter NGOÀI lock, dùng local copy ─────────────────────────────
    if (!did_push) return;

    total_alerts_.fetch_add(1, std::memory_order_relaxed);

    switch (result_copy) {
        case DetectionResult::DDOS_VOLUMETRIC:
            ddos_alerts_.fetch_add(1, std::memory_order_relaxed);
            break;
        case DetectionResult::SLOW_DDOS:
            slow_ddos_alerts_.fetch_add(1, std::memory_order_relaxed);
            break;
        case DetectionResult::PORT_SCAN:
            scan_alerts_.fetch_add(1, std::memory_order_relaxed);
            break;
        default:
            break;
    }
}

// ─── shouldSuppress ───────────────────────────────────────────────────────────
// PHẢI gọi khi đang giữ mutex_
bool AlertManager::shouldSuppress(const std::string& key) {
    auto it = suppress_map_.find(key);
    if (it == suppress_map_.end()) return false;

    const double now_sec = std::chrono::duration<double>(
        Clock::now().time_since_epoch()).count();

    return (now_sec - it->second) < static_cast<double>(SUPPRESS_SEC);
}

// ─── getRecent ────────────────────────────────────────────────────────────────
std::vector<UnifiedAlert> AlertManager::getRecent(size_t n) const {
    std::lock_guard<std::mutex> lock(mutex_);

    const size_t count = std::min(n, alerts_.size());
    return std::vector<UnifiedAlert>(
        alerts_.end() - static_cast<std::ptrdiff_t>(count),
        alerts_.end());
}

// ─── getRecentFrom ────────────────────────────────────────────────────────────
// Trả về alerts có seq > from_seq, tối đa max_n
// Dùng alert.seq thay vì tính offset từ total_alerts_ → không còn race
std::vector<UnifiedAlert> AlertManager::getRecentFrom(uint64_t from_seq,
                                                       size_t   max_n) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<UnifiedAlert> result;
    result.reserve(std::min(max_n, alerts_.size()));

    for (const auto& alert : alerts_) {
        if (alert.seq > from_seq) {
            result.push_back(alert);
            if (result.size() >= max_n) break;
        }
    }
    return result;
}
