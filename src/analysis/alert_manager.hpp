// src/analysis/alert_manager.hpp
#pragma once
#include <deque>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>
#include <unordered_map>
#include "../core/threat_types.hpp"
#include "../ml/ml_engine.hpp"

// ─── UnifiedAlert ─────────────────────────────────────────────────────────────
struct UnifiedAlert {
    enum class Source { LAYER1, LAYER2 };

    Source          source     = Source::LAYER1;
    DetectionResult result     = DetectionResult::NORMAL;
    PacketAction    action     = PacketAction::PASS;
    uint32_t        src_ip     = 0;
    uint32_t        dst_ip     = 0;
    uint16_t        src_port   = 0;
    uint16_t        dst_port   = 0;
    float           confidence = 0.0f;
    double          timestamp  = 0.0;
    std::string     detail;

    // seq: tăng dần, dùng cho getRecentFrom()
    // Gán bởi AlertManager::addAlert() — không set từ ngoài
    uint64_t        seq        = 0;

    std::string srcIpString() const;
    std::string colorCode()   const;
};

// ─── AlertManager ─────────────────────────────────────────────────────────────
//
//  Thread safety:
//    - addL1Alert / addL2Alert: gọi từ nhiều WorkerThread → cần lock
//    - getRecent / getRecentFrom: gọi từ UI thread → cần lock
//    - counter atomics: đọc từ UI không cần lock
//
//  Fix race condition cũ:
//    - seq_ tăng TRONG lock cùng lúc push vào deque
//    - getRecentFrom() dùng alert.seq thay vì tính offset từ total_alerts_
// ─────────────────────────────────────────────────────────────────────────────
class AlertManager {
public:
    static constexpr int    SUPPRESS_SEC  = 5;
    static constexpr size_t MAX_ALERTS    = 1000;

    explicit AlertManager(size_t max_alerts = MAX_ALERTS);

    void addL1Alert(const DetectionEvent& event);
    void addL2Alert(const MLResult&       result);

    // Lấy N alert gần nhất
    std::vector<UnifiedAlert> getRecent    (size_t n) const;

    // Lấy alert có seq > from_seq, tối đa max_n
    std::vector<UnifiedAlert> getRecentFrom(uint64_t from_seq,
                                            size_t   max_n) const;

    uint64_t totalAlerts()    const { return total_alerts_    .load(std::memory_order_relaxed); }
    uint64_t ddosAlerts()     const { return ddos_alerts_     .load(std::memory_order_relaxed); }
    uint64_t slowDdosAlerts() const { return slow_ddos_alerts_.load(std::memory_order_relaxed); }
    uint64_t scanAlerts()     const { return scan_alerts_     .load(std::memory_order_relaxed); }

private:
    void addAlert   (UnifiedAlert alert);
    bool shouldSuppress(const std::string& key);   // gọi khi đang giữ mutex_

    mutable std::mutex       mutex_;
    std::deque<UnifiedAlert> alerts_;
    size_t                   max_alerts_;

    // seq_ tăng dần, gán cho mỗi alert — tăng TRONG lock
    uint64_t                 seq_ = 0;

    // Dedup: flow_key → last alert time (steady_clock seconds)
    std::unordered_map<std::string, double> suppress_map_;

    // Counters — tăng NGOÀI lock (chỉ đọc từ UI)
    std::atomic<uint64_t> total_alerts_     {0};
    std::atomic<uint64_t> ddos_alerts_      {0};
    std::atomic<uint64_t> slow_ddos_alerts_ {0};
    std::atomic<uint64_t> scan_alerts_      {0};
};
