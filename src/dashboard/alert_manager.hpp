// alert_manager.hpp
#pragma once
#include <deque>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include "../common/threat_types.hpp"
#include "../layer2/ml_engine.hpp"

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

    std::string srcIpString() const;
    std::string colorCode()   const;
};

// ─── AlertManager ─────────────────────────────────────────────────────────────
class AlertManager {
public:
    // Cooldown mặc định: cùng flow không alert quá 1 lần / 5 giây
    static constexpr int    SUPPRESS_SEC  = 5;
    static constexpr size_t MAX_LOG_QUEUE = 512;

    explicit AlertManager(size_t max_alerts = 1000);

    // ✅ Gọi từ worker thread — phải cực nhanh, không I/O
    void addL1Alert(const DetectionEvent& event);
    void addL2Alert(const MLResult& result);

    // ✅ Gọi từ Qt main thread — lock ngắn
    std::vector<UnifiedAlert> getRecent(size_t n) const;

    // ✅ Atomic reads — không cần lock
    uint64_t ddosAlerts()     const { return ddos_alerts_.load();      }
    uint64_t slowDdosAlerts() const { return slow_ddos_alerts_.load(); }
    uint64_t scanAlerts()     const { return scan_alerts_.load();      }
    uint64_t totalAlerts()    const { return total_alerts_.load();     }

private:
    // dedup_key tự build bên trong — caller không cần truyền
    void addAlert(UnifiedAlert alert);
    bool shouldSuppress(const std::string& key);  // gọi khi đang giữ mutex_

    // ── Storage ───────────────────────────────────────────────────────────────
    mutable std::mutex       mutex_;
    std::deque<UnifiedAlert> alerts_;
    size_t                   max_alerts_;

    // ── Dedup map: flow_key → last alert time ─────────────────────────────────
    std::unordered_map<std::string, double> suppress_map_;

    // ── Counters (atomic — đọc từ UI thread không cần lock) ───────────────────
    std::atomic<uint64_t> total_alerts_     {0};
    std::atomic<uint64_t> ddos_alerts_      {0};
    std::atomic<uint64_t> slow_ddos_alerts_ {0};
    std::atomic<uint64_t> scan_alerts_      {0};

    std::vector<UnifiedAlert> getLatest(size_t n) const;
};
