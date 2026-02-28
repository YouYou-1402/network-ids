#pragma once
#include "../common/threat_types.hpp"
#include "../layer2/ml_engine.hpp"
#include <deque>
#include <mutex>
#include <vector>
#include <cstdint>

// Alert thống nhất từ cả L1 và L2
struct UnifiedAlert {
    enum class Source { LAYER1, LAYER2 };

    Source          source;
    DetectionResult result;
    PacketAction    action;
    uint32_t        src_ip;
    uint32_t        dst_ip;
    uint16_t        src_port;
    uint16_t        dst_port;
    float           confidence;  // 1.0 cho L1, variable cho L2
    std::string     detail;
    double          timestamp;

    // Helper: IP string
    std::string srcIpString() const;
    std::string colorCode()   const; // ANSI color
};

class AlertManager {
public:
    explicit AlertManager(size_t max_alerts = 1000);

    // Nhận alert từ Layer 1
    void addL1Alert(const DetectionEvent& event);

    // Nhận alert từ Layer 2
    void addL2Alert(const MLResult& result);

    // Lấy N alerts gần nhất (thread-safe snapshot)
    std::vector<UnifiedAlert> getRecent(size_t n = 100) const;

    // Thống kê
    uint64_t totalAlerts()   const { return total_alerts_;   }
    uint64_t ddosAlerts()    const { return ddos_alerts_;    }
    uint64_t slowDdosAlerts()const { return slow_ddos_alerts_;}
    uint64_t scanAlerts()    const { return scan_alerts_;    }

private:
    void addAlert(UnifiedAlert alert);

    std::deque<UnifiedAlert>  alerts_;
    mutable std::mutex        mutex_;
    size_t                    max_alerts_;

    std::atomic<uint64_t>     total_alerts_     {0};
    std::atomic<uint64_t>     ddos_alerts_      {0};
    std::atomic<uint64_t>     slow_ddos_alerts_ {0};
    std::atomic<uint64_t>     scan_alerts_      {0};
};
