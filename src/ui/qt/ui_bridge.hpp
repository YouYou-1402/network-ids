// src/ui/qt/ui_bridge.hpp
#pragma once
#include <QObject>
#include <QTimer>
#include <QDateTime>
#include <deque>
#include <vector>

#include "../../analysis/alert_manager.hpp"
#include "../../common/metrics.hpp"
#include "../../detection/dispatcher.hpp"
#include "../../ml/ml_engine.hpp"
#include "../../capture/io/packet_ring_buffer.hpp"
#include "../../common/engine_config.hpp"

// ─── Snapshot structs ─────────────────────────────────────────────────────────
struct MetricsSnapshot {
    uint64_t packets_captured = 0;
    uint64_t packets_dropped  = 0;
    uint64_t packets_passed   = 0;
    uint64_t packets_alerted  = 0;
    uint64_t ddos_count       = 0;
    uint64_t slow_ddos_count  = 0;
    uint64_t port_scan_count  = 0;
    uint64_t active_flows     = 0;
    uint64_t ml_jobs          = 0;
    uint64_t ml_anomalies     = 0;
};

struct TrafficPoint {
    double   timestamp = 0.0;
    uint64_t total_pps = 0;
    uint64_t drop_pps  = 0;
    uint64_t alert_pps = 0;
};

// ─── UiBridge ─────────────────────────────────────────────────────────────────
//
//  Thread model:
//    - Tất cả slots chạy trên Qt main thread (QTimer → main thread)
//    - ring_buf_ được access qua pollNew() — thread-safe (mutex bên trong)
//
//  Packet flow (single source of truth):
//    capture thread → ring_buf_.push()
//    main thread    → ring_buf_.pollNew(last_sent_seq_) → emit newPacketInfos
//    PcapTab        → onNewPacketInfos() → packet_model_->appendRecords()
//
//  ringBuf() public — PcapTab dùng để khởi tạo PacketListModel với đúng buffer
// ─────────────────────────────────────────────────────────────────────────────
class UiBridge : public QObject {
    Q_OBJECT

public:
    explicit UiBridge(AlertManager&     alert_manager,
                      Dispatcher&       dispatcher,
                      MLEngine&         ml_engine,
                      PacketRingBuffer& ring_buf,
                      QObject*          parent = nullptr);

    void startPolling(int interval_ms = 20);
    void stopPolling();

    void setMaxBatchPerTick(uint64_t n) { max_batch_per_tick_ = n; }

    // ── Public accessor — PcapTab dùng để rebuild PacketListModel ─────────────
    PacketRingBuffer& ringBuf() { return ring_buf_; }

    bool isDetectionEnabled() const {
        return ENGINE_CFG.detection_enabled.load(std::memory_order_relaxed);
    }
    bool isMlEnabled() const {
        return ENGINE_CFG.ml_enabled.load(std::memory_order_relaxed);
    }

signals:
    void metricsUpdated        (MetricsSnapshot snapshot);
    void newAlerts             (std::vector<UnifiedAlert> alerts);
    void trafficUpdated        (TrafficPoint point);
    void systemStatusChanged   (bool running);
    void newPacketInfos        (std::vector<PacketInfo> records);
    void detectionStatusChanged(bool enabled);
    void mlStatusChanged       (bool enabled);

public slots:
    void setDetectionEnabled(bool enabled);
    void setMlEnabled       (bool enabled);

private slots:
    void onTimer();

private:
    MetricsSnapshot buildMetricsSnapshot() const;
    TrafficPoint    buildTrafficPoint();
    uint64_t        currentPps() const;

    AlertManager&     alert_manager_;
    Dispatcher&       dispatcher_;
    MLEngine&         ml_engine_;
    PacketRingBuffer& ring_buf_;

    QTimer            timer_;

    uint64_t last_alert_seq_     {0};
    uint64_t last_sent_seq_      {0};   // khởi tạo = totalPushed() trong ctor
    uint64_t max_batch_per_tick_ {150};

    struct PpsPoint {
        qint64   time_ms  = 0;
        uint64_t captured = 0;
        uint64_t dropped  = 0;
        uint64_t alerted  = 0;
    };
    std::deque<PpsPoint> pps_window_;
    static constexpr int PPS_WINDOW_MS = 10000;
};
