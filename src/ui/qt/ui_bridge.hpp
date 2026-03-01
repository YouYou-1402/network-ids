#pragma once
#include <QObject>
#include <QTimer>
#include <QDateTime>
#include <deque>
#include <vector>
#include <memory>

#include "../../dashboard/alert_manager.hpp"
#include "../../common/metrics.hpp"
#include "../../layer1/dispatcher.hpp"
#include "../../layer2/ml_engine.hpp"
#include "../../pcap_io/packet_ring_buffer.hpp"

// ─── Snapshot structs ────────────────────────────────────────────────────────
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

// ─── UiBridge ────────────────────────────────────────────────────────────────
class UiBridge : public QObject {
    Q_OBJECT

public:
    explicit UiBridge(AlertManager&     alert_manager,
                      Dispatcher&       dispatcher,
                      MLEngine&         ml_engine,
                      PacketRingBuffer& ring_buf,
                      QObject*          parent = nullptr);

    void startPolling(int interval_ms = 100);
    void stopPolling();

signals:
    void metricsUpdated    (MetricsSnapshot snapshot);
    void newAlerts         (std::vector<UnifiedAlert> alerts);
    void trafficUpdated    (TrafficPoint point);
    void systemStatusChanged(bool running);
    void newPacketRecords  (std::vector<PacketRecord> records);

private slots:
    void onTimer();

private:
    MetricsSnapshot buildMetricsSnapshot() const;
    TrafficPoint    buildTrafficPoint();        // ← bỏ const, cần update state

    AlertManager&     alert_manager_;
    Dispatcher&       dispatcher_;
    MLEngine&         ml_engine_;
    PacketRingBuffer& ring_buf_;
    QTimer            timer_;

    // ── Alert tracking ────────────────────────────────────────────────────────
    size_t   last_alert_count_ = 0;

    // ── Live packet tracking ──────────────────────────────────────────────────
    uint64_t last_sent_total_  = 0;

    // ── Adaptive batch ────────────────────────────────────────────────────────
    static constexpr uint64_t MIN_BATCH = 50;
    static constexpr uint64_t MAX_BATCH = 200;
    uint64_t current_batch_   = MAX_BATCH;

    // ── Sliding window PPS (fix bug *2) ───────────────────────────────────────
    struct PpsPoint {
        qint64   time_ms  = 0;
        uint64_t captured = 0;
        uint64_t dropped  = 0;
        uint64_t alerted  = 0;
    };
    std::deque<PpsPoint> pps_window_;
    static constexpr int PPS_WINDOW_MS = 1000;  // sliding 1 giây
};
