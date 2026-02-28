#pragma once
#include <QObject>
#include <QTimer>
#include <vector>
#include <memory>

#include "../../dashboard/alert_manager.hpp"
#include "../../common/metrics.hpp"
#include "../../layer1/dispatcher.hpp"
#include "../../layer2/ml_engine.hpp"

// ─── Snapshot structs (Qt-friendly, không dùng atomic) ───────────────────────
struct MetricsSnapshot {
    uint64_t packets_captured  = 0;
    uint64_t packets_dropped   = 0;
    uint64_t packets_passed    = 0;
    uint64_t packets_alerted   = 0;
    uint64_t ddos_count        = 0;
    uint64_t slow_ddos_count   = 0;
    uint64_t port_scan_count   = 0;
    uint64_t active_flows      = 0;
    uint64_t ml_jobs           = 0;
    uint64_t ml_anomalies      = 0;
};

struct TrafficPoint {
    double   timestamp = 0.0;   // Unix time
    uint64_t total_pps = 0;     // packets/sec
    uint64_t drop_pps  = 0;
    uint64_t alert_pps = 0;
};

// ─── UiBridge ────────────────────────────────────────────────────────────────
// Chạy trong Qt main thread
// Poll dashboard data mỗi 500ms → emit signals → update widgets
class UiBridge : public QObject {
    Q_OBJECT

public:
    explicit UiBridge(AlertManager& alert_manager,
                      Dispatcher&   dispatcher,
                      MLEngine&     ml_engine,
                      QObject*      parent = nullptr);

    void startPolling(int interval_ms = 500);
    void stopPolling();

signals:
    // Phát ra khi có dữ liệu mới
    void metricsUpdated(MetricsSnapshot snapshot);
    void newAlerts(std::vector<UnifiedAlert> alerts);
    void trafficUpdated(TrafficPoint point);
    void systemStatusChanged(bool running);

private slots:
    void onTimer();

private:
    MetricsSnapshot  buildMetricsSnapshot() const;
    TrafficPoint     buildTrafficPoint()    const;

    AlertManager&    alert_manager_;
    Dispatcher&      dispatcher_;
    MLEngine&        ml_engine_;

    QTimer           timer_;

    // Để tính pps (delta giữa các lần poll)
    uint64_t         last_captured_ = 0;
    uint64_t         last_dropped_  = 0;
    uint64_t         last_alerted_  = 0;

    // Số alerts đã gửi lần trước (tránh gửi lại)
    size_t           last_alert_count_ = 0;
};
