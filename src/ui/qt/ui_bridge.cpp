#include "ui_bridge.hpp"
#include <chrono>

UiBridge::UiBridge(AlertManager& alert_manager,
                   Dispatcher&   dispatcher,
                   MLEngine&     ml_engine,
                   QObject*      parent)
    : QObject(parent)
    , alert_manager_(alert_manager)
    , dispatcher_(dispatcher)
    , ml_engine_(ml_engine)
{
    connect(&timer_, &QTimer::timeout,
            this,    &UiBridge::onTimer);
}

void UiBridge::startPolling(int interval_ms) {
    timer_.start(interval_ms);
}

void UiBridge::stopPolling() {
    timer_.stop();
}

// ─── Polling slot — chạy trong Qt main thread ─────────────────────────────────
void UiBridge::onTimer() {
    // 1. Metrics snapshot
    emit metricsUpdated(buildMetricsSnapshot());

    // 2. Traffic point
    emit trafficUpdated(buildTrafficPoint());

    // 3. New alerts (chỉ gửi phần mới)
    auto all_alerts = alert_manager_.getRecent(500);
    if (all_alerts.size() > last_alert_count_) {
        // Slice phần mới
        std::vector<UnifiedAlert> new_alerts(
            all_alerts.begin() + last_alert_count_,
            all_alerts.end()
        );
        last_alert_count_ = all_alerts.size();
        emit newAlerts(new_alerts);
    }
}

MetricsSnapshot UiBridge::buildMetricsSnapshot() const {
    MetricsSnapshot s;
    s.packets_captured  = METRICS.packets_captured.load();
    s.packets_dropped   = METRICS.packets_dropped.load();
    s.packets_passed    = METRICS.packets_passed.load();
    s.packets_alerted   = METRICS.packets_alerted.load();
    s.ddos_count        = alert_manager_.ddosAlerts();
    s.slow_ddos_count   = alert_manager_.slowDdosAlerts();
    s.port_scan_count   = alert_manager_.scanAlerts();
    s.active_flows      = dispatcher_.activeFlows();
    s.ml_jobs           = ml_engine_.jobsProcessed();
    s.ml_anomalies      = ml_engine_.anomaliesFound();
    return s;
}

TrafficPoint UiBridge::buildTrafficPoint() const {
    auto now = std::chrono::system_clock::now();
    double ts = std::chrono::duration<double>(
        now.time_since_epoch()).count();

    uint64_t cur_captured = METRICS.packets_captured.load();
    uint64_t cur_dropped  = METRICS.packets_dropped.load();
    uint64_t cur_alerted  = METRICS.packets_alerted.load();

    TrafficPoint p;
    p.timestamp = ts;
    p.total_pps = (cur_captured > last_captured_)
                  ? (cur_captured - last_captured_) * 2  // *2 vì poll 500ms
                  : 0;
    p.drop_pps  = (cur_dropped  > last_dropped_)
                  ? (cur_dropped  - last_dropped_)  * 2
                  : 0;
    p.alert_pps = (cur_alerted  > last_alerted_)
                  ? (cur_alerted  - last_alerted_)  * 2
                  : 0;

    // Cập nhật last values (const_cast vì method là const)
    const_cast<UiBridge*>(this)->last_captured_ = cur_captured;
    const_cast<UiBridge*>(this)->last_dropped_  = cur_dropped;
    const_cast<UiBridge*>(this)->last_alerted_  = cur_alerted;

    return p;
}
