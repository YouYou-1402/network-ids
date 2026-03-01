#include "ui_bridge.hpp"

UiBridge::UiBridge(AlertManager&     alert_manager,
                   Dispatcher&       dispatcher,
                   MLEngine&         ml_engine,
                   PacketRingBuffer& ring_buf,
                   QObject*          parent)
    : QObject(parent)
    , alert_manager_(alert_manager)
    , dispatcher_(dispatcher)
    , ml_engine_(ml_engine)
    , ring_buf_(ring_buf)
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

// ─── onTimer ─────────────────────────────────────────────────────────────────
void UiBridge::onTimer() {

    // ── 1. Metrics ────────────────────────────────────────────────────────────
    MetricsSnapshot snap = buildMetricsSnapshot();
    emit metricsUpdated(snap);

    // ── 2. Traffic (sliding window PPS) ───────────────────────────────────────
    emit trafficUpdated(buildTrafficPoint());

    // ── 3. Alerts: chỉ emit phần mới ─────────────────────────────────────────
    {
        auto all_alerts = alert_manager_.getRecent(500);
        if (all_alerts.size() > last_alert_count_) {
            std::vector<UnifiedAlert> new_alerts(
                all_alerts.begin() + last_alert_count_,
                all_alerts.end());
            last_alert_count_ = all_alerts.size();
            emit newAlerts(std::move(new_alerts));
        }
    }

    // ── 4. Live packets — adaptive batch ──────────────────────────────────────
    // {
    //     uint64_t total_now = ring_buf_.totalReceived();
    //     if (total_now > last_sent_total_) {
    //         uint64_t pending = total_now - last_sent_total_;

    //         // Adaptive: PPS cao → batch nhỏ để Qt không bị block
    //         if (!pps_window_.empty()) {
    //             uint64_t pps = pps_window_.back().captured > pps_window_.front().captured
    //                 ? (pps_window_.back().captured - pps_window_.front().captured)
    //                 : 0;
    //             if      (pps > 800) current_batch_ = MIN_BATCH;
    //             else if (pps > 400) current_batch_ = MIN_BATCH * 2;
    //             else                current_batch_ = MAX_BATCH;
    //         }

    //         uint64_t to_send = std::min(pending, current_batch_);
    //         uint64_t idx_end = last_sent_total_ + to_send;

    //         auto records = ring_buf_.getRange(last_sent_total_, idx_end);
    //         if (!records.empty())
    //             emit newPacketRecords(std::move(records));

    //         last_sent_total_ = idx_end;
    //     }
    // }
}

// ─── buildMetricsSnapshot ────────────────────────────────────────────────────
MetricsSnapshot UiBridge::buildMetricsSnapshot() const {
    MetricsSnapshot s;
    s.packets_captured = METRICS.packets_captured.load();
    s.packets_dropped  = METRICS.packets_dropped.load();
    s.packets_passed   = METRICS.packets_passed.load();
    s.packets_alerted  = METRICS.packets_alerted.load();
    s.ddos_count       = alert_manager_.ddosAlerts();
    s.slow_ddos_count  = alert_manager_.slowDdosAlerts();
    s.port_scan_count  = alert_manager_.scanAlerts();
    s.active_flows     = dispatcher_.activeFlows();
    s.ml_jobs          = ml_engine_.jobsProcessed();
    s.ml_anomalies     = ml_engine_.anomaliesFound();
    return s;
}

// ─── buildTrafficPoint ───────────────────────────────────────────────────────
// Dùng sliding window 1 giây thay vì nhân cứng *2
// → chính xác kể cả khi timer bị jitter
TrafficPoint UiBridge::buildTrafficPoint() {
    qint64   now_ms      = QDateTime::currentMSecsSinceEpoch();
    uint64_t captured    = METRICS.packets_captured.load();
    uint64_t dropped     = METRICS.packets_dropped.load();
    uint64_t alerted     = METRICS.packets_alerted.load();

    // Push điểm hiện tại vào window
    pps_window_.push_back({now_ms, captured, dropped, alerted});

    // Xóa điểm cũ hơn PPS_WINDOW_MS
    while (pps_window_.size() > 1 &&
           now_ms - pps_window_.front().time_ms > PPS_WINDOW_MS) {
        pps_window_.pop_front();
    }

    TrafficPoint p;
    p.timestamp = now_ms / 1000.0;

    if (pps_window_.size() >= 2) {
        const auto& oldest   = pps_window_.front();
        const auto& newest   = pps_window_.back();
        qint64 elapsed_ms    = newest.time_ms - oldest.time_ms;

        if (elapsed_ms > 0) {
            // PPS = delta_packets / elapsed_seconds (thực tế)
            auto pps = [&](uint64_t a, uint64_t b) -> uint64_t {
                return (a > b) ? (a - b) * 1000ULL / elapsed_ms : 0ULL;
            };
            p.total_pps = pps(newest.captured, oldest.captured);
            p.drop_pps  = pps(newest.dropped,  oldest.dropped);
            p.alert_pps = pps(newest.alerted,  oldest.alerted);
        }
    }
    // Nếu window chỉ có 1 điểm (tick đầu tiên) → giữ nguyên 0
    // Không bao giờ trả về giá trị sai

    return p;
}
