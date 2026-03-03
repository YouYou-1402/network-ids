// ── ui_bridge.cpp ─────────────────────────────────────────────────────────────
#include "ui_bridge.hpp"
#include <algorithm>

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
    connect(&timer_, &QTimer::timeout, this, &UiBridge::onTimer);
}

void UiBridge::startPolling(int interval_ms) { timer_.start(interval_ms);  }
void UiBridge::stopPolling()                 { timer_.stop();               }


void UiBridge::onTimer() {

    // ── 1. Metrics — atomic reads, không lock ────────────────────────────────
    emit metricsUpdated(buildMetricsSnapshot());

    // ── 2. Traffic chart ─────────────────────────────────────────────────────
    emit trafficUpdated(buildTrafficPoint());

    // ── 3. Alerts — chỉ lấy PHẦN MỚI, không copy toàn bộ ───────────────────
    {
        // ✅ Chỉ lấy tối đa 20 alert mới nhất mỗi tick
        // Không dùng last_alert_count_ index vì deque có thể pop_front
        const uint64_t total_now = alert_manager_.totalAlerts();

        if (total_now > last_alert_seq_) {
            // Chỉ lấy phần mới — tối đa 20 để không flood UI
            const size_t want = static_cast<size_t>(
                std::min<uint64_t>(total_now - last_alert_seq_, 20));

            auto new_alerts = alert_manager_.getRecent(want);
            last_alert_seq_ = total_now;

            if (!new_alerts.empty())
                emit newAlerts(std::move(new_alerts));
        }
    }

    // ── 4. Live packets ───────────────────────────────────────────────────────
    {
        const uint64_t total_now = ring_buf_.totalReceived();
        if (total_now <= last_sent_seq_) return;

        const uint64_t pending = total_now - last_sent_seq_;

        // Adaptive batch
        uint64_t to_send = std::min(pending, max_batch_per_tick_);

        if (pps_window_.size() >= 2) {
            const auto& oldest   = pps_window_.front();
            const auto& newest   = pps_window_.back();
            const qint64 elapsed = newest.time_ms - oldest.time_ms;

            if (elapsed > 0) {
                const uint64_t pps =
                    (newest.captured > oldest.captured)
                    ? (newest.captured - oldest.captured) * 1000ULL
                      / static_cast<uint64_t>(elapsed)
                    : 0ULL;

                if      (pps > 5000) max_batch_per_tick_ = 30;
                else if (pps > 2000) max_batch_per_tick_ = 60;
                else if (pps > 500)  max_batch_per_tick_ = 100;
                else                 max_batch_per_tick_ = 150;

                to_send = std::min(pending, max_batch_per_tick_);
            }
        }

        auto records = ring_buf_.getRange(last_sent_seq_,
                                          last_sent_seq_ + to_send);
        if (!records.empty()) {
            for (auto& r : records)
                r.raw_data = nullptr;

            last_sent_seq_ += static_cast<uint64_t>(records.size());
            emit newPacketRecords(std::move(records));
        }
    }
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

// ─── buildTrafficPoint — sliding window PPS ───────────────────────────────────
TrafficPoint UiBridge::buildTrafficPoint() {
    const qint64   now_ms   = QDateTime::currentMSecsSinceEpoch();
    const uint64_t captured = METRICS.packets_captured.load();
    const uint64_t dropped  = METRICS.packets_dropped.load();
    const uint64_t alerted  = METRICS.packets_alerted.load();

    pps_window_.push_back({now_ms, captured, dropped, alerted});

    // Xóa điểm cũ hơn PPS_WINDOW_MS
    while (pps_window_.size() > 1 &&
           now_ms - pps_window_.front().time_ms > PPS_WINDOW_MS)
        pps_window_.pop_front();

    TrafficPoint p;
    p.timestamp = now_ms / 1000.0;

    if (pps_window_.size() >= 2) {
        const auto& oldest    = pps_window_.front();
        const auto& newest    = pps_window_.back();
        const qint64 elapsed  = newest.time_ms - oldest.time_ms;

        if (elapsed > 0) {
            auto pps = [&](uint64_t a, uint64_t b) -> uint64_t {
                return (a > b)
                    ? (a - b) * 1000ULL / static_cast<uint64_t>(elapsed)
                    : 0ULL;
            };
            p.total_pps = pps(newest.captured, oldest.captured);
            p.drop_pps  = pps(newest.dropped,  oldest.dropped);
            p.alert_pps = pps(newest.alerted,  oldest.alerted);
        }
    }
    return p;
}
