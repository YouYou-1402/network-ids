// src/ui/qt/ui_bridge.cpp
#include "ui_bridge.hpp"
#include "../../common/engine_config.hpp"
#include "../../common/logger.hpp"
#include <algorithm>

UiBridge::UiBridge(AlertManager&     alert_manager,
                   Dispatcher&       dispatcher,
                   MLEngine&         ml_engine,
                   PacketRingBuffer& ring_buf,
                   QObject*          parent)
    : QObject(parent)
    , alert_manager_   (alert_manager)
    , dispatcher_      (dispatcher)
    , ml_engine_       (ml_engine)
    , ring_buf_        (ring_buf)
    , firewall_manager_(nullptr)
{
    connect(&timer_, &QTimer::timeout, this, &UiBridge::onTimer);
    last_sent_seq_ = ring_buf_.totalPushed();
}

void UiBridge::startPolling(int interval_ms) { timer_.start(interval_ms); }
void UiBridge::stopPolling()                 { timer_.stop();              }

// ─── onTimer ──────────────────────────────────────────────────────────────────
void UiBridge::onTimer() {

    // ── 1. Metrics ────────────────────────────────────────────────────────────
    emit metricsUpdated(buildMetricsSnapshot());

    // ── 2. Traffic chart ──────────────────────────────────────────────────────
    emit trafficUpdated(buildTrafficPoint());

    // ── 3. Alerts ─────────────────────────────────────────────────────────────
    {
        const uint64_t total_now = alert_manager_.totalAlerts();
        if (total_now > last_alert_seq_) {
            const size_t want = static_cast<size_t>(
                std::min<uint64_t>(total_now - last_alert_seq_, 20));

            auto new_alerts = alert_manager_.getRecentFrom(last_alert_seq_, want);
            last_alert_seq_ = total_now;

            if (!new_alerts.empty())
                emit newAlerts(std::move(new_alerts));
        }
    }

    // ── 4. Live packets ───────────────────────────────────────────────────────
    {
        const uint64_t total_now = ring_buf_.totalPushed();
        if (total_now > last_sent_seq_) {
            const uint64_t pps = currentPps();
            if      (pps > 5000) max_batch_per_tick_ = 30;
            else if (pps > 2000) max_batch_per_tick_ = 60;
            else if (pps > 500)  max_batch_per_tick_ = 100;
            else                 max_batch_per_tick_ = 150;

            const uint64_t available = total_now - last_sent_seq_;
            const uint64_t to_fetch  = std::min(
                available,
                static_cast<uint64_t>(max_batch_per_tick_));

            auto records = ring_buf_.pollRange(last_sent_seq_, to_fetch);
            last_sent_seq_ += to_fetch;

            if (!records.empty())
                emit newPacketInfos(std::move(records));
        }
    }

    // ── 5. Firewall stats (mỗi tick) ─────────────────────────────────────────
    if (firewall_manager_) {
        emit firewallStatsUpdated(
            firewall_manager_->blacklistSize(),
            firewall_manager_->whitelistSize());
    }
}

// ─── buildMetricsSnapshot ─────────────────────────────────────────────────────
MetricsSnapshot UiBridge::buildMetricsSnapshot() const {
    MetricsSnapshot s;
    s.packets_captured = METRICS.packets_captured.load(std::memory_order_relaxed);
    s.packets_dropped  = METRICS.packets_dropped .load(std::memory_order_relaxed);
    s.packets_passed   = METRICS.packets_passed  .load(std::memory_order_relaxed);
    s.packets_alerted  = METRICS.packets_alerted .load(std::memory_order_relaxed);
    s.ddos_count       = alert_manager_.ddosAlerts();
    s.slow_ddos_count  = alert_manager_.slowDdosAlerts();
    s.port_scan_count  = alert_manager_.scanAlerts();
    s.active_flows     = dispatcher_.activeFlows();
    s.ml_jobs          = ml_engine_.jobsProcessed();
    s.ml_anomalies     = ml_engine_.anomaliesFound();
    return s;
}

// ─── buildTrafficPoint ────────────────────────────────────────────────────────
TrafficPoint UiBridge::buildTrafficPoint() {
    const qint64   now_ms   = QDateTime::currentMSecsSinceEpoch();
    const uint64_t captured = METRICS.packets_captured.load(std::memory_order_relaxed);
    const uint64_t dropped  = METRICS.packets_dropped .load(std::memory_order_relaxed);
    const uint64_t alerted  = METRICS.packets_alerted .load(std::memory_order_relaxed);

    pps_window_.push_back({now_ms, captured, dropped, alerted});

    while (pps_window_.size() > 1 &&
           now_ms - pps_window_.front().time_ms > PPS_WINDOW_MS)
        pps_window_.pop_front();

    TrafficPoint p;
    p.timestamp = static_cast<double>(now_ms) / 1000.0;
    p.total_pps = 0;
    p.drop_pps  = 0;
    p.alert_pps = 0;

    if (pps_window_.size() >= 2) {
        const auto&  oldest  = pps_window_.front();
        const auto&  newest  = pps_window_.back();
        const qint64 elapsed = newest.time_ms - oldest.time_ms;

        if (elapsed >= 100) {
            auto pps = [&](uint64_t newer, uint64_t older) -> uint64_t {
                return (newer > older)
                    ? (newer - older) * 1000ULL
                      / static_cast<uint64_t>(elapsed)
                    : 0ULL;
            };
            p.total_pps = pps(newest.captured, oldest.captured);
            p.drop_pps  = pps(newest.dropped,  oldest.dropped);
            p.alert_pps = pps(newest.alerted,  oldest.alerted);
        }
    }
    return p;
}

// ─── currentPps ───────────────────────────────────────────────────────────────
uint64_t UiBridge::currentPps() const {
    if (pps_window_.size() < 2) return 0;
    const auto&  oldest  = pps_window_.front();
    const auto&  newest  = pps_window_.back();
    const qint64 elapsed = newest.time_ms - oldest.time_ms;
    if (elapsed <= 0 || newest.captured <= oldest.captured) return 0;
    return (newest.captured - oldest.captured) * 1000ULL
           / static_cast<uint64_t>(elapsed);
}

// ─── setDetectionEnabled ──────────────────────────────────────────────────────
void UiBridge::setDetectionEnabled(bool enabled) {
    const bool prev = ENGINE_CFG.detection_enabled.exchange(enabled);
    if (prev != enabled) {
        LOG_INFO(std::string("Detection engine: ")
                 + (enabled ? "ENABLED" : "DISABLED"));
        emit detectionStatusChanged(enabled);
    }
}

// ─── setMlEnabled ─────────────────────────────────────────────────────────────
void UiBridge::setMlEnabled(bool enabled) {
    const bool prev = ENGINE_CFG.ml_enabled.exchange(enabled);
    if (prev != enabled) {
        LOG_INFO(std::string("ML engine: ")
                 + (enabled ? "ENABLED" : "DISABLED"));
        emit mlStatusChanged(enabled);
    }
}

// ─── blockIp ─────────────────────────────────────────────────────────────────
void UiBridge::blockIp(const QString& ip, const QString& reason) {
    if (!firewall_manager_) return;
    const std::string reason_str = reason.isEmpty()
        ? "Manual block via UI"
        : reason.toStdString();
    const uint64_t id = firewall_manager_->manualBlock(
        ip.toStdString(),
        0,      // protocol: any
        0,      // port: any
        false,  // not permanent
        600,    // TTL 10 min
        reason_str);
    if (id > 0)
        LOG_INFO("UI blocked IP: " + ip.toStdString()
                 + " reason=" + reason_str);
    else
        LOG_WARN("UI block failed for IP: " + ip.toStdString());
}

// ─── unblockIp ────────────────────────────────────────────────────────────────
void UiBridge::unblockIp(const QString& ip) {
    if (!firewall_manager_) return;
    if (firewall_manager_->removeByIp(ip.toStdString()))
        LOG_INFO("UI unblocked IP: " + ip.toStdString());
    else
        LOG_WARN("UI unblock failed for IP: " + ip.toStdString());
}

// ─── notifyCaptureStarted / Stopped ──────────────────────────────────────────
void UiBridge::notifyCaptureStarted() {
    LOG_INFO("UiBridge: capture started");
    emit captureStarted();
}

void UiBridge::notifyCaptureStopped() {
    LOG_INFO("UiBridge: capture stopped");
    emit captureStopped();
}
void UiBridge::clearAll() {
    // ── 1. Dừng timer tạm — tránh race với onTimer() ─────────────────────────
    const bool was_active = timer_.isActive();
    timer_.stop();

    // ── 2. Xóa PacketRingBuffer ───────────────────────────────────────────────
    // Sau lệnh này: totalPushed() = 0, oldest_seq_ = 0
    ring_buf_.clear();

    // ── 3. Reset read cursors ─────────────────────────────────────────────────
    // last_sent_seq_ = 0 → onTimer() block 4: total_now(=0) > last_sent_seq_(=0)
    //                      = FALSE → KHÔNG emit newPacketInfos → màn hình không fill lại
    // last_alert_seq_ = 0 → đồng bộ với alert_manager_.seq_ (cũng reset về 0)
    last_sent_seq_  = 0;
    last_alert_seq_ = 0;

    // ── 4. Xóa pps_window_ ───────────────────────────────────────────────────
    // Nếu không clear: buildTrafficPoint() tính delta từ snapshot cũ
    // → pps spike ảo ngay sau khi clear
    pps_window_.clear();

    // ── 5. Force expire toàn bộ flow + IP tracker ────────────────────────────
    // idle_timeout = 0.0 → mọi flow đều "idle quá lâu" → bị xóa ngay
    dispatcher_.cleanupFlows(0.0);
    dispatcher_.cleanupIps  (0.0);

    // ── 6. Xóa alert history ─────────────────────────────────────────────────
    // Bên trong: alerts_.clear(), suppress_map_.clear(), seq_=0, counters=0
    alert_manager_.clear();

    // ── 7. Reset metrics ──────────────────────────────────────────────────────
    METRICS.reset();

    // ── 8. Broadcast cho UI widgets ──────────────────────────────────────────
    // AlertPanel::onClearClicked() — xóa table + all_alerts_ + count_lbl_
    // TrafficChart::reset()        — xóa history_ + series + reset axis
    emit clearRequested();

    // ── 9. Restart timer ─────────────────────────────────────────────────────
    if (was_active) timer_.start();

    LOG_INFO("UiBridge::clearAll — ring_buf, flows, alerts, metrics reset");
}