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
    , alert_manager_(alert_manager)
    , dispatcher_(dispatcher)
    , ml_engine_(ml_engine)
    , ring_buf_(ring_buf)
{
    connect(&timer_, &QTimer::timeout, this, &UiBridge::onTimer);

    // Khởi tạo last_sent_seq_ = totalPushed() hiện tại
    // → không emit packet cũ khi UI vừa mở
    last_sent_seq_ = ring_buf_.totalPushed();
}

void UiBridge::startPolling(int interval_ms) { timer_.start(interval_ms); }
void UiBridge::stopPolling()                 { timer_.stop();              }

// ─── onTimer ──────────────────────────────────────────────────────────────────
void UiBridge::onTimer() {

    // ── 1. Metrics ────────────────────────────────────────────────────────────
    emit metricsUpdated(buildMetricsSnapshot());

    // ── 2. Traffic chart ──────────────────────────────────────────────────────
    // buildTrafficPoint() push vào pps_window_ → currentPps() đọc sau
    emit trafficUpdated(buildTrafficPoint());

    // ── 3. Alerts — chỉ lấy phần mới ─────────────────────────────────────────
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
        if (total_now <= last_sent_seq_) return;

        // ── Adaptive batch: điều chỉnh max_batch_per_tick_ theo PPS ──────────
        // currentPps() đọc pps_window_ đã được buildTrafficPoint() cập nhật
        const uint64_t pps = currentPps();
        if      (pps > 5000) max_batch_per_tick_ = 30;
        else if (pps > 2000) max_batch_per_tick_ = 60;
        else if (pps > 500)  max_batch_per_tick_ = 100;
        else                 max_batch_per_tick_ = 150;

        // ── FIX: dùng pollRange thay vì pollNew + rollback ────────────────────
        //
        // Trước đây (BUG):
        //   pollNew(last_sent_seq_)  → advance last_sent_seq_ lên write_seq_
        //   records.resize(batch)    → cắt bớt
        //   last_sent_seq_ -= skip   → rollback thủ công
        //   → race: capture thread push thêm trong lúc rollback
        //   → có thể bỏ sót hoặc duplicate packet
        //
        // Bây giờ (FIX):
        //   Tính to_fetch trước
        //   pollRange(from, count)   → KHÔNG thay đổi state
        //   last_sent_seq_ += to_fetch → advance chính xác SAU khi lấy xong
        //   → không race, không bỏ sót, không duplicate

        const uint64_t available = total_now - last_sent_seq_;
        const uint64_t to_fetch  = std::min(
            available,
            static_cast<uint64_t>(max_batch_per_tick_));

        auto records = ring_buf_.pollRange(last_sent_seq_, to_fetch);

        // Advance đúng số lượng đã fetch — kể cả khi ring buffer trả về
        // ít hơn to_fetch (do oldest_seq_ đã vượt qua một số slot)
        // → dùng to_fetch (không dùng records.size()) để tránh re-fetch
        //   các slot đã bị overwrite mà không bao giờ lấy được
        last_sent_seq_ += to_fetch;

        if (!records.empty())
            emit newPacketInfos(std::move(records));
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
// Push PpsPoint mới vào window, tính PPS từ oldest → newest
TrafficPoint UiBridge::buildTrafficPoint() {
    const qint64   now_ms   = QDateTime::currentMSecsSinceEpoch();
    const uint64_t captured = METRICS.packets_captured.load(std::memory_order_relaxed);
    const uint64_t dropped  = METRICS.packets_dropped .load(std::memory_order_relaxed);
    const uint64_t alerted  = METRICS.packets_alerted .load(std::memory_order_relaxed);

    pps_window_.push_back({now_ms, captured, dropped, alerted});

    // Evict điểm cũ hơn PPS_WINDOW_MS
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
// Đọc PPS từ pps_window_ hiện tại — không push thêm
// Gọi SAU buildTrafficPoint() để window đã có điểm mới nhất
uint64_t UiBridge::currentPps() const {
    if (pps_window_.size() < 2) return 0;

    const auto&  oldest  = pps_window_.front();
    const auto&  newest  = pps_window_.back();
    const qint64 elapsed = newest.time_ms - oldest.time_ms;

    if (elapsed <= 0) return 0;
    if (newest.captured <= oldest.captured) return 0;

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

void UiBridge::notifyCaptureStarted() {
    LOG_INFO("UiBridge: capture started");
    emit captureStarted();
}

void UiBridge::notifyCaptureStopped() {
    LOG_INFO("UiBridge: capture stopped");
    emit captureStopped();
}