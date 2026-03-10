// src/ui/qt/traffic_chart.cpp
#include "traffic_chart.hpp"
#include <QPen>
#include <QBrush>
#include <algorithm>

TrafficChart::TrafficChart(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
}

void TrafficChart::setupUI() {
    // ── Widget tự giãn ────────────────────────────────────────────────────────
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // ── Series ────────────────────────────────────────────────────────────────
    series_total_ = new QLineSeries();
    series_drop_  = new QLineSeries();
    series_alert_ = new QLineSeries();

    series_total_->setName("Total pkt/s");
    series_drop_ ->setName("Dropped");
    series_alert_->setName("Alerted");

    QPen pen_total(QColor("#00ff88")); pen_total.setWidth(2);
    QPen pen_drop (QColor("#ff4444")); pen_drop .setWidth(2);
    QPen pen_alert(QColor("#ffcc00")); pen_alert.setWidth(2);
    series_total_->setPen(pen_total);
    series_drop_ ->setPen(pen_drop);
    series_alert_->setPen(pen_alert);

    // ── Chart ─────────────────────────────────────────────────────────────────
    chart_ = new QChart();
    chart_->addSeries(series_total_);
    chart_->addSeries(series_drop_);
    chart_->addSeries(series_alert_);
    chart_->setTitle("Traffic Monitor (60s window)");
    chart_->setTitleBrush(QBrush(QColor("#cccccc")));
    chart_->setBackgroundBrush(QBrush(QColor("#0f0f1a")));
    chart_->setPlotAreaBackgroundBrush(QBrush(QColor("#0a0a14")));
    chart_->setPlotAreaBackgroundVisible(true);
    chart_->legend()->setLabelColor(QColor("#aaaaaa"));
    chart_->legend()->setAlignment(Qt::AlignBottom);
    // ✅ Tắt animation — tránh giật/lag khi update liên tục
    chart_->setAnimationOptions(QChart::NoAnimation);
    // ✅ Thêm margin phải để trục X không bị cắt khi setReverse
    chart_->setMargins(QMargins(8, 8, 16, 8));

    // ── Axes ──────────────────────────────────────────────────────────────────
    axis_x_ = new QValueAxis();
    axis_x_->setRange(0, WINDOW_SEC);
    axis_x_->setLabelFormat("%d s");
    axis_x_->setTickCount(7);
    axis_x_->setMinorTickCount(1);
    axis_x_->setLabelsColor(QColor("#888888"));
    axis_x_->setGridLineColor(QColor("#1e1e2e"));
    axis_x_->setMinorGridLineColor(QColor("#161622"));
    axis_x_->setLinePen(QPen(QColor("#444444")));
    axis_x_->setTitleText("seconds ago");
    axis_x_->setTitleBrush(QBrush(QColor("#888888")));
    // ✅ Reverse: 60 bên trái (quá khứ) → 0 bên phải (hiện tại)
    axis_x_->setReverse(true);

    axis_y_ = new QValueAxis();
    axis_y_->setRange(0, 100);
    axis_y_->setLabelFormat("%d");
    axis_y_->setTickCount(6);
    axis_y_->setMinorTickCount(1);
    axis_y_->setLabelsColor(QColor("#888888"));
    axis_y_->setGridLineColor(QColor("#1e1e2e"));
    axis_y_->setMinorGridLineColor(QColor("#161622"));
    axis_y_->setLinePen(QPen(QColor("#444444")));
    axis_y_->setTitleText("Packets/sec");
    axis_y_->setTitleBrush(QBrush(QColor("#888888")));

    chart_->addAxis(axis_x_, Qt::AlignBottom);
    chart_->addAxis(axis_y_, Qt::AlignLeft);

    series_total_->attachAxis(axis_x_);
    series_total_->attachAxis(axis_y_);
    series_drop_ ->attachAxis(axis_x_);
    series_drop_ ->attachAxis(axis_y_);
    series_alert_->attachAxis(axis_x_);
    series_alert_->attachAxis(axis_y_);

    // ── ChartView ─────────────────────────────────────────────────────────────
    chart_view_ = new QChartView(chart_, this);
    chart_view_->setRenderHint(QPainter::Antialiasing);
    chart_view_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    chart_view_->setMinimumSize(400, 300);
    chart_view_->setObjectName("trafficChartView");
    chart_view_->setStyleSheet(
        "#trafficChartView { border: 1px solid #2a2a3e; "
        "border-radius: 6px; background: transparent; }");

    layout->addWidget(chart_view_, 1);
}

// ─── onTrafficUpdated ─────────────────────────────────────────────────────────
void TrafficChart::onTrafficUpdated(TrafficPoint point) {
    const double now = point.timestamp;

    history_.push_back(point);

    // ✅ Xóa điểm ngoài cửa sổ theo thời gian thực (không dùng MAX_POINTS cứng)
    while (history_.size() > 1 &&
           now - history_.front().timestamp > static_cast<double>(WINDOW_SEC) + 2.0)
        history_.pop_front();

    // Giới hạn tối đa để tránh memory leak nếu timestamp bị lỗi
    while (history_.size() > MAX_POINTS)
        history_.pop_front();

    // ── Build point lists ─────────────────────────────────────────────────────
    QList<QPointF> pts_total, pts_drop, pts_alert;
    pts_total.reserve(static_cast<int>(history_.size()));
    pts_drop .reserve(static_cast<int>(history_.size()));
    pts_alert.reserve(static_cast<int>(history_.size()));

    uint64_t max_y = 100;

    for (const auto& p : history_) {
        const double age = now - p.timestamp;   // 0 = now, 60 = 60s trước
        if (age < 0.0 || age > static_cast<double>(WINDOW_SEC)) continue;

        pts_total.append({ age, static_cast<double>(p.total_pps) });
        pts_drop .append({ age, static_cast<double>(p.drop_pps)  });
        pts_alert.append({ age, static_cast<double>(p.alert_pps) });

        max_y = std::max(max_y, p.total_pps);
    }
    series_total_->replace(pts_total);
    series_drop_ ->replace(pts_drop);
    series_alert_->replace(pts_alert);

    //    Thêm 10% headroom để đường không chạm đỉnh
    const uint64_t headroom = max_y / 10;
    const uint64_t y_top    = max_y + headroom;
    const uint64_t y_max    = (y_top / 100 + 1) * 100;
    axis_y_->setRange(0, static_cast<double>(y_max));
}
