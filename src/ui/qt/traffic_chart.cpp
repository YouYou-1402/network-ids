// src/ui/qt/traffic_chart.cpp
#include "traffic_chart.hpp"
#include <QPen>
#include <QBrush>
#include <algorithm>

// ─── Palette (light theme) ────────────────────────────────────────────────────
//  BG_CHART     #f5f6fa    nền chart (match widget)
//  BG_PLOT      #ffffff    nền plot area
//  BORDER       #d0d4e8    viền chartview
//  TITLE_FG     #1a1a3e    tiêu đề chart
//  LEGEND_FG    #444466    legend labels
//  AXIS_FG      #666688    axis labels / title
//  GRID_MAJOR   #e0e4f0    gridline chính
//  GRID_MINOR   #eef0f8    gridline phụ
//  AXIS_LINE    #c0c4d8    đường trục
//  SER_TOTAL    #227744    Total pkt/s  — xanh lá đậm
//  SER_DROP     #cc2222    Dropped      — đỏ đậm
//  SER_ALERT    #cc8800    Alerted      — vàng/amber đậm
// ─────────────────────────────────────────────────────────────────────────────

TrafficChart::TrafficChart(QWidget* parent)
    : QWidget(parent)
{
    setStyleSheet("QWidget { background: #f5f6fa; }");
    setupUI();
}

void TrafficChart::setupUI() {
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

    QPen pen_total(QColor("#227744")); pen_total.setWidth(2);
    QPen pen_drop (QColor("#cc2222")); pen_drop .setWidth(2);
    QPen pen_alert(QColor("#cc8800")); pen_alert.setWidth(2);
    series_total_->setPen(pen_total);
    series_drop_ ->setPen(pen_drop);
    series_alert_->setPen(pen_alert);

    // ── Chart ─────────────────────────────────────────────────────────────────
    chart_ = new QChart();
    chart_->addSeries(series_total_);
    chart_->addSeries(series_drop_);
    chart_->addSeries(series_alert_);

    chart_->setTitle("Traffic Monitor (60s window)");
    chart_->setTitleBrush(QBrush(QColor("#1a1a3e")));

    chart_->setBackgroundBrush(QBrush(QColor("#f5f6fa")));
    chart_->setPlotAreaBackgroundBrush(QBrush(QColor("#ffffff")));
    chart_->setPlotAreaBackgroundVisible(true);

    chart_->legend()->setLabelColor(QColor("#444466"));
    chart_->legend()->setAlignment(Qt::AlignBottom);

    // ✅ Tắt animation — tránh giật/lag khi update liên tục
    chart_->setAnimationOptions(QChart::NoAnimation);
    chart_->setMargins(QMargins(8, 8, 16, 8));

    // ── Axes ──────────────────────────────────────────────────────────────────
    axis_x_ = new QValueAxis();
    axis_x_->setRange(0, WINDOW_SEC);
    axis_x_->setLabelFormat("%d s");
    axis_x_->setTickCount(7);
    axis_x_->setMinorTickCount(1);
    axis_x_->setLabelsColor(QColor("#666688"));
    axis_x_->setGridLineColor(QColor("#e0e4f0"));
    axis_x_->setMinorGridLineColor(QColor("#eef0f8"));
    axis_x_->setLinePen(QPen(QColor("#c0c4d8")));
    axis_x_->setTitleText("seconds ago");
    axis_x_->setTitleBrush(QBrush(QColor("#666688")));
    // ✅ Reverse: 60 bên trái (quá khứ) → 0 bên phải (hiện tại)
    axis_x_->setReverse(true);

    axis_y_ = new QValueAxis();
    axis_y_->setRange(0, 100);
    axis_y_->setLabelFormat("%d");
    axis_y_->setTickCount(6);
    axis_y_->setMinorTickCount(1);
    axis_y_->setLabelsColor(QColor("#666688"));
    axis_y_->setGridLineColor(QColor("#e0e4f0"));
    axis_y_->setMinorGridLineColor(QColor("#eef0f8"));
    axis_y_->setLinePen(QPen(QColor("#c0c4d8")));
    axis_y_->setTitleText("Packets/sec");
    axis_y_->setTitleBrush(QBrush(QColor("#666688")));

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
        "#trafficChartView {"
        "  border: 1px solid #d0d4e8;"
        "  border-radius: 6px;"
        "  background: transparent; }");

    layout->addWidget(chart_view_, 1);
}

// ─── onTrafficUpdated ─────────────────────────────────────────────────────────
void TrafficChart::onTrafficUpdated(TrafficPoint point) {
    const double now = point.timestamp;

    history_.push_back(point);

    // ✅ Xóa điểm ngoài cửa sổ theo thời gian thực
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
        const double age = now - p.timestamp;
        if (age < 0.0 || age > static_cast<double>(WINDOW_SEC)) continue;

        pts_total.append({ age, static_cast<double>(p.total_pps) });
        pts_drop .append({ age, static_cast<double>(p.drop_pps)  });
        pts_alert.append({ age, static_cast<double>(p.alert_pps) });

        max_y = std::max(max_y, p.total_pps);
    }

    series_total_->replace(pts_total);
    series_drop_ ->replace(pts_drop);
    series_alert_->replace(pts_alert);

    // Thêm 10% headroom để đường không chạm đỉnh
    const uint64_t headroom = max_y / 10;
    const uint64_t y_top    = max_y + headroom;
    const uint64_t y_max    = (y_top / 100 + 1) * 100;
    axis_y_->setRange(0, static_cast<double>(y_max));
}
