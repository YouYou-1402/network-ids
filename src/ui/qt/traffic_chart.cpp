#include "traffic_chart.hpp"
#include <QDateTime>
#include <QPen>
#include <QBrush>
#include <algorithm>  // std::max

TrafficChart::TrafficChart(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
}

void TrafficChart::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

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

    // ── Axes ──────────────────────────────────────────────────────────────────
    axis_x_ = new QValueAxis();
    axis_x_->setRange(0, WINDOW_SEC);
    axis_x_->setLabelFormat("%d s");
    axis_x_->setTickCount(7);
    axis_x_->setLabelsColor(QColor("#888888"));
    axis_x_->setGridLineColor(QColor("#222222"));
    axis_x_->setLinePen(QPen(QColor("#444444")));
    axis_x_->setTitleText("Time (seconds ago)");
    axis_x_->setTitleBrush(QBrush(QColor("#888888")));

    axis_y_ = new QValueAxis();
    axis_y_->setRange(0, 1000);
    axis_y_->setLabelFormat("%d");
    axis_y_->setTickCount(6);
    axis_y_->setLabelsColor(QColor("#888888"));
    axis_y_->setGridLineColor(QColor("#222222"));
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
    chart_view_->setStyleSheet(
        "QChartView { border: 1px solid #333; border-radius: 6px; }");

    layout->addWidget(chart_view_);
}

void TrafficChart::onTrafficUpdated(TrafficPoint point) {
    history_.push_back(point);
    while (history_.size() > static_cast<size_t>(MAX_POINTS))
        history_.pop_front();

    series_total_->clear();
    series_drop_ ->clear();
    series_alert_->clear();

    double   now   = point.timestamp;
    uint64_t max_y = 100;

    for (const auto& p : history_) {
        double x = WINDOW_SEC - (now - p.timestamp);
        if (x < 0) continue;

        series_total_->append(x, static_cast<double>(p.total_pps));
        series_drop_ ->append(x, static_cast<double>(p.drop_pps));
        series_alert_->append(x, static_cast<double>(p.alert_pps));

        max_y = std::max(max_y, p.total_pps);
    }

    // Auto-scale Y — round lên bội số 500
    uint64_t y_max = (max_y / 500 + 1) * 500;
    axis_y_->setRange(0, static_cast<double>(y_max));
}
