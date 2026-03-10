#pragma once
#include <QWidget>
#include <QtCharts/QChart>
#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>
#include <QVBoxLayout>
#include <deque>
#include "ui_bridge.hpp"

class TrafficChart : public QWidget {
    Q_OBJECT

public:
    explicit TrafficChart(QWidget* parent = nullptr);

    void forceResize() {
        if (chart_view_) {
            chart_view_->resize(size());
            chart_view_->update();
        }
    }

public slots:
    void onTrafficUpdated(TrafficPoint point);

private:
    void setupUI();

    QChartView*  chart_view_  { nullptr };
    QChart*      chart_       { nullptr };
    QLineSeries* series_total_{ nullptr };
    QLineSeries* series_drop_ { nullptr };
    QLineSeries* series_alert_{ nullptr };
    QValueAxis*  axis_x_      { nullptr };
    QValueAxis*  axis_y_      { nullptr };

    std::deque<TrafficPoint> history_;

    static constexpr int    WINDOW_SEC = 60;
    static constexpr size_t MAX_POINTS = 360;
};
