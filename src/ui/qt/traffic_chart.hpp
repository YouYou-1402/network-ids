#pragma once
#include <QWidget>
#include <QtCharts/QChart>
#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>
#include <QVBoxLayout>
#include <deque>
#include "ui_bridge.hpp"

// ❌ XÓA dòng này — Qt6 đã bỏ hoàn toàn QtCharts namespace
// QT_CHARTS_USE_NAMESPACE

// Qt6: QChart, QLineSeries, QValueAxis... đều nằm trong Qt:: namespace bình thường
// Không cần using namespace QtCharts hay QT_CHARTS_USE_NAMESPACE

class TrafficChart : public QWidget {
    Q_OBJECT

public:
    explicit TrafficChart(QWidget* parent = nullptr);

public slots:
    void onTrafficUpdated(TrafficPoint point);

private:
    void setupUI();
    void updateAxes();

    QChartView*  chart_view_;
    QChart*      chart_;
    QLineSeries* series_total_;
    QLineSeries* series_drop_;
    QLineSeries* series_alert_;
    QValueAxis*  axis_x_;
    QValueAxis*  axis_y_;

    std::deque<TrafficPoint> history_;
    static constexpr int     WINDOW_SEC = 60;
    static constexpr int     MAX_POINTS = 120;
};
