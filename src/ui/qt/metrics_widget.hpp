//src/ui/qt/metrics_widget.hpp
#pragma once
#include <QWidget>
#include <QLabel>
#include <QLCDNumber>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QGroupBox>
#include "ui_bridge.hpp"

class MetricsWidget : public QWidget {
    Q_OBJECT

public:
    explicit MetricsWidget(QWidget* parent = nullptr);

public slots:
    void onMetricsUpdated(MetricsSnapshot snapshot);

private:
    void setupUI();

    // Packet counters
    QLCDNumber* lcd_captured_;
    QLCDNumber* lcd_dropped_;
    QLCDNumber* lcd_passed_;
    QLCDNumber* lcd_pps_;

    // Threat breakdown
    QLabel*      lbl_ddos_count_;
    QLabel*      lbl_slow_count_;
    QLabel*      lbl_scan_count_;
    QProgressBar* bar_ddos_;
    QProgressBar* bar_slow_;
    QProgressBar* bar_scan_;

    // System info
    QLabel* lbl_active_flows_;
    QLabel* lbl_ml_jobs_;
    QLabel* lbl_ml_anomalies_;

    // Inference timing
    QLabel* lbl_infer_xgb_;      // "avg (min–max) µs"
    QLabel* lbl_infer_ae_;
    QLabel* lbl_infer_job_;
    QLabel* lbl_infer_tput_;     // jobs/s
    QLabel* lbl_infer_count_;    // total jobs measured

    // Để tính pps
    uint64_t last_captured_ = 0;
};
