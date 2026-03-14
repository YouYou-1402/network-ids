//src/ui/qt/metrics_widget.cpp
#include "metrics_widget.hpp"
#include <QFont>
#include <QPalette>
#include <algorithm>

MetricsWidget::MetricsWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
}

void MetricsWidget::setupUI() {
    auto* root_layout = new QVBoxLayout(this);
    root_layout->setSpacing(8);
    root_layout->setContentsMargins(8, 8, 8, 8);

    auto* pkt_group  = new QGroupBox("📦 Packet Counters", this);
    auto* pkt_layout = new QVBoxLayout(pkt_group);

    auto makeLCD = [&](const QString& label,
                       QLCDNumber*&   lcd,
                       const QString& color) {
        auto* row    = new QWidget(pkt_group);
        auto* layout = new QHBoxLayout(row);
        layout->setContentsMargins(0, 0, 0, 0);

        auto* lbl = new QLabel(label, row);
        lbl->setFixedWidth(80);
        lbl->setStyleSheet("color: #aaaaaa; font-size: 11px;");

        lcd = new QLCDNumber(row);
        lcd->setDigitCount(10);
        lcd->setSegmentStyle(QLCDNumber::Flat);
        lcd->setFixedHeight(32);
        lcd->setStyleSheet(
            "QLCDNumber { background: #1a1a2e; color: " + color + "; "
            "border: 1px solid #333; border-radius: 4px; }");

        layout->addWidget(lbl);
        layout->addWidget(lcd);
        pkt_layout->addWidget(row);
    };

    makeLCD("Captured",  lcd_captured_, "#00ff88");
    makeLCD("Passed",    lcd_passed_,   "#4488ff");
    makeLCD("Dropped",   lcd_dropped_,  "#ff4444");
    makeLCD("Alerted",   lcd_pps_,      "#ffaa00");

    root_layout->addWidget(pkt_group);

    auto* threat_group  = new QGroupBox("🚨 Threat Breakdown", this);
    auto* threat_layout = new QVBoxLayout(threat_group);

    auto makeThreatRow = [&](const QString& name,
                              const QString& color,
                              QLabel*&       count_lbl,
                              QProgressBar*& bar) {
        auto* row    = new QWidget(threat_group);
        auto* layout = new QHBoxLayout(row);
        layout->setContentsMargins(0, 2, 0, 2);

        auto* name_lbl = new QLabel(name, row);
        name_lbl->setFixedWidth(75);
        name_lbl->setStyleSheet(
            "color: " + color + "; font-weight: bold; font-size: 11px;");

        bar = new QProgressBar(row);
        bar->setRange(0, 100);
        bar->setValue(0);
        bar->setFixedHeight(14);
        bar->setTextVisible(false);
        bar->setStyleSheet(
            "QProgressBar { background: #1a1a2e; border: 1px solid #333; "
            "border-radius: 3px; }"
            "QProgressBar::chunk { background: " + color + "; "
            "border-radius: 2px; }");

        count_lbl = new QLabel("0", row);
        count_lbl->setFixedWidth(50);
        count_lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        count_lbl->setStyleSheet(
            "color: " + color + "; font-size: 11px; font-weight: bold;");

        layout->addWidget(name_lbl);
        layout->addWidget(bar);
        layout->addWidget(count_lbl);
        threat_layout->addWidget(row);
    };

    makeThreatRow("🔴 DDoS",     "#ff4444", lbl_ddos_count_, bar_ddos_);
    makeThreatRow("🟡 SlowDDoS", "#ffcc00", lbl_slow_count_, bar_slow_);
    makeThreatRow("🟠 PortScan", "#ff8800", lbl_scan_count_, bar_scan_);

    root_layout->addWidget(threat_group);

    auto* sys_group  = new QGroupBox("⚙️ System", this);
    auto* sys_layout = new QVBoxLayout(sys_group);

    auto makeSysRow = [&](const QString& label,
                           QLabel*&       value_lbl) {
        auto* row    = new QWidget(sys_group);
        auto* layout = new QHBoxLayout(row);
        layout->setContentsMargins(0, 1, 0, 1);

        auto* lbl = new QLabel(label, row);
        lbl->setStyleSheet("color: #aaaaaa; font-size: 11px;");

        value_lbl = new QLabel("0", row);
        value_lbl->setAlignment(Qt::AlignRight);
        value_lbl->setStyleSheet(
            "color: #00ccff; font-size: 11px; font-weight: bold;");

        layout->addWidget(lbl);
        layout->addWidget(value_lbl);
        sys_layout->addWidget(row);
    };

    makeSysRow("Active Flows :", lbl_active_flows_);
    makeSysRow("L2 Jobs      :", lbl_ml_jobs_);
    makeSysRow("L2 Anomalies :", lbl_ml_anomalies_);

    root_layout->addWidget(sys_group);
    root_layout->addStretch();

    // Dark theme cho toàn widget
    setStyleSheet("QGroupBox { color: #cccccc; font-weight: bold; "
                  "border: 1px solid #444; border-radius: 6px; "
                  "margin-top: 8px; padding-top: 4px; }"
                  "QGroupBox::title { subcontrol-origin: margin; "
                  "left: 8px; padding: 0 4px; }");
}

void MetricsWidget::onMetricsUpdated(MetricsSnapshot s) {
    // Packet counters
    lcd_captured_->display(static_cast<double>(s.packets_captured));
    lcd_passed_  ->display(static_cast<double>(s.packets_passed));
    lcd_dropped_ ->display(static_cast<double>(s.packets_dropped));
    lcd_pps_     ->display(static_cast<double>(s.packets_alerted));

    uint64_t total = s.ddos_count + s.slow_ddos_count + s.port_scan_count;
    if (total > 0) {
        bar_ddos_->setValue(
            static_cast<int>(s.ddos_count * 100 / total));
        bar_slow_->setValue(
            static_cast<int>(s.slow_ddos_count * 100 / total));
        bar_scan_->setValue(
            static_cast<int>(s.port_scan_count * 100 / total));
    }

    lbl_ddos_count_->setText(QString::number(s.ddos_count));
    lbl_slow_count_->setText(QString::number(s.slow_ddos_count));
    lbl_scan_count_->setText(QString::number(s.port_scan_count));

    lbl_active_flows_->setText(QString::number(s.active_flows));
    lbl_ml_jobs_     ->setText(QString::number(s.ml_jobs));
    lbl_ml_anomalies_->setText(QString::number(s.ml_anomalies));
}
