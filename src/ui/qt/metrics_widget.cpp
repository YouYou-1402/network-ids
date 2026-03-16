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
    root_layout->setSpacing(6);
    root_layout->setContentsMargins(8, 8, 8, 6);

    // ── Header ────────────────────────────────────────────────────────────────
    auto* header = new QLabel("📊  Stats", this);
    header->setStyleSheet(
        "color: #aaaacc; font-weight: bold; font-size: 12px; "
        "padding: 2px 0 4px 0;");
    root_layout->addWidget(header);

    // ── Packet counters — dạng grid 2 cột ────────────────────────────────────
    auto* pkt_group  = new QGroupBox("Packets", this);
    auto* pkt_layout = new QGridLayout(pkt_group);
    pkt_layout->setSpacing(4);
    pkt_layout->setContentsMargins(8, 10, 8, 8);

    auto makeCounter = [&](const QString& label,
                            QLCDNumber*&   lcd,
                            const QString& color,
                            int row, int col) {
        auto* cell   = new QWidget(pkt_group);
        auto* layout = new QVBoxLayout(cell);
        layout->setSpacing(2);
        layout->setContentsMargins(2, 2, 2, 2);

        auto* lbl = new QLabel(label, cell);
        lbl->setAlignment(Qt::AlignCenter);
        lbl->setStyleSheet("color: #888888; font-size: 9px;");

        lcd = new QLCDNumber(cell);
        lcd->setDigitCount(8);
        lcd->setSegmentStyle(QLCDNumber::Flat);
        lcd->setFixedHeight(28);
        lcd->setStyleSheet(
            "QLCDNumber { background: #12121e; color: " + color + "; "
            "border: 1px solid #2a2a3e; border-radius: 3px; }");

        layout->addWidget(lbl);
        layout->addWidget(lcd);
        pkt_layout->addWidget(cell, row, col);
    };

    makeCounter("Captured", lcd_captured_, "#00ff88", 0, 0);
    makeCounter("Passed",   lcd_passed_,   "#4488ff", 0, 1);
    makeCounter("Dropped",  lcd_dropped_,  "#ff4444", 1, 0);
    makeCounter("Alerted",  lcd_pps_,      "#ffaa00", 1, 1);

    root_layout->addWidget(pkt_group);

    // ── Threat breakdown — compact bars ───────────────────────────────────────
    auto* threat_group  = new QGroupBox("Threats", this);
    auto* threat_layout = new QVBoxLayout(threat_group);
    threat_layout->setSpacing(5);
    threat_layout->setContentsMargins(8, 10, 8, 8);

    auto makeThreatRow = [&](const QString& name,
                              const QString& color,
                              QLabel*&       count_lbl,
                              QProgressBar*& bar) {
        auto* row    = new QWidget(threat_group);
        auto* layout = new QHBoxLayout(row);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        auto* name_lbl = new QLabel(name, row);
        name_lbl->setFixedWidth(70);
        name_lbl->setStyleSheet(
            "color: " + color + "; font-size: 10px; font-weight: bold;");

        bar = new QProgressBar(row);
        bar->setRange(0, 100);
        bar->setValue(0);
        bar->setFixedHeight(12);
        bar->setTextVisible(false);
        bar->setStyleSheet(
            "QProgressBar { background: #1a1a2e; border: 1px solid #2a2a3e; "
            "border-radius: 2px; }"
            "QProgressBar::chunk { background: " + color + "; "
            "border-radius: 1px; }");

        count_lbl = new QLabel("0", row);
        count_lbl->setFixedWidth(36);
        count_lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        count_lbl->setStyleSheet(
            "color: " + color + "; font-size: 10px; font-weight: bold;");

        layout->addWidget(name_lbl);
        layout->addWidget(bar, 1);
        layout->addWidget(count_lbl);
        threat_layout->addWidget(row);
    };

    makeThreatRow("🔴 DDoS",     "#ff4444", lbl_ddos_count_, bar_ddos_);
    makeThreatRow("🟡 SlowDDoS", "#ffcc00", lbl_slow_count_, bar_slow_);
    makeThreatRow("🟠 PortScan", "#ff8800", lbl_scan_count_, bar_scan_);

    root_layout->addWidget(threat_group);

    // ── System info — compact ─────────────────────────────────────────────────
    auto* sys_group  = new QGroupBox("System", this);
    auto* sys_layout = new QGridLayout(sys_group);
    sys_layout->setSpacing(3);
    sys_layout->setContentsMargins(8, 10, 8, 8);

    auto makeSysRow = [&](const QString& label,
                           QLabel*&       value_lbl,
                           int row) {
        auto* lbl = new QLabel(label, sys_group);
        lbl->setStyleSheet("color: #888888; font-size: 10px;");

        value_lbl = new QLabel("0", sys_group);
        value_lbl->setAlignment(Qt::AlignRight);
        value_lbl->setStyleSheet(
            "color: #00ccff; font-size: 10px; font-weight: bold;");

        sys_layout->addWidget(lbl,       row, 0);
        sys_layout->addWidget(value_lbl, row, 1);
    };

    makeSysRow("Active Flows",  lbl_active_flows_, 0);
    makeSysRow("L2 Jobs",       lbl_ml_jobs_,      1);
    makeSysRow("L2 Anomalies",  lbl_ml_anomalies_, 2);

    root_layout->addWidget(sys_group);

    // ── GroupBox style chung ──────────────────────────────────────────────────
    const QString group_style =
        "QGroupBox { color: #8888aa; font-size: 10px; font-weight: bold; "
        "border: 1px solid #2a2a3e; border-radius: 5px; "
        "margin-top: 6px; padding-top: 2px; background: #0d0d1a; }"
        "QGroupBox::title { subcontrol-origin: margin; "
        "left: 8px; padding: 0 4px; }";
    pkt_group->setStyleSheet(group_style);
    threat_group->setStyleSheet(group_style);
    sys_group->setStyleSheet(group_style);
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
