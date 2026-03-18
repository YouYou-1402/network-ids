//src/ui/qt/metrics_widget.cpp
#include "metrics_widget.hpp"
#include <QFont>
#include <QPalette>
#include <algorithm>

// ─── Palette ──────────────────────────────────────────────────────────────────
//  BG_PAGE      #f5f6fa    nền tổng
//  BG_GROUP     #ffffff    nền groupbox
//  BG_LCD       #eef0f7    nền LCD
//  BORDER       #d0d4e8    viền
//  TEXT_HDR     #1a1a3e    header
//  TEXT_SEC     #888899    label phụ
//  TEXT_SYS     #3355cc    system value
//  GREEN        #227744    captured
//  BLUE         #3355cc    passed
//  RED          #cc2222    dropped
//  ORANGE       #cc6600    alerted
//  BAR_BG       #e0e4f4    nền progress bar
//  DDOS_CLR     #cc2222    đỏ
//  SLOW_CLR     #cc8800    vàng đậm
//  SCAN_CLR     #cc5500    cam đậm
// ─────────────────────────────────────────────────────────────────────────────

MetricsWidget::MetricsWidget(QWidget* parent)
    : QWidget(parent)
{
    setStyleSheet("QWidget { background: #f5f6fa; color: #1a1a3e; }");
    setupUI();
}

void MetricsWidget::setupUI() {
    auto* root_layout = new QVBoxLayout(this);
    root_layout->setSpacing(8);
    root_layout->setContentsMargins(8, 8, 8, 8);

    // ── Header ────────────────────────────────────────────────────────────────
    auto* header = new QLabel("📊  Stats", this);
    header->setStyleSheet(
        "QLabel { background: transparent;"
        "  color: #1a1a3e; font-weight: bold; font-size: 12px;"
        "  padding: 2px 0 4px 0; }");
    root_layout->addWidget(header);

    // ── GroupBox style chung ──────────────────────────────────────────────────
    const QString group_style =
        "QGroupBox {"
        "  background: #ffffff;"
        "  border: 1px solid #d0d4e8; border-radius: 6px;"
        "  margin-top: 8px; padding-top: 4px; }"
        "QGroupBox::title {"
        "  subcontrol-origin: margin;"
        "  left: 10px; padding: 0 4px;"
        "  color: #3355cc; font-size: 10px; font-weight: bold; }";

    // ── Packet counters ───────────────────────────────────────────────────────
    auto* pkt_group  = new QGroupBox("Packets", this);
    pkt_group->setStyleSheet(group_style);
    auto* pkt_layout = new QGridLayout(pkt_group);
    pkt_layout->setSpacing(6);
    pkt_layout->setContentsMargins(8, 12, 8, 8);

    auto makeCounter = [&](const QString& label,
                            QLCDNumber*&   lcd,
                            const QString& color,
                            int row, int col)
    {
        auto* cell   = new QWidget(pkt_group);
        cell->setStyleSheet("QWidget { background: transparent; }");
        auto* layout = new QVBoxLayout(cell);
        layout->setSpacing(2);
        layout->setContentsMargins(2, 2, 2, 2);

        auto* lbl = new QLabel(label, cell);
        lbl->setAlignment(Qt::AlignCenter);
        lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #888899; font-size: 9px; }");

        lcd = new QLCDNumber(cell);
        lcd->setDigitCount(8);
        lcd->setSegmentStyle(QLCDNumber::Flat);
        lcd->setFixedHeight(30);
        lcd->setStyleSheet(
            "QLCDNumber {"
            "  background: #eef0f7; color: " + color + ";"
            "  border: 1px solid #d0d4e8; border-radius: 4px; }");

        layout->addWidget(lbl);
        layout->addWidget(lcd);
        pkt_layout->addWidget(cell, row, col);
    };

    makeCounter("Captured", lcd_captured_, "#227744", 0, 0);
    makeCounter("Passed",   lcd_passed_,   "#3355cc", 0, 1);
    makeCounter("Dropped",  lcd_dropped_,  "#cc2222", 1, 0);
    makeCounter("Alerted",  lcd_pps_,      "#cc6600", 1, 1);

    root_layout->addWidget(pkt_group);

    // ── Threat breakdown ──────────────────────────────────────────────────────
    auto* threat_group  = new QGroupBox("Threats", this);
    threat_group->setStyleSheet(group_style);
    auto* threat_layout = new QVBoxLayout(threat_group);
    threat_layout->setSpacing(6);
    threat_layout->setContentsMargins(8, 12, 8, 8);

    auto makeThreatRow = [&](const QString& name,
                              const QString& color,
                              QLabel*&       count_lbl,
                              QProgressBar*& bar)
    {
        auto* row    = new QWidget(threat_group);
        row->setStyleSheet("QWidget { background: transparent; }");
        auto* layout = new QHBoxLayout(row);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        auto* name_lbl = new QLabel(name, row);
        name_lbl->setFixedWidth(74);
        name_lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: " + color + ";"
            "         font-size: 10px; font-weight: bold; }");

        bar = new QProgressBar(row);
        bar->setRange(0, 100);
        bar->setValue(0);
        bar->setFixedHeight(12);
        bar->setTextVisible(false);
        bar->setStyleSheet(
            "QProgressBar {"
            "  background: #e8eaf4;"
            "  border: 1px solid #d0d4e8;"
            "  border-radius: 3px; }"
            "QProgressBar::chunk {"
            "  background: " + color + ";"
            "  border-radius: 2px; }");

        count_lbl = new QLabel("0", row);
        count_lbl->setFixedWidth(38);
        count_lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        count_lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: " + color + ";"
            "         font-size: 10px; font-weight: bold; }");

        layout->addWidget(name_lbl);
        layout->addWidget(bar, 1);
        layout->addWidget(count_lbl);
        threat_layout->addWidget(row);
    };

    makeThreatRow("🔴 DDoS",     "#cc2222", lbl_ddos_count_, bar_ddos_);
    makeThreatRow("🟡 SlowDDoS", "#cc8800", lbl_slow_count_, bar_slow_);
    makeThreatRow("🟠 PortScan", "#cc5500", lbl_scan_count_, bar_scan_);

    root_layout->addWidget(threat_group);

    // ── System info ───────────────────────────────────────────────────────────
    auto* sys_group  = new QGroupBox("System", this);
    sys_group->setStyleSheet(group_style);
    auto* sys_layout = new QGridLayout(sys_group);
    sys_layout->setSpacing(4);
    sys_layout->setContentsMargins(8, 12, 8, 8);

    auto makeSysRow = [&](const QString& label,
                           QLabel*&       value_lbl,
                           int row)
    {
        auto* lbl = new QLabel(label, sys_group);
        lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #666688; font-size: 10px; }");

        value_lbl = new QLabel("0", sys_group);
        value_lbl->setAlignment(Qt::AlignRight);
        value_lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #3355cc;"
            "         font-size: 10px; font-weight: bold; }");

        // separator line giữa các row
        if (row > 0) {
            auto* sep = new QFrame(sys_group);
            sep->setFrameShape(QFrame::HLine);
            sep->setStyleSheet("QFrame { color: #e8eaf4; }");
            sys_layout->addWidget(sep, row * 2 - 1, 0, 1, 2);
        }

        sys_layout->addWidget(lbl,       row * 2, 0);
        sys_layout->addWidget(value_lbl, row * 2, 1);
    };

    makeSysRow("Active Flows", lbl_active_flows_, 0);
    makeSysRow("L2 Jobs",      lbl_ml_jobs_,      1);
    makeSysRow("L2 Anomalies", lbl_ml_anomalies_, 2);

    root_layout->addWidget(sys_group);
    root_layout->addStretch();
}

// ─── onMetricsUpdated ─────────────────────────────────────────────────────────
void MetricsWidget::onMetricsUpdated(MetricsSnapshot s) {
    lcd_captured_->display(static_cast<double>(s.packets_captured));
    lcd_passed_  ->display(static_cast<double>(s.packets_passed));
    lcd_dropped_ ->display(static_cast<double>(s.packets_dropped));
    lcd_pps_     ->display(static_cast<double>(s.packets_alerted));

    uint64_t total = s.ddos_count + s.slow_ddos_count + s.port_scan_count;
    if (total > 0) {
        bar_ddos_->setValue(
            static_cast<int>(s.ddos_count       * 100 / total));
        bar_slow_->setValue(
            static_cast<int>(s.slow_ddos_count  * 100 / total));
        bar_scan_->setValue(
            static_cast<int>(s.port_scan_count  * 100 / total));
    }

    lbl_ddos_count_->setText(QString::number(s.ddos_count));
    lbl_slow_count_->setText(QString::number(s.slow_ddos_count));
    lbl_scan_count_->setText(QString::number(s.port_scan_count));

    lbl_active_flows_->setText(QString::number(s.active_flows));
    lbl_ml_jobs_     ->setText(QString::number(s.ml_jobs));
    lbl_ml_anomalies_->setText(QString::number(s.ml_anomalies));
}
