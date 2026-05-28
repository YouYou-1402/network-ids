//src/ui/qt/metrics_widget.cpp
#include "metrics_widget.hpp"
#include <QFont>
#include <QPalette>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QFrame>
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
    root_layout->setSpacing(6);
    root_layout->setContentsMargins(6, 6, 6, 6);

    // RESPONSIVE: tính kích thước theo font metrics
    const int em = fontMetrics().height();

    // ── Header ────────────────────────────────────────────────────────────────
    auto* header = new QLabel("Stats", this);
    header->setStyleSheet(
        "QLabel { background: transparent;"
        "  color: #1a1a3e; font-weight: bold;"
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
            "         color: #888899; }");

        lcd = new QLCDNumber(cell);
        lcd->setDigitCount(8);
        lcd->setSegmentStyle(QLCDNumber::Flat);
        // RESPONSIVE: bỏ setFixedHeight(30) → dùng setMinimumHeight theo em
        lcd->setMinimumHeight(em * 2);
        lcd->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
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
        // RESPONSIVE: bỏ setFixedWidth(74) → dùng setMinimumWidth theo em
        name_lbl->setMinimumWidth(em * 5);
        name_lbl->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        name_lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: " + color + ";"
            "         font-weight: bold; }");

        bar = new QProgressBar(row);
        bar->setRange(0, 100);
        bar->setValue(0);
        // RESPONSIVE: bỏ setFixedHeight(12) → dùng setMaximumHeight theo em
        bar->setMaximumHeight(em);
        bar->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
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
        // RESPONSIVE: bỏ setFixedWidth(38) → dùng setMinimumWidth theo em
        count_lbl->setMinimumWidth(em * 3);
        count_lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        count_lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: " + color + ";"
            "         font-weight: bold; }");

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

    // ── Inference timing ──────────────────────────────────────────────────────
    auto* infer_group  = new QGroupBox("Inference Timing", this);
    infer_group->setStyleSheet(group_style);
    auto* infer_layout = new QGridLayout(infer_group);
    infer_layout->setSpacing(4);
    infer_layout->setContentsMargins(8, 12, 8, 8);

    auto makeInferRow = [&](const QString& label,
                             QLabel*&       value_lbl,
                             int row)
    {
        auto* lbl = new QLabel(label, infer_group);
        lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #666688; font-size: 10px; }");

        value_lbl = new QLabel("—", infer_group);
        value_lbl->setAlignment(Qt::AlignRight);
        value_lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #226688;"
            "         font-size: 10px; font-weight: bold; }");

        if (row > 0) {
            auto* sep = new QFrame(infer_group);
            sep->setFrameShape(QFrame::HLine);
            sep->setStyleSheet("QFrame { color: #e8eaf4; }");
            infer_layout->addWidget(sep, row * 2 - 1, 0, 1, 2);
        }

        infer_layout->addWidget(lbl,       row * 2, 0);
        infer_layout->addWidget(value_lbl, row * 2, 1);
    };

    makeInferRow("XGB avg(min–max)",  lbl_infer_xgb_,   0);
    makeInferRow("AE  avg(min–max)",  lbl_infer_ae_,    1);
    makeInferRow("Job avg(min–max)",  lbl_infer_job_,   2);
    makeInferRow("Throughput",        lbl_infer_tput_,  3);
    makeInferRow("Jobs measured",     lbl_infer_count_, 4);

    root_layout->addWidget(infer_group);
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

    // ── Inference timing ──────────────────────────────────────────────────────
    auto fmtLatency = [](uint64_t avg_us, uint64_t min_us, uint64_t max_us) -> QString {
        if (avg_us == 0 && max_us == 0)
            return QString("—");
        return QString("%1 (%2–%3) µs")
            .arg(avg_us)
            .arg(min_us)
            .arg(max_us);
    };

    lbl_infer_xgb_->setText(
        fmtLatency(s.infer_xgb_avg_us, s.infer_xgb_min_us, s.infer_xgb_max_us));
    lbl_infer_ae_->setText(
        fmtLatency(s.infer_ae_avg_us,  s.infer_ae_min_us,  s.infer_ae_max_us));
    lbl_infer_job_->setText(
        fmtLatency(s.infer_job_avg_us, s.infer_job_min_us, s.infer_job_max_us));

    if (s.infer_jobs_per_sec > 0.0)
        lbl_infer_tput_->setText(
            QString("%1 jobs/s").arg(s.infer_jobs_per_sec, 0, 'f', 1));
    else
        lbl_infer_tput_->setText("—");

    lbl_infer_count_->setText(
        s.infer_job_count > 0
            ? QString::number(s.infer_job_count)
            : QString("—"));
}
