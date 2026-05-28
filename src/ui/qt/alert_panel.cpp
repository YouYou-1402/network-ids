// src/ui/qt/alert_panel.cpp
#include "alert_panel.hpp"
#include <QHeaderView>
#include <QDialog>
#include <QTextEdit>
#include <QDialogButtonBox>
#include <QDateTime>
#include <arpa/inet.h>

// ─── Palette ──────────────────────────────────────────────────────────────────
//  BG_PAGE   #f5f6fa    nền tổng
//  BG_PANEL  #ffffff    nền bảng
//  BG_HEADER #eef0f7    header row / toolbar
//  BORDER    #d0d4e8    viền
//  TEXT_PRI  #1a1a3e    chữ chính
//  TEXT_SEC  #666688    chữ phụ
//  ACCENT    #3355cc    xanh accent
// ─────────────────────────────────────────────────────────────────────────────

AlertPanel::AlertPanel(QWidget* parent)
    : QWidget(parent)
{
    setStyleSheet("QWidget { background: #f5f6fa; color: #1a1a3e; }");
    setupUI();
}

void AlertPanel::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(6);
    layout->setContentsMargins(8, 8, 8, 8);

    // ── Toolbar ───────────────────────────────────────────────────────────────
    auto* toolbar   = new QWidget(this);
    toolbar->setStyleSheet(
        "QWidget { background: #eef0f7;"
        "          border: 1px solid #d0d4e8;"
        "          border-radius: 4px; }");
    auto* tb_layout = new QHBoxLayout(toolbar);
    tb_layout->setContentsMargins(8, 4, 8, 4);
    tb_layout->setSpacing(8);

    auto* filter_lbl = new QLabel("Filter:", toolbar);
    filter_lbl->setStyleSheet(
        "QLabel { background: transparent;"
        "         color: #555577; font-size: 12px; }");

    filter_combo_ = new QComboBox(toolbar);
    filter_combo_->addItems({"ALL", "DDoS", "SlowDDoS",
                             "PortScan", "L1 Only", "L2 Only"});
    filter_combo_->setStyleSheet(
        "QComboBox {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #b0b8d8; border-radius: 4px;"
        "  padding: 2px 8px; font-size: 12px; }"
        "QComboBox:focus { border-color: #3355cc; }"
        "QComboBox::drop-down { border: none; width: 18px; }"
        "QComboBox QAbstractItemView {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #d0d4e8;"
        "  selection-background-color: #dce3ff;"
        "  selection-color: #0a0a6e; }");

    count_lbl_ = new QLabel("0 alerts", toolbar);
    count_lbl_->setStyleSheet(
        "QLabel { background: transparent;"
        "         color: #888899; font-size: 11px; }");

    clear_btn_ = new QPushButton("🗑  Clear", toolbar);
    // RESPONSIVE: bỏ setFixedWidth(80) → tự co dãn theo nội dung
    clear_btn_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    clear_btn_->setStyleSheet(
        "QPushButton {"
        "  background: #fff0f0; color: #cc2222;"
        "  border: 1px solid #f0b8b8; border-radius: 4px;"
        "  padding: 3px 8px; font-size: 12px; }"
        "QPushButton:hover   { background: #ffe0e0; border-color: #cc2222; }"
        "QPushButton:pressed { background: #ffd0d0; }");

    tb_layout->addWidget(filter_lbl);
    tb_layout->addWidget(filter_combo_);
    tb_layout->addStretch();
    tb_layout->addWidget(count_lbl_);
    tb_layout->addWidget(clear_btn_);
    layout->addWidget(toolbar);

    // ── Table ─────────────────────────────────────────────────────────────────
    table_ = new QTableWidget(0, 7, this);
    table_->setHorizontalHeaderLabels({
        "Time", "Layer", "Type", "Action",
        "Source IP", "Port", "Detail"
    });

    // RESPONSIVE: bỏ setColumnWidth hardcode pixel
    // Dùng ResizeToContents cho các cột ngắn, Stretch cho cột dài
    auto* hdr = table_->horizontalHeader();
    hdr->setSectionResizeMode(0, QHeaderView::ResizeToContents); // Time
    hdr->setSectionResizeMode(1, QHeaderView::ResizeToContents); // Layer
    hdr->setSectionResizeMode(2, QHeaderView::Interactive);      // Type
    hdr->setSectionResizeMode(3, QHeaderView::ResizeToContents); // Action
    hdr->setSectionResizeMode(4, QHeaderView::Interactive);      // Source IP
    hdr->setSectionResizeMode(5, QHeaderView::ResizeToContents); // Port
    hdr->setSectionResizeMode(6, QHeaderView::Stretch);          // Detail
    // Đặt kích thước mặc định tương đối theo font
    const int em = fontMetrics().averageCharWidth();
    hdr->resizeSection(2, em * 16);   // Type ~16 chars
    hdr->resizeSection(4, em * 14);   // Source IP ~14 chars

    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(false);   // tự tô màu theo threat
    table_->verticalHeader()->setVisible(false);
    table_->setShowGrid(false);
    table_->setFocusPolicy(Qt::NoFocus);
    table_->verticalHeader()->setDefaultSectionSize(22);

    table_->setStyleSheet(
        // ── Body ────────────────────────────────────────────────────────────
        "QTableWidget {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #d0d4e8;"
        "  gridline-color: transparent;"
        "  font-size: 11px; }"
        "QTableWidget::item { padding: 2px 6px; border: none; }"
        "QTableWidget::item:selected {"
        "  background: #dce3ff; color: #0a0a6e; }"
        "QTableWidget::item:hover { background: #eef0ff; }"
        // ── Header ──────────────────────────────────────────────────────────
        "QHeaderView::section {"
        "  background: #eef0f7; color: #333366;"
        "  border: none;"
        "  border-right: 1px solid #d0d4e8;"
        "  border-bottom: 2px solid #b0b8d8;"
        "  padding: 4px 6px;"
        "  font-size: 10px; font-weight: bold; }"
        "QHeaderView::section:last { border-right: none; }"
        // ── Scrollbar ───────────────────────────────────────────────────────
        "QScrollBar:vertical   { background: #f0f1f8; width: 8px; }"
        "QScrollBar:horizontal { background: #f0f1f8; height: 8px; }"
        "QScrollBar::handle:vertical   { background: #b0b8d8;"
        "  border-radius: 4px; min-height: 20px; }"
        "QScrollBar::handle:horizontal { background: #b0b8d8;"
        "  border-radius: 4px; min-width: 20px; }"
        "QScrollBar::add-line, QScrollBar::sub-line { height:0; width:0; }");

    layout->addWidget(table_);

    // ── Connections ───────────────────────────────────────────────────────────
    connect(filter_combo_,
            QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AlertPanel::onFilterChanged);
    connect(clear_btn_,  &QPushButton::clicked,
            this, &AlertPanel::onClearClicked);
    connect(table_, &QTableWidget::cellDoubleClicked,
            this, &AlertPanel::onRowClicked);
}

// ═════════════════════════════════════════════════════════════════════════════
// onNewAlerts
// ═════════════════════════════════════════════════════════════════════════════

void AlertPanel::onNewAlerts(std::vector<UnifiedAlert> alerts) {
    for (auto& alert : alerts) {
        all_alerts_.push_back(alert);
        if (matchesFilter(alert))
            addAlertRow(alert);
    }

    while (table_->rowCount() > MAX_ROWS)
        table_->removeRow(0);

    table_->scrollToBottom();
    count_lbl_->setText(QString::number(all_alerts_.size()) + " alerts");
}

// ═════════════════════════════════════════════════════════════════════════════
// addAlertRow  — light theme row colors
// ═════════════════════════════════════════════════════════════════════════════

void AlertPanel::addAlertRow(const UnifiedAlert& alert) {
    int row = table_->rowCount();
    table_->insertRow(row);

    // ── Time ──────────────────────────────────────────────────────────────────
    QDateTime dt = QDateTime::fromSecsSinceEpoch(
        static_cast<qint64>(alert.timestamp));
    auto* time_item = new QTableWidgetItem(dt.toString("hh:mm:ss"));
    time_item->setForeground(QColor("#666688"));

    // ── Layer tag ─────────────────────────────────────────────────────────────
    auto* layer_item = new QTableWidgetItem(sourceTag(alert.source));
    layer_item->setTextAlignment(Qt::AlignCenter);
    layer_item->setForeground(QColor("#3355cc"));

    // ── Threat type ───────────────────────────────────────────────────────────
    auto* type_item = new QTableWidgetItem(
        threatIcon(alert.result) + " " +
        QString::fromStdString(threatToString(alert.result)));
    type_item->setForeground(QColor(threatColor(alert.result)));

    // ── Action ────────────────────────────────────────────────────────────────
    auto* action_item = new QTableWidgetItem(
        QString::fromStdString(actionToString(alert.action)));
    action_item->setTextAlignment(Qt::AlignCenter);

    // ── Source IP ─────────────────────────────────────────────────────────────
    struct in_addr addr;
    addr.s_addr = alert.src_ip;
    auto* ip_item = new QTableWidgetItem(QString(inet_ntoa(addr)));

    // ── Port ──────────────────────────────────────────────────────────────────
    auto* port_item = new QTableWidgetItem(
        QString::number(alert.src_port));
    port_item->setTextAlignment(Qt::AlignCenter);

    // ── Detail ────────────────────────────────────────────────────────────────
    auto* detail_item = new QTableWidgetItem(
        QString::fromStdString(alert.detail));
    detail_item->setForeground(QColor("#666688"));

    table_->setItem(row, 0, time_item);
    table_->setItem(row, 1, layer_item);
    table_->setItem(row, 2, type_item);
    table_->setItem(row, 3, action_item);
    table_->setItem(row, 4, ip_item);
    table_->setItem(row, 5, port_item);
    table_->setItem(row, 6, detail_item);

    // ── Row background — light pastel theo threat type ────────────────────────
    //   DDoS      → đỏ nhạt   #fff0f0
    //   SlowDDoS  → vàng nhạt #fffbe6
    //   PortScan  → cam nhạt  #fff4e6
    //   Normal    → xanh nhạt #f0fff4
    QColor row_bg;
    switch (alert.result) {
        case DetectionResult::DDOS_VOLUMETRIC: row_bg = QColor("#fff0f0"); break;
        case DetectionResult::SLOW_DDOS:       row_bg = QColor("#fffbe6"); break;
        case DetectionResult::PORT_SCAN:       row_bg = QColor("#fff4e6"); break;
        default:                               row_bg = QColor("#f0fff4"); break;
    }

    for (int col = 0; col < table_->columnCount(); ++col)
        if (auto* item = table_->item(row, col))
            item->setBackground(row_bg);
}

// ═════════════════════════════════════════════════════════════════════════════
// Filter
// ═════════════════════════════════════════════════════════════════════════════

bool AlertPanel::matchesFilter(const UnifiedAlert& alert) const {
    switch (filter_combo_->currentIndex()) {
        case 0: return true;
        case 1: return alert.result == DetectionResult::DDOS_VOLUMETRIC;
        case 2: return alert.result == DetectionResult::SLOW_DDOS;
        case 3: return alert.result == DetectionResult::PORT_SCAN;
        case 4: return alert.source == UnifiedAlert::Source::LAYER1;
        case 5: return alert.source == UnifiedAlert::Source::LAYER2;
        default: return true;
    }
}

void AlertPanel::onFilterChanged(int) {
    table_->setRowCount(0);
    for (const auto& alert : all_alerts_)
        if (matchesFilter(alert))
            addAlertRow(alert);
}

void AlertPanel::onClearClicked() {
    all_alerts_.clear();
    table_->setRowCount(0);
    count_lbl_->setText("0 alerts");
}

// ═════════════════════════════════════════════════════════════════════════════
// Double-click → detail dialog
// ═════════════════════════════════════════════════════════════════════════════

void AlertPanel::onRowClicked(int row, int) {
    if (row >= static_cast<int>(all_alerts_.size())) return;

    int visible_row = 0;
    for (const auto& alert : all_alerts_) {
        if (!matchesFilter(alert)) continue;
        if (visible_row == row) {

            auto* dialog = new QDialog(this);
            dialog->setWindowTitle("Alert Detail");
            dialog->setMinimumSize(520, 320);
            dialog->setStyleSheet(
                "QDialog { background: #f5f6fa; color: #1a1a3e; }");

            auto* dlg_lay = new QVBoxLayout(dialog);
            dlg_lay->setSpacing(8);
            dlg_lay->setContentsMargins(12, 12, 12, 12);

            auto* text = new QTextEdit(dialog);
            text->setReadOnly(true);
            text->setStyleSheet(
                "QTextEdit {"
                "  background: #ffffff; color: #1a1a3e;"
                "  border: 1px solid #d0d4e8; border-radius: 4px;"
                "  font-family: 'Consolas', monospace; font-size: 12px;"
                "  padding: 6px; }");

            struct in_addr src_addr, dst_addr;
            src_addr.s_addr = alert.src_ip;
            dst_addr.s_addr = alert.dst_ip;

            QDateTime dt = QDateTime::fromSecsSinceEpoch(
                static_cast<qint64>(alert.timestamp));

            text->setPlainText(
                "=== Alert Detail ===\n"
                "Time       : " + dt.toString("yyyy-MM-dd hh:mm:ss") + "\n"
                "Layer      : " + sourceTag(alert.source) + "\n"
                "Threat     : " +
                    QString::fromStdString(threatToString(alert.result)) + "\n"
                "Action     : " +
                    QString::fromStdString(actionToString(alert.action)) + "\n"
                "Confidence : " +
                    QString::number(alert.confidence, 'f', 3) + "\n\n"
                "Source IP  : " + QString(inet_ntoa(src_addr)) +
                    ":" + QString::number(alert.src_port) + "\n"
                "Dest IP    : " + QString(inet_ntoa(dst_addr)) +
                    ":" + QString::number(alert.dst_port) + "\n\n"
                "Detail     : " +
                    QString::fromStdString(alert.detail));

            auto* btns = new QDialogButtonBox(
                QDialogButtonBox::Close, dialog);
            btns->setStyleSheet(
                "QPushButton {"
                "  background: #eef0f7; color: #1a1a3e;"
                "  border: 1px solid #b0b8d8; border-radius: 4px;"
                "  padding: 4px 16px; }"
                "QPushButton:hover { background: #dce3ff; }");
            connect(btns, &QDialogButtonBox::rejected,
                    dialog, &QDialog::accept);

            dlg_lay->addWidget(text);
            dlg_lay->addWidget(btns);
            dialog->exec();
            break;
        }
        visible_row++;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════════════

QString AlertPanel::threatColor(DetectionResult r) const {
    switch (r) {
        case DetectionResult::DDOS_VOLUMETRIC: return "#cc2222";  // đỏ đậm
        case DetectionResult::SLOW_DDOS:       return "#aa8800";  // vàng đậm
        case DetectionResult::PORT_SCAN:       return "#cc6600";  // cam đậm
        default:                               return "#227744";  // xanh đậm
    }
}

QString AlertPanel::threatIcon(DetectionResult r) const {
    switch (r) {
        case DetectionResult::DDOS_VOLUMETRIC: return "🔴";
        case DetectionResult::SLOW_DDOS:       return "🟡";
        case DetectionResult::PORT_SCAN:       return "🟠";
        default:                               return "✅";
    }
}

QString AlertPanel::sourceTag(UnifiedAlert::Source s) const {
    return (s == UnifiedAlert::Source::LAYER1) ? "L1" : "L2";
}
