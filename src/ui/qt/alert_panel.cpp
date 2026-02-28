#include "alert_panel.hpp"
#include <QHeaderView>
#include <QDialog>
#include <QTextEdit>
#include <QDialogButtonBox>
#include <QDateTime>
#include <arpa/inet.h>

AlertPanel::AlertPanel(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
}

void AlertPanel::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(6);
    layout->setContentsMargins(8, 8, 8, 8);

    // ── Toolbar ───────────────────────────────────────────────────────────────
    auto* toolbar  = new QWidget(this);
    auto* tb_layout = new QHBoxLayout(toolbar);
    tb_layout->setContentsMargins(0, 0, 0, 0);

    auto* filter_lbl = new QLabel("Filter:", toolbar);
    filter_lbl->setStyleSheet("color: #aaaaaa;");

    filter_combo_ = new QComboBox(toolbar);
    filter_combo_->addItems({"ALL", "DDoS", "SlowDDoS",
                             "PortScan", "L1 Only", "L2 Only"});
    filter_combo_->setStyleSheet(
        "QComboBox { background: #2a2a3e; color: #cccccc; "
        "border: 1px solid #555; border-radius: 4px; padding: 2px 8px; }"
        "QComboBox::drop-down { border: none; }"
        "QComboBox QAbstractItemView { background: #2a2a3e; "
        "color: #cccccc; selection-background-color: #444; }");

    count_lbl_ = new QLabel("0 alerts", toolbar);
    count_lbl_->setStyleSheet("color: #888888; font-size: 11px;");

    clear_btn_ = new QPushButton("🗑 Clear", toolbar);
    clear_btn_->setFixedWidth(80);
    clear_btn_->setStyleSheet(
        "QPushButton { background: #3a2a2a; color: #ff6666; "
        "border: 1px solid #664444; border-radius: 4px; padding: 3px 8px; }"
        "QPushButton:hover { background: #4a3a3a; }");

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

    // Column widths
    table_->setColumnWidth(0, 85);   // Time
    table_->setColumnWidth(1, 45);   // Layer
    table_->setColumnWidth(2, 120);  // Type
    table_->setColumnWidth(3, 60);   // Action
    table_->setColumnWidth(4, 115);  // Source IP
    table_->setColumnWidth(5, 50);   // Port
    table_->horizontalHeader()->setStretchLastSection(true); // Detail

    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(false);
    table_->verticalHeader()->setVisible(false);
    table_->setShowGrid(false);
    table_->setFocusPolicy(Qt::NoFocus);
    table_->verticalHeader()->setDefaultSectionSize(22);

    table_->setStyleSheet(
        "QTableWidget { background: #0f0f1a; color: #cccccc; "
        "border: 1px solid #333; gridline-color: #222; "
        "font-size: 11px; }"
        "QTableWidget::item { padding: 2px 6px; border: none; }"
        "QTableWidget::item:selected { background: #2a2a4a; }"
        "QHeaderView::section { background: #1a1a2e; color: #8888aa; "
        "border: none; border-bottom: 1px solid #444; "
        "padding: 4px 6px; font-size: 11px; font-weight: bold; }");

    layout->addWidget(table_);

    // ── Connections ───────────────────────────────────────────────────────────
    connect(filter_combo_,
            QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AlertPanel::onFilterChanged);
    connect(clear_btn_, &QPushButton::clicked,
            this, &AlertPanel::onClearClicked);
    connect(table_, &QTableWidget::cellDoubleClicked,
            this, &AlertPanel::onRowClicked);
}

// ─── Nhận alerts mới từ UiBridge ─────────────────────────────────────────────
void AlertPanel::onNewAlerts(std::vector<UnifiedAlert> alerts) {
    for (auto& alert : alerts) {
        all_alerts_.push_back(alert);
        if (matchesFilter(alert))
            addAlertRow(alert);
    }

    // Giới hạn rows hiển thị
    while (table_->rowCount() > MAX_ROWS)
        table_->removeRow(0);

    // Scroll xuống dưới cùng
    table_->scrollToBottom();

    count_lbl_->setText(
        QString::number(all_alerts_.size()) + " alerts");
}

void AlertPanel::addAlertRow(const UnifiedAlert& alert) {
    int row = table_->rowCount();
    table_->insertRow(row);

    // Time
    QDateTime dt = QDateTime::fromSecsSinceEpoch(
        static_cast<qint64>(alert.timestamp));
    auto* time_item = new QTableWidgetItem(
        dt.toString("hh:mm:ss"));
    time_item->setForeground(QColor("#888888"));

    // Layer tag
    auto* layer_item = new QTableWidgetItem(
        sourceTag(alert.source));
    layer_item->setTextAlignment(Qt::AlignCenter);

    // Threat type với icon
    auto* type_item = new QTableWidgetItem(
        threatIcon(alert.result) + " " +
        QString::fromStdString(threatToString(alert.result)));

    // Action
    auto* action_item = new QTableWidgetItem(
        QString::fromStdString(actionToString(alert.action)));
    action_item->setTextAlignment(Qt::AlignCenter);

    // Source IP
    struct in_addr addr;
    addr.s_addr = alert.src_ip;
    auto* ip_item = new QTableWidgetItem(
        QString(inet_ntoa(addr)));

    // Port
    auto* port_item = new QTableWidgetItem(
        QString::number(alert.src_port));
    port_item->setTextAlignment(Qt::AlignCenter);

    // Detail
    auto* detail_item = new QTableWidgetItem(
        QString::fromStdString(alert.detail));
    detail_item->setForeground(QColor("#888888"));

    // Set items
    table_->setItem(row, 0, time_item);
    table_->setItem(row, 1, layer_item);
    table_->setItem(row, 2, type_item);
    table_->setItem(row, 3, action_item);
    table_->setItem(row, 4, ip_item);
    table_->setItem(row, 5, port_item);
    table_->setItem(row, 6, detail_item);

    // Row background color theo threat type
    QColor row_color;
    switch (alert.result) {
        case DetectionResult::DDOS_VOLUMETRIC:
            row_color = QColor(60, 20, 20);   break; // Đỏ tối
        case DetectionResult::SLOW_DDOS:
            row_color = QColor(50, 45, 10);   break; // Vàng tối
        case DetectionResult::PORT_SCAN:
            row_color = QColor(55, 35, 10);   break; // Cam tối
        default:
            row_color = QColor(15, 25, 15);           // Xanh tối
    }

    for (int col = 0; col < table_->columnCount(); col++) {
        if (auto* item = table_->item(row, col))
            item->setBackground(row_color);
    }

    // Màu chữ cho type column
    if (type_item)
        type_item->setForeground(QColor(threatColor(alert.result)));
}

// ─── Filter ───────────────────────────────────────────────────────────────────
bool AlertPanel::matchesFilter(const UnifiedAlert& alert) const {
    int idx = filter_combo_->currentIndex();
    switch (idx) {
        case 0: return true; // ALL
        case 1: return alert.result == DetectionResult::DDOS_VOLUMETRIC;
        case 2: return alert.result == DetectionResult::SLOW_DDOS;
        case 3: return alert.result == DetectionResult::PORT_SCAN;
        case 4: return alert.source == UnifiedAlert::Source::LAYER1;
        case 5: return alert.source == UnifiedAlert::Source::LAYER2;
        default: return true;
    }
}

void AlertPanel::onFilterChanged(int) {
    // Rebuild table với filter mới
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

// ─── Double-click → detail dialog ────────────────────────────────────────────
void AlertPanel::onRowClicked(int row, int) {
    if (row >= static_cast<int>(all_alerts_.size())) return;

    // Tìm alert tương ứng với row hiển thị
    // (đơn giản hóa: lấy từ cuối danh sách)
    int visible_row = 0;
    for (const auto& alert : all_alerts_) {
        if (!matchesFilter(alert)) continue;
        if (visible_row == row) {
            // Hiện dialog chi tiết
            auto* dialog = new QDialog(this);
            dialog->setWindowTitle("Alert Detail");
            dialog->setMinimumSize(500, 300);
            dialog->setStyleSheet(
                "QDialog { background: #1a1a2e; color: #cccccc; }");

            auto* layout = new QVBoxLayout(dialog);
            auto* text   = new QTextEdit(dialog);
            text->setReadOnly(true);
            text->setStyleSheet(
                "QTextEdit { background: #0f0f1a; color: #cccccc; "
                "border: 1px solid #333; font-family: monospace; }");

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
                    QString::number(alert.confidence, 'f', 3) + "\n"
                "\n"
                "Source IP  : " + QString(inet_ntoa(src_addr)) +
                    ":" + QString::number(alert.src_port) + "\n"
                "Dest IP    : " + QString(inet_ntoa(dst_addr)) +
                    ":" + QString::number(alert.dst_port) + "\n"
                "\n"
                "Detail     : " +
                    QString::fromStdString(alert.detail)
            );

            auto* btns = new QDialogButtonBox(
                QDialogButtonBox::Close, dialog);
            btns->setStyleSheet(
                "QPushButton { background: #2a2a4a; color: #cccccc; "
                "border: 1px solid #555; border-radius: 4px; "
                "padding: 4px 16px; }"
                "QPushButton:hover { background: #3a3a5a; }");
            connect(btns, &QDialogButtonBox::rejected,
                    dialog, &QDialog::accept);

            layout->addWidget(text);
            layout->addWidget(btns);
            dialog->exec();
            break;
        }
        visible_row++;
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
QString AlertPanel::threatColor(DetectionResult r) const {
    switch (r) {
        case DetectionResult::DDOS_VOLUMETRIC: return "#ff4444";
        case DetectionResult::SLOW_DDOS:       return "#ffcc00";
        case DetectionResult::PORT_SCAN:       return "#ff8800";
        default:                               return "#44ff88";
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
