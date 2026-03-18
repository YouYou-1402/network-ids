// src/ui/qt/firewall_widget.cpp
#include "firewall_widget.hpp"
#include "../../common/logger.hpp"
#include <QMetaObject>
#include <QMessageBox>
#include <QFileDialog>
#include <QDateTime>
#include <QCheckBox>
#include <chrono>
#include <ctime>

// ─── Palette ──────────────────────────────────────────────────────────────────
//  BG_PAGE   #f5f6fa    nền tổng
//  BG_PANEL  #ffffff    nền bảng
//  BG_ALT    #f4f5fb    alternate row
//  BG_HEADER #eef0f7    header / toolbar
//  BORDER    #d0d4e8    viền
//  TEXT_PRI  #1a1a3e    chữ chính
//  TEXT_SEC  #666688    chữ phụ
//  ACCENT    #3355cc    xanh accent
//  RED_FG    #cc2222    đỏ foreground
//  RED_BG    #fff0f0    đỏ background pastel
//  GREEN_FG  #227744    xanh lá foreground
//  GREEN_BG  #f0fff4    xanh lá background pastel
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════════
// Constructor / setFirewallManager
// ═══════════════════════════════════════════════════════════════════════════════

FirewallWidget::FirewallWidget(QWidget* parent)
    : QWidget(parent)
{
    setStyleSheet("QWidget { background: #f5f6fa; color: #1a1a3e; }");
    setupUI();
    setControlsEnabled(false);
}

void FirewallWidget::setFirewallManager(FirewallManager* fw) {
    fw_ = fw;
    setControlsEnabled(fw_ != nullptr);
    if (!fw_) return;

    fw_->setRuleChangeCallback(
        [this](const FirewallRule& rule, bool added) {
            QMetaObject::invokeMethod(this,
                [this, rule, added]() { onRuleChanged(rule, added); },
                Qt::QueuedConnection);
        });

    refresh();
}

// ═══════════════════════════════════════════════════════════════════════════════
// setupUI
// ═══════════════════════════════════════════════════════════════════════════════

void FirewallWidget::setupUI() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(6);
    root->setContentsMargins(6, 6, 6, 6);

    // ── Stats badge ───────────────────────────────────────────────────────────
    lbl_stats_badge_ = new QLabel("🔴 Blacklist: 0   🟢 Whitelist: 0", this);
    lbl_stats_badge_->setAlignment(Qt::AlignCenter);
    lbl_stats_badge_->setFixedHeight(28);
    lbl_stats_badge_->setStyleSheet(
        "QLabel {"
        "  background: #eef0f7; color: #1a1a3e;"
        "  font-size: 11px; font-weight: bold;"
        "  border: 1px solid #d0d4e8; border-radius: 4px;"
        "  padding: 2px 8px; }");
    root->addWidget(lbl_stats_badge_);

    // ── Tab widget ────────────────────────────────────────────────────────────
    tab_widget_ = new QTabWidget(this);
    tab_widget_->setStyleSheet(
        "QTabWidget::pane {"
        "  border: 1px solid #d0d4e8; border-radius: 4px;"
        "  background: #ffffff; }"
        "QTabBar::tab {"
        "  background: #eef0f7; color: #555577;"
        "  border: 1px solid #d0d4e8;"
        "  border-bottom: none;"
        "  padding: 5px 14px;"
        "  font-size: 11px; }"
        "QTabBar::tab:selected {"
        "  background: #ffffff; color: #1a1a3e;"
        "  font-weight: bold;"
        "  border-bottom: 2px solid #3355cc; }"
        "QTabBar::tab:hover { background: #dce3ff; }");

    auto* bl_tab = new QWidget(tab_widget_);
    setupBlacklistTab(bl_tab);
    tab_widget_->addTab(bl_tab, "🔴  Blacklist");

    auto* wl_tab = new QWidget(tab_widget_);
    setupWhitelistTab(wl_tab);
    tab_widget_->addTab(wl_tab, "🟢  Whitelist");

    root->addWidget(tab_widget_, 1);

    setupQuickActions(root);
}

// ─── Table stylesheet helper ──────────────────────────────────────────────────
static QString tableStyle() {
    return
        "QTableWidget {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #d0d4e8;"
        "  gridline-color: #e8eaf4;"
        "  font-size: 11px; }"
        "QTableWidget::item { padding: 2px 6px; border: none; }"
        "QTableWidget::item:selected {"
        "  background: #dce3ff; color: #0a0a6e; }"
        "QTableWidget::item:hover { background: #eef0ff; }"
        "QHeaderView::section {"
        "  background: #eef0f7; color: #333366;"
        "  border: none;"
        "  border-right: 1px solid #d0d4e8;"
        "  border-bottom: 2px solid #b0b8d8;"
        "  padding: 3px 6px;"
        "  font-size: 10px; font-weight: bold; }"
        "QHeaderView::section:last { border-right: none; }"
        "QScrollBar:vertical   { background: #f0f1f8; width: 8px; }"
        "QScrollBar:horizontal { background: #f0f1f8; height: 8px; }"
        "QScrollBar::handle:vertical   { background: #b0b8d8;"
        "  border-radius: 4px; min-height: 20px; }"
        "QScrollBar::handle:horizontal { background: #b0b8d8;"
        "  border-radius: 4px; min-width: 20px; }"
        "QScrollBar::add-line, QScrollBar::sub-line { height:0; width:0; }";
}

static QString inputStyle(const QString& focus_border = "#3355cc") {
    return QString(
        "QLineEdit {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #b0b8d8; border-radius: 4px;"
        "  padding: 3px 8px; font-size: 11px; }"
        "QLineEdit:focus { border-color: %1; }"
        "QLineEdit:disabled { background: #f0f0f8; color: #aaaacc; }").arg(focus_border);
}

// ─── setupBlacklistTab ────────────────────────────────────────────────────────
void FirewallWidget::setupBlacklistTab(QWidget* parent) {
    auto* layout = new QVBoxLayout(parent);
    layout->setSpacing(6);
    layout->setContentsMargins(6, 6, 6, 6);

    bl_table_ = new QTableWidget(0, BL_COL_COUNT, parent);
    bl_table_->setHorizontalHeaderLabels(
        {"IP Address", "Proto", "Comment", "TTL", "Source", ""});
    bl_table_->horizontalHeader()->setSectionResizeMode(
        BL_IP,      QHeaderView::Stretch);
    bl_table_->horizontalHeader()->setSectionResizeMode(
        BL_PROTO,   QHeaderView::ResizeToContents);
    bl_table_->horizontalHeader()->setSectionResizeMode(
        BL_COMMENT, QHeaderView::Stretch);
    bl_table_->horizontalHeader()->setSectionResizeMode(
        BL_TTL,     QHeaderView::ResizeToContents);
    bl_table_->horizontalHeader()->setSectionResizeMode(
        BL_SOURCE,  QHeaderView::ResizeToContents);
    bl_table_->horizontalHeader()->setSectionResizeMode(
        BL_ACTION,  QHeaderView::Fixed);
    bl_table_->setColumnWidth(BL_ACTION, 60);
    bl_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    bl_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    bl_table_->setAlternatingRowColors(false);
    bl_table_->verticalHeader()->hide();
    bl_table_->setStyleSheet(tableStyle());
    layout->addWidget(bl_table_, 1);

    // ── Add row ───────────────────────────────────────────────────────────────
    auto* add_row    = new QWidget(parent);
    add_row->setStyleSheet(
        "QWidget { background: #eef0f7;"
        "          border: 1px solid #d0d4e8; border-radius: 4px; }");
    auto* add_layout = new QHBoxLayout(add_row);
    add_layout->setContentsMargins(8, 5, 8, 5);
    add_layout->setSpacing(6);

    bl_ip_input_ = new QLineEdit(add_row);
    bl_ip_input_->setPlaceholderText("IP / CIDR  (e.g. 192.168.1.1)");
    bl_ip_input_->setStyleSheet(inputStyle("#cc2222"));

    bl_comment_ = new QLineEdit(add_row);
    bl_comment_->setPlaceholderText("Comment (optional)");
    bl_comment_->setFixedWidth(130);
    bl_comment_->setStyleSheet(inputStyle());

    bl_perm_btn_ = new QPushButton("⏱ TTL 10m", add_row);
    bl_perm_btn_->setFixedSize(84, 26);
    bl_perm_btn_->setCheckable(true);
    bl_perm_btn_->setStyleSheet(
        "QPushButton {"
        "  background: #eef0f7; color: #227744;"
        "  border: 1px solid #a5d6a7; border-radius: 4px;"
        "  font-size: 10px; }"
        "QPushButton:checked {"
        "  background: #fff0f0; color: #cc2222;"
        "  border-color: #f0b8b8; }"
        "QPushButton:hover { opacity: 0.85; }");
    connect(bl_perm_btn_, &QPushButton::toggled, this, [this](bool checked) {
        bl_permanent_ = checked;
        bl_perm_btn_->setText(checked ? "🔒 Perm" : "⏱ TTL 10m");
    });

    btn_block_ = new QPushButton("⛔ Block", add_row);
    btn_block_->setFixedSize(72, 26);
    btn_block_->setStyleSheet(
        "QPushButton {"
        "  background: #fff0f0; color: #cc2222;"
        "  border: 1px solid #f0b8b8; border-radius: 4px;"
        "  font-size: 11px; font-weight: bold; }"
        "QPushButton:hover   { background: #ffe0e0; border-color: #cc2222; }"
        "QPushButton:pressed { background: #ffd0d0; }"
        "QPushButton:disabled { background: #f8f8f8; color: #aaaacc;"
        "                       border-color: #d8d8ee; }");
    connect(btn_block_, &QPushButton::clicked,
            this, &FirewallWidget::onBlockClicked);

    add_layout->addWidget(bl_ip_input_, 1);
    add_layout->addWidget(bl_comment_);
    add_layout->addWidget(bl_perm_btn_);
    add_layout->addWidget(btn_block_);
    layout->addWidget(add_row);
}

// ─── setupWhitelistTab ────────────────────────────────────────────────────────
void FirewallWidget::setupWhitelistTab(QWidget* parent) {
    auto* layout = new QVBoxLayout(parent);
    layout->setSpacing(6);
    layout->setContentsMargins(6, 6, 6, 6);

    wl_table_ = new QTableWidget(0, WL_COL_COUNT, parent);
    wl_table_->setHorizontalHeaderLabels({"IP Address", "Comment", ""});
    wl_table_->horizontalHeader()->setSectionResizeMode(
        WL_IP,      QHeaderView::Stretch);
    wl_table_->horizontalHeader()->setSectionResizeMode(
        WL_COMMENT, QHeaderView::Stretch);
    wl_table_->horizontalHeader()->setSectionResizeMode(
        WL_ACTION,  QHeaderView::Fixed);
    wl_table_->setColumnWidth(WL_ACTION, 60);
    wl_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    wl_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    wl_table_->setAlternatingRowColors(false);
    wl_table_->verticalHeader()->hide();
    wl_table_->setStyleSheet(tableStyle());
    layout->addWidget(wl_table_, 1);

    // ── Add row ───────────────────────────────────────────────────────────────
    auto* add_row    = new QWidget(parent);
    add_row->setStyleSheet(
        "QWidget { background: #eef0f7;"
        "          border: 1px solid #d0d4e8; border-radius: 4px; }");
    auto* add_layout = new QHBoxLayout(add_row);
    add_layout->setContentsMargins(8, 5, 8, 5);
    add_layout->setSpacing(6);

    wl_ip_input_ = new QLineEdit(add_row);
    wl_ip_input_->setPlaceholderText("IP / CIDR  (e.g. 10.0.0.1)");
    wl_ip_input_->setStyleSheet(inputStyle("#227744"));

    wl_comment_ = new QLineEdit(add_row);
    wl_comment_->setPlaceholderText("Comment (optional)");
    wl_comment_->setFixedWidth(150);
    wl_comment_->setStyleSheet(inputStyle());

    btn_allow_ = new QPushButton("✅ Allow", add_row);
    btn_allow_->setFixedSize(72, 26);
    btn_allow_->setStyleSheet(
        "QPushButton {"
        "  background: #f0fff4; color: #227744;"
        "  border: 1px solid #a5d6a7; border-radius: 4px;"
        "  font-size: 11px; font-weight: bold; }"
        "QPushButton:hover   { background: #c8e6c9; border-color: #388e3c; }"
        "QPushButton:pressed { background: #b2dfdb; }"
        "QPushButton:disabled { background: #f8f8f8; color: #aaaacc;"
        "                       border-color: #d8d8ee; }");
    connect(btn_allow_, &QPushButton::clicked,
            this, &FirewallWidget::onAllowClicked);

    add_layout->addWidget(wl_ip_input_, 1);
    add_layout->addWidget(wl_comment_);
    add_layout->addWidget(btn_allow_);
    layout->addWidget(add_row);
}

// ─── setupQuickActions ────────────────────────────────────────────────────────
void FirewallWidget::setupQuickActions(QVBoxLayout* root) {
    auto* row    = new QWidget(this);
    row->setStyleSheet("QWidget { background: transparent; }");
    auto* layout = new QHBoxLayout(row);
    layout->setContentsMargins(0, 2, 0, 0);
    layout->setSpacing(5);

    const QString btn_style =
        "QPushButton {"
        "  background: #eef0f7; color: #3355cc;"
        "  border: 1px solid #c0c8e8; border-radius: 4px;"
        "  font-size: 10px; padding: 4px 10px; }"
        "QPushButton:hover   { background: #dce3ff; border-color: #3355cc; }"
        "QPushButton:pressed { background: #c8d0f8; }"
        "QPushButton:disabled { color: #aaaacc; border-color: #d8d8ee; }";

    btn_refresh_ = new QPushButton("🔄  Refresh",        row);
    btn_flush_   = new QPushButton("🗑  Flush Blacklist", row);
    btn_save_    = new QPushButton("💾  Save Rules",      row);

    btn_refresh_->setStyleSheet(btn_style);
    btn_flush_  ->setStyleSheet(btn_style);
    btn_save_   ->setStyleSheet(btn_style);

    connect(btn_refresh_, &QPushButton::clicked,
            this, &FirewallWidget::refresh);
    connect(btn_flush_,   &QPushButton::clicked,
            this, &FirewallWidget::onFlushBlacklist);
    connect(btn_save_,    &QPushButton::clicked,
            this, &FirewallWidget::onSaveRules);

    layout->addWidget(btn_refresh_);
    layout->addWidget(btn_flush_);
    layout->addStretch();
    layout->addWidget(btn_save_);
    root->addWidget(row);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Slots — Button actions
// ═══════════════════════════════════════════════════════════════════════════════

void FirewallWidget::onBlockClicked() {
    if (!fw_) return;

    const QString ip = bl_ip_input_->text().trimmed();
    if (ip.isEmpty()) {
        emit statusMessage("⚠️  Please enter an IP address to block.");
        return;
    }

    const std::string comment = bl_comment_->text().trimmed().toStdString();
    const uint64_t id = fw_->manualBlock(
        ip.toStdString(), 0, 0,
        bl_permanent_,
        bl_permanent_ ? 0 : 600,
        comment.empty() ? "Manual block" : comment);

    if (id == 0) {
        emit statusMessage(
            QString("⚠️  Failed to block %1 (already exists or invalid IP)")
                .arg(ip));
        return;
    }

    bl_ip_input_->clear();
    bl_comment_ ->clear();
    emit statusMessage(QString("⛔  Blocked: %1%2")
        .arg(ip)
        .arg(bl_permanent_ ? " [permanent]" : " [TTL 10m]"));
}

void FirewallWidget::onAllowClicked() {
    if (!fw_) return;

    const QString ip = wl_ip_input_->text().trimmed();
    if (ip.isEmpty()) {
        emit statusMessage("⚠️  Please enter an IP address to whitelist.");
        return;
    }

    const std::string comment = wl_comment_->text().trimmed().toStdString();
    const uint64_t id = fw_->addWhitelist(
        ip.toStdString(),
        comment.empty() ? "Manual whitelist" : comment);

    if (id == 0) {
        emit statusMessage(
            QString("⚠️  Failed to whitelist %1 (already exists or invalid IP)")
                .arg(ip));
        return;
    }

    wl_ip_input_->clear();
    wl_comment_ ->clear();
    emit statusMessage(QString("✅  Whitelisted: %1").arg(ip));
}

void FirewallWidget::onFlushBlacklist() {
    if (!fw_) return;

    const auto ans = QMessageBox::question(
        this, "Flush Blacklist",
        "Remove ALL blacklist rules?\n(Whitelist rules will be kept)",
        QMessageBox::Yes | QMessageBox::No);
    if (ans != QMessageBox::Yes) return;

    const auto rules = fw_->listBlacklist();
    for (const auto& r : rules)
        fw_->removeRule(r.id);

    emit statusMessage(
        QString("🗑  Flushed %1 blacklist rule(s)").arg(rules.size()));
    refresh();
}

void FirewallWidget::onSaveRules() {
    if (!fw_) return;

    const QString path = QFileDialog::getSaveFileName(
        this, "Save Firewall Rules",
        QString(RULES_PATH),
        "JSON Files (*.json);;All Files (*)");
    if (path.isEmpty()) return;

    if (fw_->saveRules(path.toStdString()))
        emit statusMessage(QString("💾  Rules saved → %1").arg(path));
    else
        emit statusMessage(QString("❌  Failed to save rules → %1").arg(path));
}

void FirewallWidget::onRemoveBlacklistRow(int row) {
    if (!fw_ || row < 0 || row >= bl_table_->rowCount()) return;

    const uint64_t rule_id = bl_table_->item(row, BL_IP)
                                ->data(Qt::UserRole).toULongLong();
    if (fw_->removeRule(rule_id))
        emit statusMessage(
            QString("✅  Removed blacklist rule #%1").arg(rule_id));
}

void FirewallWidget::onRemoveWhitelistRow(int row) {
    if (!fw_ || row < 0 || row >= wl_table_->rowCount()) return;

    const QString ip = wl_table_->item(row, WL_IP)->text();
    if (fw_->removeWhitelist(ip.toStdString()))
        emit statusMessage(QString("✅  Removed whitelist: %1").arg(ip));
    refresh();
}

// ═══════════════════════════════════════════════════════════════════════════════
// refresh / onRuleChanged
// ═══════════════════════════════════════════════════════════════════════════════

void FirewallWidget::refresh() {
    if (!fw_) return;
    refreshBlacklist();
    refreshWhitelist();
    updateStatsBadge();
}

void FirewallWidget::onRuleChanged(const FirewallRule& /*rule*/,
                                    bool               /*added*/) {
    refresh();
}

// ─── refreshBlacklist ─────────────────────────────────────────────────────────
void FirewallWidget::refreshBlacklist() {
    const auto rules = fw_->listBlacklist();

    bl_table_->setUpdatesEnabled(false);
    bl_table_->setRowCount(0);
    bl_table_->setRowCount(static_cast<int>(rules.size()));

    for (int i = 0; i < static_cast<int>(rules.size()); ++i) {
        const auto& r = rules[i];

        // ── IP ────────────────────────────────────────────────────────────────
        auto* ip_item = makeItem(QString::fromStdString(r.src_ip));
        ip_item->setData(Qt::UserRole, static_cast<qulonglong>(r.id));
        ip_item->setForeground(QColor("#cc2222"));
        bl_table_->setItem(i, BL_IP, ip_item);

        // ── Protocol ──────────────────────────────────────────────────────────
        bl_table_->setItem(i, BL_PROTO,
            makeItem(protocolName(r.protocol),
                     Qt::AlignCenter | Qt::AlignVCenter));

        // ── Comment ───────────────────────────────────────────────────────────
        auto* cmt_item = makeItem(QString::fromStdString(r.comment));
        cmt_item->setForeground(QColor("#666688"));
        bl_table_->setItem(i, BL_COMMENT, cmt_item);

        // ── TTL ───────────────────────────────────────────────────────────────
        const QString ttl_str = r.permanent
            ? "∞ Permanent"
            : formatTtl(r.ttl_sec, r.created_at);
        auto* ttl_item = makeItem(ttl_str,
                                   Qt::AlignCenter | Qt::AlignVCenter);
        ttl_item->setForeground(r.permanent
            ? QColor("#cc2222") : QColor("#cc6600"));
        bl_table_->setItem(i, BL_TTL, ttl_item);

        // ── Source ────────────────────────────────────────────────────────────
        const bool is_auto = (r.source == FirewallRule::Source::AUTO);
        const QString src  = is_auto ? "🤖 Auto" : "👤 Manual";
        auto* src_item = makeItem(src, Qt::AlignCenter | Qt::AlignVCenter);
        src_item->setForeground(QColor(is_auto ? "#3355cc" : "#666688"));
        bl_table_->setItem(i, BL_SOURCE, src_item);

        // ── Remove button ─────────────────────────────────────────────────────
        auto* btn = new QPushButton("✕", bl_table_);
        btn->setFixedSize(42, 20);
        btn->setStyleSheet(
            "QPushButton {"
            "  background: #fff0f0; color: #cc2222;"
            "  border: 1px solid #f0b8b8; border-radius: 3px;"
            "  font-size: 11px; }"
            "QPushButton:hover { background: #ffe0e0; border-color: #cc2222; }");
        const int row_idx = i;
        connect(btn, &QPushButton::clicked,
                this, [this, row_idx]() { onRemoveBlacklistRow(row_idx); });
        bl_table_->setCellWidget(i, BL_ACTION, btn);

        // Row tint nhẹ theo loại
        const QColor row_bg = r.permanent
            ? QColor("#fff8f8")   // permanent → đỏ rất nhạt
            : QColor("#ffffff");
        for (int col = 0; col < BL_ACTION; ++col)
            if (auto* item = bl_table_->item(i, col))
                item->setBackground(row_bg);

        bl_table_->setRowHeight(i, 22);
    }

    bl_table_->setUpdatesEnabled(true);
}

// ─── refreshWhitelist ─────────────────────────────────────────────────────────
void FirewallWidget::refreshWhitelist() {
    const auto rules = fw_->listWhitelist();

    wl_table_->setUpdatesEnabled(false);
    wl_table_->setRowCount(0);
    wl_table_->setRowCount(static_cast<int>(rules.size()));

    for (int i = 0; i < static_cast<int>(rules.size()); ++i) {
        const auto& r = rules[i];

        auto* ip_item = makeItem(QString::fromStdString(r.src_ip));
        ip_item->setForeground(QColor("#227744"));
        wl_table_->setItem(i, WL_IP, ip_item);

        auto* cmt_item = makeItem(QString::fromStdString(r.comment));
        cmt_item->setForeground(QColor("#666688"));
        wl_table_->setItem(i, WL_COMMENT, cmt_item);

        auto* btn = new QPushButton("✕", wl_table_);
        btn->setFixedSize(42, 20);
        btn->setStyleSheet(
            "QPushButton {"
            "  background: #f0fff4; color: #227744;"
            "  border: 1px solid #a5d6a7; border-radius: 3px;"
            "  font-size: 11px; }"
            "QPushButton:hover { background: #c8e6c9; border-color: #388e3c; }");
        const int row_idx = i;
        connect(btn, &QPushButton::clicked,
                this, [this, row_idx]() { onRemoveWhitelistRow(row_idx); });
        wl_table_->setCellWidget(i, WL_ACTION, btn);

        wl_table_->setRowHeight(i, 22);
    }

    wl_table_->setUpdatesEnabled(true);
}

// ─── updateStatsBadge ─────────────────────────────────────────────────────────
void FirewallWidget::updateStatsBadge() {
    if (!fw_) {
        lbl_stats_badge_->setText("🔴 Blacklist: —   🟢 Whitelist: —");
        return;
    }
    lbl_stats_badge_->setText(
        QString("🔴 Blacklist: %1   🟢 Whitelist: %2")
            .arg(fw_->blacklistSize())
            .arg(fw_->whitelistSize()));
}

// ─── setControlsEnabled ───────────────────────────────────────────────────────
void FirewallWidget::setControlsEnabled(bool enabled) {
    btn_block_  ->setEnabled(enabled);
    btn_allow_  ->setEnabled(enabled);
    btn_refresh_->setEnabled(enabled);
    btn_flush_  ->setEnabled(enabled);
    btn_save_   ->setEnabled(enabled);
    bl_ip_input_->setEnabled(enabled);
    bl_comment_ ->setEnabled(enabled);
    bl_perm_btn_->setEnabled(enabled);
    wl_ip_input_->setEnabled(enabled);
    wl_comment_ ->setEnabled(enabled);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Static helpers
// ═══════════════════════════════════════════════════════════════════════════════

QString FirewallWidget::protocolName(uint8_t proto) {
    switch (proto) {
        case  0: return "ANY";
        case  1: return "ICMP";
        case  6: return "TCP";
        case 17: return "UDP";
        default: return QString::number(proto);
    }
}

QString FirewallWidget::formatTtl(uint32_t ttl_sec, uint64_t created_at) {
    if (ttl_sec == 0) return "∞";

    const uint64_t now     = static_cast<uint64_t>(std::time(nullptr));
    const uint64_t expires = created_at + ttl_sec;

    if (expires <= now) return "⌛ Expired";

    const uint64_t remaining = expires - now;
    if (remaining >= 3600)
        return QString("%1h %2m")
            .arg(remaining / 3600)
            .arg((remaining % 3600) / 60);
    if (remaining >= 60)
        return QString("%1m %2s")
            .arg(remaining / 60)
            .arg(remaining % 60);
    return QString("%1s").arg(remaining);
}

QTableWidgetItem* FirewallWidget::makeItem(const QString& text,
                                            Qt::Alignment  align) {
    auto* item = new QTableWidgetItem(text);
    item->setTextAlignment(align);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    return item;
}
