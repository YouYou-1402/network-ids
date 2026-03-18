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

// ═══════════════════════════════════════════════════════════════════════════════
// Constructor / setFirewallManager
// ═══════════════════════════════════════════════════════════════════════════════

FirewallWidget::FirewallWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
    setControlsEnabled(false);
}

void FirewallWidget::setFirewallManager(FirewallManager* fw) {
    fw_ = fw;
    setControlsEnabled(fw_ != nullptr);
    if (!fw_) return;

    // ── RuleChangeCallback → marshal về main thread ───────────────────────────
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
    root->setSpacing(5);
    root->setContentsMargins(6, 6, 6, 6);

    // ── Stats badge ───────────────────────────────────────────────────────────
    lbl_stats_badge_ = new QLabel("🔴 Blacklist: 0   🟢 Whitelist: 0", this);
    lbl_stats_badge_->setAlignment(Qt::AlignCenter);
    lbl_stats_badge_->setFixedHeight(26);
    lbl_stats_badge_->setStyleSheet(
        "QLabel { background: #0d0d1a; color: #aaaacc; "
        "font-size: 11px; font-weight: bold; "
        "border: 1px solid #2a2a3e; border-radius: 4px; "
        "padding: 2px 6px; }");
    root->addWidget(lbl_stats_badge_);

    // ── Tab widget ────────────────────────────────────────────────────────────
    tab_widget_ = new QTabWidget(this);
    tab_widget_->setStyleSheet(
        "QTabWidget::pane  { border: 1px solid #2a2a3e; background: #0d0d1a; }"
        "QTabBar::tab      { background: #1a1a2e; color: #888899; "
        "                    border: 1px solid #2a2a3e; padding: 4px 10px; }"
        "QTabBar::tab:selected { background: #1e1e35; color: #ffffff; "
        "                        border-bottom: 2px solid #ff4444; }"
        "QTabBar::tab:hover    { background: #222238; }");

    auto* bl_tab = new QWidget(tab_widget_);
    setupBlacklistTab(bl_tab);
    tab_widget_->addTab(bl_tab, "🔴 Blacklist");

    auto* wl_tab = new QWidget(tab_widget_);
    setupWhitelistTab(wl_tab);
    tab_widget_->addTab(wl_tab, "🟢 Whitelist");

    root->addWidget(tab_widget_, 1);

    setupQuickActions(root);
}

// ─── setupBlacklistTab ────────────────────────────────────────────────────────
void FirewallWidget::setupBlacklistTab(QWidget* parent) {
    auto* layout = new QVBoxLayout(parent);
    layout->setSpacing(4);
    layout->setContentsMargins(4, 4, 4, 4);

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
    bl_table_->setAlternatingRowColors(true);
    bl_table_->verticalHeader()->hide();
    bl_table_->setStyleSheet(
        "QTableWidget { background: #0d0d1a; color: #cccccc; "
        "gridline-color: #1e1e2e; font-size: 11px; "
        "alternate-background-color: #111120; }"
        "QHeaderView::section { background: #1a1a2e; color: #8888aa; "
        "border: 1px solid #2a2a3e; padding: 3px; font-size: 10px; }"
        "QTableWidget::item:selected { background: #2a1a1a; color: #ff8888; }");
    layout->addWidget(bl_table_, 1);

    // ── Add row ───────────────────────────────────────────────────────────────
    auto* add_row    = new QWidget(parent);
    auto* add_layout = new QHBoxLayout(add_row);
    add_layout->setContentsMargins(0, 0, 0, 0);
    add_layout->setSpacing(4);

    bl_ip_input_ = new QLineEdit(add_row);
    bl_ip_input_->setPlaceholderText("IP / CIDR  (e.g. 192.168.1.1)");
    bl_ip_input_->setStyleSheet(
        "QLineEdit { background: #1a1a2e; color: #cccccc; "
        "border: 1px solid #333355; border-radius: 3px; "
        "padding: 3px 6px; font-size: 11px; }"
        "QLineEdit:focus { border-color: #ff4444; }");

    bl_comment_ = new QLineEdit(add_row);
    bl_comment_->setPlaceholderText("Comment (optional)");
    bl_comment_->setFixedWidth(120);
    bl_comment_->setStyleSheet(bl_ip_input_->styleSheet());

    bl_perm_btn_ = new QPushButton("⏱ TTL 10m", add_row);
    bl_perm_btn_->setFixedSize(80, 26);
    bl_perm_btn_->setCheckable(true);
    bl_perm_btn_->setStyleSheet(
        "QPushButton { background: #1a2a1a; color: #88cc88; "
        "border: 1px solid #336633; border-radius: 3px; font-size: 10px; }"
        "QPushButton:checked { background: #2a1a1a; color: #ff8888; "
        "border-color: #663333; }"
        "QPushButton:hover { opacity: 0.85; }");
    connect(bl_perm_btn_, &QPushButton::toggled, this, [this](bool checked) {
        bl_permanent_ = checked;
        bl_perm_btn_->setText(checked ? "🔒 Perm" : "⏱ TTL 10m");
    });

    btn_block_ = new QPushButton("⛔ Block", add_row);
    btn_block_->setFixedSize(70, 26);
    btn_block_->setStyleSheet(
        "QPushButton { background: #3a1010; color: #ff6666; "
        "border: 1px solid #662222; border-radius: 3px; "
        "font-size: 11px; font-weight: bold; }"
        "QPushButton:hover { background: #4a1818; }"
        "QPushButton:disabled { background: #1a1a1a; color: #444444; "
        "border-color: #333333; }");
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
    layout->setSpacing(4);
    layout->setContentsMargins(4, 4, 4, 4);

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
    wl_table_->setAlternatingRowColors(true);
    wl_table_->verticalHeader()->hide();
    wl_table_->setStyleSheet(
        "QTableWidget { background: #0d0d1a; color: #cccccc; "
        "gridline-color: #1e1e2e; font-size: 11px; "
        "alternate-background-color: #111120; }"
        "QHeaderView::section { background: #1a1a2e; color: #8888aa; "
        "border: 1px solid #2a2a3e; padding: 3px; font-size: 10px; }"
        "QTableWidget::item:selected { background: #1a2a1a; color: #88ff88; }");
    layout->addWidget(wl_table_, 1);

    auto* add_row    = new QWidget(parent);
    auto* add_layout = new QHBoxLayout(add_row);
    add_layout->setContentsMargins(0, 0, 0, 0);
    add_layout->setSpacing(4);

    wl_ip_input_ = new QLineEdit(add_row);
    wl_ip_input_->setPlaceholderText("IP / CIDR  (e.g. 10.0.0.1)");
    wl_ip_input_->setStyleSheet(
        "QLineEdit { background: #1a1a2e; color: #cccccc; "
        "border: 1px solid #333355; border-radius: 3px; "
        "padding: 3px 6px; font-size: 11px; }"
        "QLineEdit:focus { border-color: #00cc66; }");

    wl_comment_ = new QLineEdit(add_row);
    wl_comment_->setPlaceholderText("Comment (optional)");
    wl_comment_->setFixedWidth(140);
    wl_comment_->setStyleSheet(wl_ip_input_->styleSheet());

    btn_allow_ = new QPushButton("✅ Allow", add_row);
    btn_allow_->setFixedSize(70, 26);
    btn_allow_->setStyleSheet(
        "QPushButton { background: #0d2a0d; color: #00ff88; "
        "border: 1px solid #1a5a1a; border-radius: 3px; "
        "font-size: 11px; font-weight: bold; }"
        "QPushButton:hover { background: #1a3a1a; }"
        "QPushButton:disabled { background: #1a1a1a; color: #444444; "
        "border-color: #333333; }");
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
    auto* layout = new QHBoxLayout(row);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(4);

    const QString btn_style =
        "QPushButton { background: #1a1a2e; color: #8888cc; "
        "border: 1px solid #2a2a4e; border-radius: 3px; "
        "font-size: 10px; padding: 3px 8px; }"
        "QPushButton:hover { background: #222240; color: #aaaaee; }"
        "QPushButton:disabled { color: #444444; border-color: #222222; }";

    btn_refresh_ = new QPushButton("🔄 Refresh", row);
    btn_flush_   = new QPushButton("🗑 Flush Blacklist", row);
    btn_save_    = new QPushButton("💾 Save Rules", row);

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
        ip.toStdString(),
        0,
        0,
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
        ip_item->setForeground(QColor("#ff8888"));
        bl_table_->setItem(i, BL_IP, ip_item);

        // ── Protocol ──────────────────────────────────────────────────────────
        bl_table_->setItem(i, BL_PROTO,
            makeItem(protocolName(r.protocol),
                     Qt::AlignCenter | Qt::AlignVCenter));

        // ── Comment ───────────────────────────────────────────────────────────
        // field name: comment (theo firewall_rule.hpp chuẩn hóa ở trên)
        auto* cmt_item = makeItem(QString::fromStdString(r.comment));
        cmt_item->setForeground(QColor("#aaaacc"));
        bl_table_->setItem(i, BL_COMMENT, cmt_item);

        // ── TTL ───────────────────────────────────────────────────────────────
        const QString ttl_str = r.permanent
            ? "∞ Permanent"
            : formatTtl(r.ttl_sec, r.created_at);
        auto* ttl_item = makeItem(ttl_str,
                                   Qt::AlignCenter | Qt::AlignVCenter);
        ttl_item->setForeground(r.permanent
            ? QColor("#ff6666") : QColor("#ffaa44"));
        bl_table_->setItem(i, BL_TTL, ttl_item);

        // ── Source ────────────────────────────────────────────────────────────
        const bool is_auto = (r.source == FirewallRule::Source::AUTO);
        const QString src  = is_auto ? "🤖 Auto" : "👤 Manual";
        auto* src_item = makeItem(src, Qt::AlignCenter | Qt::AlignVCenter);
        src_item->setForeground(QColor(is_auto ? "#44aaff" : "#aaaaaa"));
        bl_table_->setItem(i, BL_SOURCE, src_item);

        // ── Remove button ─────────────────────────────────────────────────────
        auto* btn = new QPushButton("✕", bl_table_);
        btn->setFixedSize(40, 20);
        btn->setStyleSheet(
            "QPushButton { background: #3a1010; color: #ff6666; "
            "border: 1px solid #552222; border-radius: 2px; font-size: 11px; }"
            "QPushButton:hover { background: #4a1818; }");
        const int row_idx = i;
        connect(btn, &QPushButton::clicked,
                this, [this, row_idx]() { onRemoveBlacklistRow(row_idx); });
        bl_table_->setCellWidget(i, BL_ACTION, btn);

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
        ip_item->setForeground(QColor("#88ff88"));
        wl_table_->setItem(i, WL_IP, ip_item);

        // ── Comment ───────────────────────────────────────────────────────────
        auto* cmt_item = makeItem(QString::fromStdString(r.comment));
        cmt_item->setForeground(QColor("#aaaacc"));
        wl_table_->setItem(i, WL_COMMENT, cmt_item);

        auto* btn = new QPushButton("✕", wl_table_);
        btn->setFixedSize(40, 20);
        btn->setStyleSheet(
            "QPushButton { background: #102a10; color: #66ff66; "
            "border: 1px solid #225522; border-radius: 2px; font-size: 11px; }"
            "QPushButton:hover { background: #183a18; }");
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
