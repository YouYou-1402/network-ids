#include "firewall_widget.hpp"
#include "../../common/logger.hpp"

#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QDir>
#include <ctime>

// ════════════════════════════════════════════════════════════════════════════
// Style helpers
// ════════════════════════════════════════════════════════════════════════════

namespace {

const char* kTableStyle =
    "QTableWidget {"
    "  background:#ffffff; color:#1a1a3e;"
    "  border:1px solid #d0d4e8; gridline-color:#eef0f8;"
    "  font-size:12px; outline:none; }"
    "QTableWidget::item { padding:3px 8px; border:none; }"
    "QTableWidget::item:selected { background:#dce3ff; color:#0a0a6e; }"
    "QTableWidget::item:hover    { background:#f0f2ff; }"
    "QHeaderView::section {"
    "  background:#eef0f7; color:#333366;"
    "  border:none; border-right:1px solid #d0d4e8;"
    "  border-bottom:2px solid #b0b8d8;"
    "  padding:4px 8px; font-size:11px; font-weight:bold; }"
    "QScrollBar:vertical   { background:#f0f1f8; width:8px; border:none; }"
    "QScrollBar:horizontal { background:#f0f1f8; height:8px; border:none; }"
    "QScrollBar::handle    { background:#b0b8d8; border-radius:4px; min-height:20px; }"
    "QScrollBar::add-line,QScrollBar::sub-line { height:0; width:0; }";

const char* kInputStyle =
    "QLineEdit {"
    "  background:#ffffff; color:#1a1a3e;"
    "  border:1px solid #b0b8d8; border-radius:5px;"
    "  padding:4px 10px; font-size:12px; }"
    "QLineEdit:focus   { border-color:#3355cc; }"
    "QLineEdit:disabled{ background:#f4f4f8; color:#aaaacc; }";

const char* kComboStyle =
    "QComboBox {"
    "  background:#ffffff; color:#1a1a3e;"
    "  border:1px solid #b0b8d8; border-radius:5px;"
    "  padding:3px 8px; font-size:12px; }"
    "QComboBox:focus { border-color:#3355cc; }"
    "QComboBox::drop-down { border:none; width:20px; }"
    "QComboBox QAbstractItemView {"
    "  background:#fff; color:#1a1a3e;"
    "  selection-background-color:#dce3ff; }";

const char* kSpinStyle =
    "QSpinBox {"
    "  background:#ffffff; color:#1a1a3e;"
    "  border:1px solid #b0b8d8; border-radius:5px;"
    "  padding:3px 6px; font-size:12px; }"
    "QSpinBox:focus    { border-color:#3355cc; }"
    "QSpinBox:disabled { background:#f4f4f8; color:#aaaacc; }";

const char* kCheckStyle =
    "QCheckBox { font-size:12px; color:#1a1a3e; spacing:5px; }"
    "QCheckBox::indicator {"
    "  width:16px; height:16px;"
    "  border:1px solid #b0b8d8; border-radius:3px; background:#fff; }"
    "QCheckBox::indicator:checked {"
    "  background:#cc2222; border-color:#cc2222; }";

QString btnStyle(const QString& bg,  const QString& fg,
                 const QString& bdr, const QString& hov) {
    return QString(
        "QPushButton {"
        "  background:%1; color:%2;"
        "  border:1px solid %3; border-radius:5px;"
        "  padding:5px 14px; font-size:12px; font-weight:bold; }"
        "QPushButton:hover    { background:%4; }"
        "QPushButton:pressed  { background:%4; border-color:%2; }"
        "QPushButton:disabled {"
        "  background:#f4f4f8; color:#aaaacc; border-color:#d8d8ee; }")
        .arg(bg, fg, bdr, hov);
}

} // namespace

// ════════════════════════════════════════════════════════════════════════════
// Constructor
// ════════════════════════════════════════════════════════════════════════════

FirewallWidget::FirewallWidget(QWidget* parent) : QWidget(parent) {
    setStyleSheet("QWidget { background:#f5f6fa; color:#1a1a3e; }");
    setupUI();
    setControlsEnabled(false);   // disabled cho đến khi setFirewallManager()

    ttl_timer_ = new QTimer(this);
    ttl_timer_->setInterval(10'000);   // cập nhật TTL mỗi 10 giây
    connect(ttl_timer_, &QTimer::timeout,
            this, &FirewallWidget::onTtlTimerTick);
}

// ════════════════════════════════════════════════════════════════════════════
// setFirewallManager  ← điểm kết nối chính
// ════════════════════════════════════════════════════════════════════════════

void FirewallWidget::setFirewallManager(FirewallManager* fw) {
    fw_ = fw;

    if (!fw_) {
        setControlsEnabled(false);
        lbl_backend_->setText("  ⚠️ No backend  ");
        lbl_backend_->setStyleSheet(
            "color:#884400; background:#fff4e0;"
            "border:1px solid #ddaa44; border-radius:4px;"
            "padding:2px 8px; font-size:11px;");
        return;
    }

    // ── Hiển thị backend ──────────────────────────────────────────────────────
    const QString bname = QString::fromStdString(fw_->backendName());
    QString bstyle;
    if (bname == "nftables")
        bstyle = "color:#116611; background:#e8f8e8;"
                 "border:1px solid #88cc88; border-radius:4px;"
                 "padding:2px 8px; font-size:11px;";
    else if (bname == "iptables")
        bstyle = "color:#114488; background:#e8eeff;"
                 "border:1px solid #88aadd; border-radius:4px;"
                 "padding:2px 8px; font-size:11px;";
    else
        bstyle = "color:#555577; background:#eef0f7;"
                 "border:1px solid #c0c8e8; border-radius:4px;"
                 "padding:2px 8px; font-size:11px;";

    lbl_backend_->setText("  🔧 " + bname + "  ");
    lbl_backend_->setStyleSheet(bstyle);

    // ── Callback khi rule thay đổi (có thể từ worker thread) ─────────────────
    fw_->setRuleChangeCallback(
        [this](const FirewallRule& /*r*/, bool /*added*/) {
            // Marshal về Qt main thread
            QMetaObject::invokeMethod(
                this,
                [this] { refresh(); },
                Qt::QueuedConnection);
        });

    // ── Enable controls ───────────────────────────────────────────────────────
    setControlsEnabled(true);

    // ── Auto-load rules nếu chưa load ────────────────────────────────────────
    if (fw_->blacklistSize() == 0 && fw_->whitelistSize() == 0) {
        if (QFile::exists(RULES_PATH)) {
            fw_->loadRules(RULES_PATH);
            LOG_INFO("FirewallWidget: auto-loaded " + std::string(RULES_PATH));
        }
    }

    // ── Hiển thị ngay ─────────────────────────────────────────────────────────
    refresh();
    ttl_timer_->start();
}

// ════════════════════════════════════════════════════════════════════════════
// setupUI
// ════════════════════════════════════════════════════════════════════════════

void FirewallWidget::setupUI() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(6);
    root->setContentsMargins(8, 8, 8, 8);

    buildHeaderBar(root);

    tabs_ = new QTabWidget(this);
    tabs_->setStyleSheet(
        "QTabWidget::pane {"
        "  border:1px solid #d0d4e8; border-radius:6px;"
        "  background:#ffffff; margin-top:-1px; }"
        "QTabBar::tab {"
        "  background:#eef0f7; color:#555577;"
        "  border:1px solid #d0d4e8; border-bottom:none;"
        "  padding:6px 22px; font-size:12px;"
        "  border-radius:4px 4px 0 0; }"
        "QTabBar::tab:selected {"
        "  background:#ffffff; color:#1a1a3e;"
        "  font-weight:bold; border-bottom:3px solid #3355cc; }"
        "QTabBar::tab:hover:!selected { background:#dce3ff; }");

    auto* bl_tab = new QWidget(tabs_);
    buildBlacklistTab(bl_tab);
    tabs_->addTab(bl_tab, "🔴  Blacklist");

    auto* wl_tab = new QWidget(tabs_);
    buildWhitelistTab(wl_tab);
    tabs_->addTab(wl_tab, "🟢  Whitelist");

    root->addWidget(tabs_, 1);
    buildQuickBar(root);
}

// ─── buildHeaderBar ───────────────────────────────────────────────────────────

void FirewallWidget::buildHeaderBar(QVBoxLayout* root) {
    auto* row = new QWidget(this);
    row->setStyleSheet("background:transparent;");
    auto* lay = new QHBoxLayout(row);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(8);

    // RESPONSIVE: tính kích thước theo font metrics
    const int em = fontMetrics().height();

    lbl_stats_ = new QLabel("🔴 Blacklist: 0   🟢 Whitelist: 0", this);
    lbl_stats_->setAlignment(Qt::AlignCenter);
    // RESPONSIVE: bỏ setFixedHeight(30) → dùng setMinimumHeight theo em
    lbl_stats_->setMinimumHeight(em * 2);
    lbl_stats_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    lbl_stats_->setStyleSheet(
        "background:#eef0f7; color:#1a1a3e;"
        "font-weight:bold;"
        "border:1px solid #d0d4e8; border-radius:5px;"
        "padding:2px 16px;");

    lbl_backend_ = new QLabel("  🔧 Backend: —  ", this);
    // RESPONSIVE: bỏ setFixedHeight(30)
    lbl_backend_->setMinimumHeight(em * 2);
    lbl_backend_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    lbl_backend_->setStyleSheet(
        "color:#555577; background:#eef0f7;"
        "border:1px solid #c0c8e8; border-radius:5px;"
        "padding:2px 8px;");

    lay->addWidget(lbl_stats_, 1);
    lay->addWidget(lbl_backend_);
    root->addWidget(row);
}

// ─── buildBlacklistTab ────────────────────────────────────────────────────────

void FirewallWidget::buildBlacklistTab(QWidget* p) {
    auto* lay = new QVBoxLayout(p);
    lay->setSpacing(6);
    lay->setContentsMargins(8, 8, 8, 8);

    // RESPONSIVE: tính kích thước theo font metrics
    const int em = fontMetrics().height();

    // Search bar
    bl_search_ = new QLineEdit(p);
    bl_search_->setPlaceholderText("🔍  Search IP / comment…");
    // RESPONSIVE: bỏ setFixedHeight(30) → dùng setMinimumHeight theo em
    bl_search_->setMinimumHeight(em * 2);
    bl_search_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    bl_search_->setStyleSheet(kInputStyle);
    bl_search_->setClearButtonEnabled(true);
    connect(bl_search_, &QLineEdit::textChanged,
            this, &FirewallWidget::onBlSearchChanged);
    lay->addWidget(bl_search_);

    // Table
    bl_table_ = new QTableWidget(0, BL_NCOLS, p);
    bl_table_->setHorizontalHeaderLabels(
        {"IP / CIDR", "Proto", "Comment", "TTL / Expires", "Source", ""});
    auto* bh = bl_table_->horizontalHeader();
    bh->setSectionResizeMode(BL_IP,    QHeaderView::Stretch);
    bh->setSectionResizeMode(BL_PROTO, QHeaderView::ResizeToContents);
    bh->setSectionResizeMode(BL_CMT,   QHeaderView::Stretch);
    bh->setSectionResizeMode(BL_TTL,   QHeaderView::ResizeToContents);
    bh->setSectionResizeMode(BL_SRC,   QHeaderView::ResizeToContents);
    bh->setSectionResizeMode(BL_DEL,   QHeaderView::Fixed);
    bl_table_->setColumnWidth(BL_DEL, 50);
    bl_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    bl_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    bl_table_->verticalHeader()->hide();
    bl_table_->setStyleSheet(kTableStyle);
    bl_table_->setSortingEnabled(true);
    bl_table_->setAlternatingRowColors(true);
    lay->addWidget(bl_table_, 1);

    // ── Add form ──────────────────────────────────────────────────────────────
    auto* form = new QFrame(p);
    form->setStyleSheet(
        "QFrame { background:#fdf0f0;"
        "  border:1px solid #f0d0d0; border-radius:6px; }");
    auto* fl = new QVBoxLayout(form);
    fl->setContentsMargins(10, 8, 10, 8);
    fl->setSpacing(6);

    // Row 1: IP + Proto + Comment
    auto* r1 = new QHBoxLayout;
    r1->setSpacing(6);

    bl_ip_ = new QLineEdit(form);
    bl_ip_->setPlaceholderText("IP / CIDR  (e.g. 192.168.1.1  or  10.0.0.0/8)");
    // RESPONSIVE: bỏ setFixedHeight(30)
    bl_ip_->setMinimumHeight(em * 2);
    bl_ip_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    bl_ip_->setStyleSheet(kInputStyle);
    connect(bl_ip_, &QLineEdit::returnPressed,
            this, &FirewallWidget::onBlockClicked);

    bl_proto_ = new QComboBox(form);
    bl_proto_->addItem("ANY",  0);
    bl_proto_->addItem("TCP",  6);
    bl_proto_->addItem("UDP",  17);
    bl_proto_->addItem("ICMP", 1);
    // RESPONSIVE: bỏ setFixedSize(72, 30)
    bl_proto_->setMinimumHeight(em * 2);
    bl_proto_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    bl_proto_->setStyleSheet(kComboStyle);

    bl_cmt_ = new QLineEdit(form);
    bl_cmt_->setPlaceholderText("Comment (optional)");
    // RESPONSIVE: bỏ setFixedHeight(30)
    bl_cmt_->setMinimumHeight(em * 2);
    bl_cmt_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    bl_cmt_->setStyleSheet(kInputStyle);

    auto* lbl_ip  = new QLabel("IP:",      form);
    auto* lbl_pr  = new QLabel("Proto:",   form);
    auto* lbl_cm  = new QLabel("Comment:", form);
    for (auto* l : {lbl_ip, lbl_pr, lbl_cm})
        l->setStyleSheet("font-size:12px; color:#555577; background:transparent;");

    r1->addWidget(lbl_ip);
    r1->addWidget(bl_ip_,   3);
    r1->addWidget(lbl_pr);
    r1->addWidget(bl_proto_);
    r1->addWidget(lbl_cm);
    r1->addWidget(bl_cmt_,  2);
    fl->addLayout(r1);

    // Row 2: TTL + Permanent + Block button
    auto* r2 = new QHBoxLayout;
    r2->setSpacing(8);

    bl_perm_ = new QCheckBox("🔒 Permanent", form);
    bl_perm_->setStyleSheet(kCheckStyle);

    auto* lbl_ttl = new QLabel("TTL (min):", form);
    lbl_ttl->setStyleSheet("font-size:12px; color:#555577; background:transparent;");

    bl_ttl_ = new QSpinBox(form);
    bl_ttl_->setRange(1, 10080);
    bl_ttl_->setValue(10);
    bl_ttl_->setSuffix(" min");
    // RESPONSIVE: bỏ setFixedSize(100, 30)
    bl_ttl_->setMinimumHeight(em * 2);
    bl_ttl_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    bl_ttl_->setStyleSheet(kSpinStyle);

    connect(bl_perm_, &QCheckBox::toggled, this, [=](bool checked) {
        bl_ttl_->setEnabled(!checked);
        lbl_ttl->setEnabled(!checked);
    });

    btn_block_ = new QPushButton("⛔  Block IP", form);
    // RESPONSIVE: bỏ setFixedHeight(32) + setMinimumWidth(110)
    btn_block_->setMinimumHeight(em * 2);
    btn_block_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    btn_block_->setStyleSheet(
        btnStyle("#fff0f0", "#cc2222", "#f0b8b8", "#ffe0e0"));
    connect(btn_block_, &QPushButton::clicked,
            this, &FirewallWidget::onBlockClicked);

    r2->addWidget(bl_perm_);
    r2->addWidget(lbl_ttl);
    r2->addWidget(bl_ttl_);
    r2->addStretch();
    r2->addWidget(btn_block_);
    fl->addLayout(r2);

    lay->addWidget(form);
}

// ─── buildWhitelistTab ────────────────────────────────────────────────────────

void FirewallWidget::buildWhitelistTab(QWidget* p) {
    auto* lay = new QVBoxLayout(p);
    lay->setSpacing(6);
    lay->setContentsMargins(8, 8, 8, 8);

    // RESPONSIVE: tính kích thước theo font metrics
    const int em = fontMetrics().height();

    // Search bar
    wl_search_ = new QLineEdit(p);
    wl_search_->setPlaceholderText("🔍  Search IP / comment…");
    // RESPONSIVE: bỏ setFixedHeight(30)
    wl_search_->setMinimumHeight(em * 2);
    wl_search_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    wl_search_->setStyleSheet(kInputStyle);
    wl_search_->setClearButtonEnabled(true);
    connect(wl_search_, &QLineEdit::textChanged,
            this, &FirewallWidget::onWlSearchChanged);
    lay->addWidget(wl_search_);

    // Table
    wl_table_ = new QTableWidget(0, WL_NCOLS, p);
    wl_table_->setHorizontalHeaderLabels({"IP / CIDR", "Comment", ""});
    auto* wh = wl_table_->horizontalHeader();
    wh->setSectionResizeMode(WL_IP,  QHeaderView::Stretch);
    wh->setSectionResizeMode(WL_CMT, QHeaderView::Stretch);
    wh->setSectionResizeMode(WL_DEL, QHeaderView::Fixed);
    wl_table_->setColumnWidth(WL_DEL, 50);
    wl_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    wl_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    wl_table_->verticalHeader()->hide();
    wl_table_->setStyleSheet(kTableStyle);
    wl_table_->setSortingEnabled(true);
    wl_table_->setAlternatingRowColors(true);
    lay->addWidget(wl_table_, 1);

    // ── Add form ──────────────────────────────────────────────────────────────
    auto* form = new QFrame(p);
    form->setStyleSheet(
        "QFrame { background:#f0fff4;"
        "  border:1px solid #c8e6c9; border-radius:6px; }");
    auto* fl = new QHBoxLayout(form);
    fl->setContentsMargins(10, 8, 10, 8);
    fl->setSpacing(8);

    wl_ip_ = new QLineEdit(form);
    wl_ip_->setPlaceholderText("IP / CIDR  (e.g. 10.0.0.1  or  192.168.0.0/16)");
    // RESPONSIVE: bỏ setFixedHeight(30)
    wl_ip_->setMinimumHeight(em * 2);
    wl_ip_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    wl_ip_->setStyleSheet(kInputStyle);
    connect(wl_ip_, &QLineEdit::returnPressed,
            this, &FirewallWidget::onAllowClicked);

    wl_cmt_ = new QLineEdit(form);
    wl_cmt_->setPlaceholderText("Comment (optional)");
    // RESPONSIVE: bỏ setFixedHeight(30) + setFixedWidth(200)
    wl_cmt_->setMinimumHeight(em * 2);
    wl_cmt_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    wl_cmt_->setStyleSheet(kInputStyle);

    btn_allow_ = new QPushButton("✅  Allow IP", form);
    // RESPONSIVE: bỏ setFixedHeight(32) + setMinimumWidth(110)
    btn_allow_->setMinimumHeight(em * 2);
    btn_allow_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    btn_allow_->setStyleSheet(
        btnStyle("#f0fff4", "#227744", "#a5d6a7", "#c8e6c9"));
    connect(btn_allow_, &QPushButton::clicked,
            this, &FirewallWidget::onAllowClicked);

    auto* lbl_ip = new QLabel("IP:", form);
    auto* lbl_cm = new QLabel("Comment:", form);
    for (auto* l : {lbl_ip, lbl_cm})
        l->setStyleSheet("font-size:12px; color:#555577; background:transparent;");

    fl->addWidget(lbl_ip);
    fl->addWidget(wl_ip_,   3);
    fl->addWidget(lbl_cm);
    fl->addWidget(wl_cmt_,  1);
    fl->addWidget(btn_allow_);
    lay->addWidget(form);
}

// ─── buildQuickBar ────────────────────────────────────────────────────────────

void FirewallWidget::buildQuickBar(QVBoxLayout* root) {
    auto* sep = new QFrame(this);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color:#d0d4e8;");
    root->addWidget(sep);

    auto* row = new QWidget(this);
    row->setStyleSheet("background:transparent;");
    auto* lay = new QHBoxLayout(row);
    lay->setContentsMargins(0, 2, 0, 2);
    lay->setSpacing(6);

    btn_refresh_ = new QPushButton("🔄  Refresh",        row);
    btn_flush_   = new QPushButton("🗑  Flush Blacklist", row);
    btn_load_    = new QPushButton("📂  Load Rules",      row);
    btn_save_    = new QPushButton("💾  Save Rules",      row);

    const QString sNormal = btnStyle("#eef0f7","#3355cc","#c0c8e8","#dce3ff");
    const QString sFlush  = btnStyle("#fff0f0","#cc2222","#f0b8b8","#ffe0e0");

    btn_refresh_->setStyleSheet(sNormal);
    btn_flush_  ->setStyleSheet(sFlush);
    btn_load_   ->setStyleSheet(sNormal);
    btn_save_   ->setStyleSheet(sNormal);

    // RESPONSIVE: bỏ setFixedHeight(30) → tự co dãn theo nội dung
    for (auto* b : {btn_refresh_, btn_flush_, btn_load_, btn_save_})
        b->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);

    connect(btn_refresh_, &QPushButton::clicked,
            this, &FirewallWidget::refresh);
    connect(btn_flush_,   &QPushButton::clicked,
            this, &FirewallWidget::onFlushBlacklist);
    connect(btn_load_,    &QPushButton::clicked,
            this, &FirewallWidget::onLoadRules);
    connect(btn_save_,    &QPushButton::clicked,
            this, &FirewallWidget::onSaveRules);

    lay->addWidget(btn_refresh_);
    lay->addWidget(btn_flush_);
    lay->addWidget(btn_load_);
    lay->addStretch();
    lay->addWidget(btn_save_);
    root->addWidget(row);
}

// ════════════════════════════════════════════════════════════════════════════
// Slots — Block / Allow
// ════════════════════════════════════════════════════════════════════════════

void FirewallWidget::onBlockClicked() {
    if (!fw_) return;

    const QString ip = bl_ip_->text().trimmed();
    if (ip.isEmpty()) {
        emit statusMessage("⚠️  Enter an IP / CIDR to block.");
        return;
    }

    const uint8_t  proto   = static_cast<uint8_t>(
                                 bl_proto_->currentData().toInt());
    const bool     perm    = bl_perm_->isChecked();
    const uint32_t ttl_sec = perm ? 0
                                  : static_cast<uint32_t>(bl_ttl_->value() * 60);
    const std::string cmt  = bl_cmt_->text().trimmed().toStdString();

    const uint64_t id = fw_->manualBlock(
        ip.toStdString(), proto, 0,
        perm, ttl_sec,
        cmt.empty() ? "Manual block" : cmt);

    if (id == 0) {
        const QString reason =
            fw_->isWhitelisted(ip.toStdString())
                ? "IP is whitelisted — remove from whitelist first."
                : "Failed (invalid IP or already blocked).";
        emit statusMessage("⚠️  " + reason);
        return;
    }

    bl_ip_->clear();
    bl_cmt_->clear();
    emit statusMessage(
        QString("⛔  Blocked: %1  [%2]  %3")
            .arg(ip)
            .arg(bl_proto_->currentText())
            .arg(perm ? "permanent"
                      : QString("%1 min").arg(bl_ttl_->value())));
    refresh();
}

void FirewallWidget::onAllowClicked() {
    if (!fw_) return;

    const QString ip = wl_ip_->text().trimmed();
    if (ip.isEmpty()) {
        emit statusMessage("⚠️  Enter an IP / CIDR to whitelist.");
        return;
    }

    const std::string cmt = wl_cmt_->text().trimmed().toStdString();
    const uint64_t id = fw_->addWhitelist(
        ip.toStdString(),
        cmt.empty() ? "Manual whitelist" : cmt);

    if (id == 0) {
        emit statusMessage(
            QString("⚠️  Failed to whitelist %1 (already exists?)").arg(ip));
        return;
    }

    wl_ip_->clear();
    wl_cmt_->clear();
    emit statusMessage(QString("✅  Whitelisted: %1").arg(ip));
    refresh();
}

// ════════════════════════════════════════════════════════════════════════════
// Slots — Flush / Save / Load
// ════════════════════════════════════════════════════════════════════════════

void FirewallWidget::onFlushBlacklist() {
    if (!fw_) return;

    const auto rules = fw_->listBlacklist();
    if (rules.empty()) {
        emit statusMessage("ℹ️  Blacklist is already empty.");
        return;
    }

    const auto reply = QMessageBox::question(
        this, "Flush Blacklist",
        QString("Remove ALL %1 blacklist rule(s)?\n"
                "(Whitelist rules will be kept)")
            .arg(rules.size()),
        QMessageBox::Yes | QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    int n = 0;
    for (const auto& r : rules)
        if (fw_->removeRule(r.id)) ++n;

    emit statusMessage(
        QString("🗑  Flushed %1 / %2 rule(s)").arg(n).arg(rules.size()));
    refresh();
}

void FirewallWidget::onSaveRules() {
    if (!fw_) return;

    // Đảm bảo thư mục config tồn tại
    QDir().mkpath(RULES_DIR);

    const QString path = QFileDialog::getSaveFileName(
        this, "Save Firewall Rules",
        RULES_PATH,
        "JSON (*.json);;All (*)");
    if (path.isEmpty()) return;

    const bool ok = fw_->saveRules(path.toStdString());
    emit statusMessage(ok
        ? QString("💾  Saved → %1").arg(path)
        : QString("❌  Save failed → %1  (check permissions)").arg(path));
}

void FirewallWidget::onLoadRules() {
    if (!fw_) return;

    const QString path = QFileDialog::getOpenFileName(
        this, "Load Firewall Rules",
        RULES_DIR,
        "JSON (*.json);;All (*)");
    if (path.isEmpty()) return;

    const bool ok = fw_->loadRules(path.toStdString());
    if (ok) refresh();
    emit statusMessage(ok
        ? QString("📂  Loaded ← %1  (BL:%2  WL:%3)")
              .arg(path)
              .arg(fw_->blacklistSize())
              .arg(fw_->whitelistSize())
        : QString("Load failed ← %1").arg(path));
}

// ════════════════════════════════════════════════════════════════════════════
// Slots — Remove row
// ════════════════════════════════════════════════════════════════════════════

void FirewallWidget::onRemoveBlacklistRow(int row) {
    if (!fw_) return;

    auto* ip_item = bl_table_->item(row, BL_IP);
    if (!ip_item) return;

    const uint64_t id = ip_item->data(Qt::UserRole).toULongLong();
    const QString  ip = ip_item->text();

    if (fw_->removeRule(id))
        emit statusMessage(QString("Removed blacklist: %1").arg(ip));
    else
        emit statusMessage(QString("Cannot remove rule #%1").arg(id));

    refresh();
}

void FirewallWidget::onRemoveWhitelistRow(int row) {
    if (!fw_) return;

    auto* ip_item = wl_table_->item(row, WL_IP);
    if (!ip_item) return;

    const QString ip = ip_item->text();

    if (fw_->removeWhitelist(ip.toStdString()))
        emit statusMessage(QString("Removed whitelist: %1").arg(ip));
    else
        emit statusMessage(QString("Cannot remove whitelist: %1").arg(ip));

    refresh();
}

// ════════════════════════════════════════════════════════════════════════════
// Slots — Search / TTL timer
// ════════════════════════════════════════════════════════════════════════════

void FirewallWidget::onBlSearchChanged(const QString& t) { applyBlSearch(t); }
void FirewallWidget::onWlSearchChanged(const QString& t) { applyWlSearch(t); }

void FirewallWidget::onTtlTimerTick() {
    if (!fw_) return;

    bool any_expired = false;

    // Cập nhật cột TTL hiển thị
    for (int i = 0; i < bl_table_->rowCount(); ++i) {
        auto* ip_item = bl_table_->item(i, BL_IP);
        if (!ip_item) continue;

        const uint64_t id = ip_item->data(Qt::UserRole).toULongLong();
        for (const auto& r : bl_cache_) {
            if (r.id != id) continue;
            if (r.isExpired()) {
                any_expired = true;
            } else {
                if (auto* ti = bl_table_->item(i, BL_TTL))
                    ti->setText(r.permanent
                        ? "∞ Permanent"
                        : formatTtl(r.ttl_sec, r.created_at));
            }
            break;
        }
    }

    // Nếu có rule hết hạn → full refresh để xóa khỏi bảng
    if (any_expired) refresh();
}

// ════════════════════════════════════════════════════════════════════════════
// refresh
// ════════════════════════════════════════════════════════════════════════════

void FirewallWidget::refresh() {
    if (!fw_) return;
    refreshBlacklist();
    refreshWhitelist();
    updateStatsBadge();
    applyBlSearch(bl_search_->text());
    applyWlSearch(wl_search_->text());
}

void FirewallWidget::refreshBlacklist() {
    bl_cache_ = fw_->listBlacklist();

    bl_table_->setSortingEnabled(false);
    bl_table_->setUpdatesEnabled(false);
    bl_table_->clearContents();
    bl_table_->setRowCount(static_cast<int>(bl_cache_.size()));

    for (int i = 0; i < static_cast<int>(bl_cache_.size()); ++i) {
        const auto& r = bl_cache_[i];

        // ── IP / CIDR ─────────────────────────────────────────────────────────
        auto* ip_cell = cell(QString::fromStdString(r.src_ip));
        ip_cell->setData(Qt::UserRole, static_cast<qulonglong>(r.id));
        ip_cell->setForeground(QColor("#cc2222"));
        QFont f; f.setBold(true);
        ip_cell->setFont(f);
        bl_table_->setItem(i, BL_IP, ip_cell);

        // ── Protocol ──────────────────────────────────────────────────────────
        auto* pr_cell = cell(protocolName(r.protocol),
                              Qt::AlignCenter | Qt::AlignVCenter);
        if (r.protocol != 0)
            pr_cell->setForeground(QColor("#3355cc"));
        bl_table_->setItem(i, BL_PROTO, pr_cell);

        // ── Comment ───────────────────────────────────────────────────────────
        auto* cm_cell = cell(QString::fromStdString(r.comment));
        cm_cell->setForeground(QColor("#666688"));
        bl_table_->setItem(i, BL_CMT, cm_cell);

        // ── TTL ───────────────────────────────────────────────────────────────
        const QString ttl_str = r.permanent
            ? "∞ Permanent"
            : formatTtl(r.ttl_sec, r.created_at);
        auto* ttl_cell = cell(ttl_str, Qt::AlignCenter | Qt::AlignVCenter);
        ttl_cell->setForeground(r.permanent
            ? QColor("#cc2222") : QColor("#cc6600"));
        bl_table_->setItem(i, BL_TTL, ttl_cell);

        // ── Source ────────────────────────────────────────────────────────────
        const bool is_auto = (r.source == FirewallRule::Source::AUTO);
        auto* src_cell = cell(is_auto ? "🤖 Auto" : "👤 Manual",
                               Qt::AlignCenter | Qt::AlignVCenter);
        src_cell->setForeground(QColor(is_auto ? "#3355cc" : "#666688"));
        bl_table_->setItem(i, BL_SRC, src_cell);

        // ── Delete button ─────────────────────────────────────────────────────
        auto* del_btn = makeIconBtn(
            bl_table_, "✕",
            "#fff0f0", "#cc2222", "#f0b8b8", "#ffe0e0");
        const int ri = i;
        connect(del_btn, &QPushButton::clicked,
                this, [this, ri] { onRemoveBlacklistRow(ri); });
        bl_table_->setCellWidget(i, BL_DEL, del_btn);

        // ── Row background ────────────────────────────────────────────────────
        const QColor bg = r.permanent ? QColor("#fff8f8") : Qt::white;
        for (int c = 0; c < BL_DEL; ++c)
            if (auto* it = bl_table_->item(i, c))
                it->setBackground(bg);

        bl_table_->setRowHeight(i, 26);
    }

    bl_table_->setUpdatesEnabled(true);
    bl_table_->setSortingEnabled(true);
}

void FirewallWidget::refreshWhitelist() {
    wl_cache_ = fw_->listWhitelist();

    wl_table_->setSortingEnabled(false);
    wl_table_->setUpdatesEnabled(false);
    wl_table_->clearContents();
    wl_table_->setRowCount(static_cast<int>(wl_cache_.size()));

    for (int i = 0; i < static_cast<int>(wl_cache_.size()); ++i) {
        const auto& r = wl_cache_[i];

        // ── IP / CIDR ─────────────────────────────────────────────────────────
        auto* ip_cell = cell(QString::fromStdString(r.src_ip));
        ip_cell->setData(Qt::UserRole, static_cast<qulonglong>(r.id));
        ip_cell->setForeground(QColor("#227744"));
        QFont f; f.setBold(true);
        ip_cell->setFont(f);
        wl_table_->setItem(i, WL_IP, ip_cell);

        // ── Comment ───────────────────────────────────────────────────────────
        auto* cm_cell = cell(QString::fromStdString(r.comment));
        cm_cell->setForeground(QColor("#666688"));
        wl_table_->setItem(i, WL_CMT, cm_cell);

        // ── Delete button ─────────────────────────────────────────────────────
        auto* del_btn = makeIconBtn(
            wl_table_, "✕",
            "#f0fff4", "#227744", "#a5d6a7", "#c8e6c9");
        const int ri = i;
        connect(del_btn, &QPushButton::clicked,
                this, [this, ri] { onRemoveWhitelistRow(ri); });
        wl_table_->setCellWidget(i, WL_DEL, del_btn);

        wl_table_->setRowHeight(i, 26);
    }

    wl_table_->setUpdatesEnabled(true);
    wl_table_->setSortingEnabled(true);
}

// ════════════════════════════════════════════════════════════════════════════
// updateStatsBadge
// ════════════════════════════════════════════════════════════════════════════

void FirewallWidget::updateStatsBadge() {
    if (!fw_) {
        lbl_stats_->setText("🔴 Blacklist: —   🟢 Whitelist: —");
        return;
    }
    const size_t bl = fw_->blacklistSize();
    const size_t wl = fw_->whitelistSize();

    lbl_stats_->setText(
        QString("🔴 Blacklist: %1   🟢 Whitelist: %2   📋 Total: %3")
            .arg(bl).arg(wl).arg(bl + wl));

    lbl_stats_->setStyleSheet(bl > 0
        ? "background:#fff0f0; color:#cc2222;"
          "font-size:12px; font-weight:bold;"
          "border:1px solid #f0b8b8; border-radius:5px; padding:2px 16px;"
        : "background:#eef0f7; color:#1a1a3e;"
          "font-size:12px; font-weight:bold;"
          "border:1px solid #d0d4e8; border-radius:5px; padding:2px 16px;");
}

// ════════════════════════════════════════════════════════════════════════════
// Search filter
// ════════════════════════════════════════════════════════════════════════════

void FirewallWidget::applyBlSearch(const QString& t) {
    const QString q = t.trimmed().toLower();
    for (int i = 0; i < bl_table_->rowCount(); ++i) {
        bool show = q.isEmpty();
        for (int c = BL_IP; c < BL_DEL && !show; ++c)
            if (auto* it = bl_table_->item(i, c))
                show = it->text().toLower().contains(q);
        bl_table_->setRowHidden(i, !show);
    }
}

void FirewallWidget::applyWlSearch(const QString& t) {
    const QString q = t.trimmed().toLower();
    for (int i = 0; i < wl_table_->rowCount(); ++i) {
        bool show = q.isEmpty();
        for (int c = WL_IP; c < WL_DEL && !show; ++c)
            if (auto* it = wl_table_->item(i, c))
                show = it->text().toLower().contains(q);
        wl_table_->setRowHidden(i, !show);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// setControlsEnabled
// ════════════════════════════════════════════════════════════════════════════

void FirewallWidget::setControlsEnabled(bool on) {
    for (auto* w : std::initializer_list<QWidget*>{
            btn_block_,  btn_allow_,
            btn_refresh_, btn_flush_, btn_load_, btn_save_,
            bl_ip_,  bl_cmt_,  bl_proto_, bl_perm_, bl_ttl_, bl_search_,
            wl_ip_,  wl_cmt_,  wl_search_ })
        if (w) w->setEnabled(on);
}

// ════════════════════════════════════════════════════════════════════════════
// Static helpers
// ════════════════════════════════════════════════════════════════════════════

QString FirewallWidget::protocolName(uint8_t p) {
    switch (p) {
        case  0: return "ANY";
        case  1: return "ICMP";
        case  6: return "TCP";
        case 17: return "UDP";
        default: return QString("(%1)").arg(p);
    }
}

QString FirewallWidget::formatTtl(uint32_t ttl_sec, uint64_t created_at) {
    if (ttl_sec == 0) return "∞";
    const uint64_t now     = static_cast<uint64_t>(std::time(nullptr));
    const uint64_t expires = created_at + ttl_sec;
    if (expires <= now) return "Expired";
    const uint64_t rem = expires - now;
    if (rem >= 3600)
        return QString("%1h %2m").arg(rem / 3600).arg((rem % 3600) / 60);
    if (rem >= 60)
        return QString("%1m %2s").arg(rem / 60).arg(rem % 60);
    return QString("%1s").arg(rem);
}

QTableWidgetItem* FirewallWidget::cell(const QString& text,
                                        Qt::Alignment  align) {
    auto* it = new QTableWidgetItem(text);
    it->setTextAlignment(align);
    it->setFlags(it->flags() & ~Qt::ItemIsEditable);
    return it;
}

QPushButton* FirewallWidget::makeIconBtn(QWidget*       parent,
                                          const QString& label,
                                          const QString& bg,
                                          const QString& fg,
                                          const QString& border,
                                          const QString& hover) {
    auto* btn = new QPushButton(label, parent);
    btn->setFixedSize(36, 22);
    btn->setToolTip("Remove");
    btn->setStyleSheet(QString(
        "QPushButton {"
        "  background:%1; color:%2;"
        "  border:1px solid %3; border-radius:4px; font-size:13px; }"
        "QPushButton:hover { background:%4; border-color:%2; }")
        .arg(bg, fg, border, hover));
    return btn;
}

