// src/ui/qt/main_window.cpp
#include "main_window.hpp"

#include "pcap_tab.hpp"
#include "capture_control_dialog.hpp"
#include "ips_control_widget.hpp"
#include "alert_panel.hpp"
#include "metrics_widget.hpp"
#include "traffic_chart.hpp"
#include "firewall_widget.hpp"

#include "../../capture/packet_capture.hpp"
#include "../../common/engine_config.hpp"

#include <QApplication>
#include <QMenuBar>
#include <QStatusBar>
#include <QCloseEvent>
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QDateTime>
#include <QDir>
#include <QLineEdit>

// ═══════════════════════════════════════════════════════════════════════════════
// Constructor
// ═══════════════════════════════════════════════════════════════════════════════

MainWindow::MainWindow(AlertManager&     alert_manager,
                       Dispatcher&       dispatcher,
                       MLEngine&         ml_engine,
                       PacketRingBuffer& ring_buf,
                       FirewallManager*  firewall_manager,
                       QWidget*          parent)
    : QMainWindow(parent)
    , alert_manager_   (alert_manager)
    , dispatcher_      (dispatcher)
    , ml_engine_       (ml_engine)
    , ring_buf_        (ring_buf)
    , firewall_manager_(firewall_manager)
    , start_time_      (QTime::currentTime())
{
    setWindowTitle("Network IDS/IPS — HVKTQS 2025");
    setMinimumSize(1280, 760);
    resize(1440, 900);

    applyTheme();
    setupUI();
    setupMenuBar();
    setupStatusBar();

    // ── UiBridge ──────────────────────────────────────────────────────────────
    ui_bridge_ = std::make_unique<UiBridge>(
        alert_manager_, dispatcher_, ml_engine_, ring_buf_, this);
    ui_bridge_->setFirewallManager(firewall_manager_);

    // ── Live tab ──────────────────────────────────────────────────────────────
    live_tab_->setUiBridge(ui_bridge_.get());

    // ── IpsControlWidget ← UiBridge signals ───────────────────────────────────
    connect(ui_bridge_.get(), &UiBridge::detectionStatusChanged,
            ips_widget_,      &IpsControlWidget::onDetectionStatusChanged);
    connect(ui_bridge_.get(), &UiBridge::mlStatusChanged,
            ips_widget_,      &IpsControlWidget::onMlStatusChanged);

    connect(ips_widget_, &IpsControlWidget::toggleDetection,
            ui_bridge_.get(), &UiBridge::setDetectionEnabled);
    connect(ips_widget_, &IpsControlWidget::toggleMl,
            ui_bridge_.get(), &UiBridge::setMlEnabled);

    // ── AlertPanel (tab IPS — live feed) ← UiBridge::newAlerts ───────────────
    connect(ui_bridge_.get(), &UiBridge::newAlerts,
            alert_panel_ips_,  &AlertPanel::onNewAlerts);

    // ── TrafficChart ← UiBridge::trafficUpdated ───────────────────────────────
    connect(ui_bridge_.get(), &UiBridge::trafficUpdated,
            traffic_chart_,    &TrafficChart::onTrafficUpdated);

    // // ── MetricsWidget ← UiBridge::metricsUpdated ─────────────────────────────
    // connect(ui_bridge_.get(), &UiBridge::metricsUpdated,
    //         metrics_widget_,   &MetricsWidget::onMetricsUpdated);

    // ── FirewallWidget ────────────────────────────────────────────────────────
    if (firewall_tab_) {
        // Luôn gọi setFirewallManager — kể cả khi firewall_manager_ == nullptr
        // để widget hiển thị trạng thái "No backend" thay vì bị disabled hoàn toàn
        firewall_tab_->setFirewallManager(firewall_manager_);

        connect(firewall_tab_, &FirewallWidget::statusMessage,
                this, [this](const QString& msg) {
                    statusBar()->showMessage(msg, 4000);
                });
    }

    // ── Firewall stats badge ───────────────────────────────────────────────────
    connect(ui_bridge_.get(), &UiBridge::firewallStatsUpdated,
            this, [this](size_t bl, size_t wl) {
                const QString txt =
                    QString("  🔴 BL:%1  🟢 WL:%2  ").arg(bl).arg(wl);
                if (status_fw_badge_) status_fw_badge_->setText(txt);
                if (lbl_fw_badge_)    lbl_fw_badge_   ->setText(txt);
            });

    // ── Engine status → MainWindow badges ─────────────────────────────────────
    connect(ui_bridge_.get(), &UiBridge::detectionStatusChanged,
            this, &MainWindow::onDetectionToggled);
    connect(ui_bridge_.get(), &UiBridge::mlStatusChanged,
            this, &MainWindow::onMlToggled);

    // ── Sync trạng thái ban đầu cho IpsControlWidget ──────────────────────────
    ips_widget_->syncState(
        ENGINE_CFG.detection_enabled.load(std::memory_order_relaxed),
        ENGINE_CFG.ml_enabled       .load(std::memory_order_relaxed));

    ui_bridge_->startPolling(200);

    connect(&uptime_timer_, &QTimer::timeout,
            this, &MainWindow::updateUptime);
    uptime_timer_.start(1000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Destructor
// ═══════════════════════════════════════════════════════════════════════════════

MainWindow::~MainWindow() {
    if (ui_bridge_) ui_bridge_->stopPolling();
    stopLiveCapture();
    if (capture_thread_ && capture_thread_->joinable())
        capture_thread_->join();
}

// ═══════════════════════════════════════════════════════════════════════════════
// applyTheme
// ═══════════════════════════════════════════════════════════════════════════════

void MainWindow::applyTheme() {
    setStyleSheet(
        "QMainWindow, QWidget { background: #f5f6fa; color: #1a1a3e; }"

        "QTableView, QTableWidget {"
        "  background: #ffffff; color: #1a1a3e;"
        "  gridline-color: #dde0ee;"
        "  selection-background-color: #d0d8ff;"
        "  selection-color: #0a0a6e;"
        "  alternate-background-color: #f0f2ff;"
        "}"
        "QHeaderView::section {"
        "  background: #e8eaf6; color: #333366;"
        "  border: 1px solid #c5cae9;"
        "  padding: 4px 6px;"
        "  font-weight: bold; font-size: 11px;"
        "}"

        "QTreeWidget, QTreeView {"
        "  background: #ffffff; color: #1a1a3e;"
        "  alternate-background-color: #f0f2ff;"
        "}"
        "QTreeWidget::item:selected, QTreeView::item:selected {"
        "  background: #d0d8ff; color: #0a0a6e;"
        "}"

        "QLineEdit, QComboBox {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #b0b8d8; border-radius: 4px;"
        "  padding: 4px 8px; font-size: 12px;"
        "}"
        "QLineEdit:focus, QComboBox:focus { border-color: #3355cc; }"

        "QPushButton {"
        "  background: #e8eaf6; color: #333366;"
        "  border: 1px solid #b0b8d8; border-radius: 4px;"
        "  padding: 4px 12px; font-size: 12px;"
        "}"
        "QPushButton:hover    { background: #d8dcf8; }"
        "QPushButton:pressed  { background: #c8cef0; }"
        "QPushButton:disabled { background: #f0f0f5; color: #aaaacc;"
        "                       border-color: #d8d8e8; }"

        "QGroupBox {"
        "  background: #ffffff;"
        "  border: 1px solid #c5cae9; border-radius: 6px;"
        "  margin-top: 8px; padding-top: 8px;"
        "  font-weight: bold; color: #333366;"
        "}"
        "QGroupBox::title {"
        "  subcontrol-origin: margin; subcontrol-position: top left;"
        "  padding: 0 6px; color: #3355cc;"
        "}"

        "QSplitter::handle          { background: #c5cae9; }"
        "QSplitter::handle:horizontal { width: 2px; }"
        "QSplitter::handle:vertical   { height: 2px; }"

        "QScrollBar:vertical   { background: #f0f0f8; width: 10px; }"
        "QScrollBar:horizontal { background: #f0f0f8; height: 10px; }"
        "QScrollBar::handle:vertical   { background: #b0b8d8;"
        "  border-radius: 5px; min-height: 24px; }"
        "QScrollBar::handle:horizontal { background: #b0b8d8;"
        "  border-radius: 5px; min-width: 24px; }"
        "QScrollBar::add-line:vertical,   QScrollBar::sub-line:vertical   { height: 0; }"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:  0; }"

        "QToolTip { background: #1e2a4a; color: #ddeeff;"
        "           border: 1px solid #3355cc; padding: 4px; font-size: 11px; }");
}

// ═══════════════════════════════════════════════════════════════════════════════
// setupUI
// ═══════════════════════════════════════════════════════════════════════════════

void MainWindow::setupUI() {
    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* root = new QVBoxLayout(central);
    root->setSpacing(0);
    root->setContentsMargins(0, 0, 0, 0);

    root->addWidget(buildCaptureToolbar());

    tab_widget_ = new QTabWidget(central);
    tab_widget_->setDocumentMode(true);
    tab_widget_->setTabsClosable(false);
    tab_widget_->setMovable(false);
    tab_widget_->setStyleSheet(
        "QTabWidget::pane { border: none; background: #f5f6fa; }"
        "QTabBar { background: #e8eaf6; border-bottom: 2px solid #b0b8d8; }"
        "QTabBar::tab {"
        "  background: #e8eaf6; color: #555577;"
        "  border: 1px solid #c5cae9; border-bottom: none;"
        "  padding: 7px 20px; margin-right: 2px;"
        "  font-size: 12px; font-weight: 500; min-width: 120px;"
        "}"
        "QTabBar::tab:selected {"
        "  background: #f5f6fa; color: #1a1a6e;"
        "  border-bottom: 3px solid #3355cc; font-weight: bold;"
        "}"
        "QTabBar::tab:hover:!selected { background: #dde0f8; color: #222244; }");

    // ── 5 tabs (bỏ Alerts) ────────────────────────────────────────────────────
    tab_widget_->addTab(buildTab_LiveCapture(),  "📡  Live Capture");   // 0
    tab_widget_->addTab(buildTab_FileAnalysis(), "📂  File Analysis");  // 1
    tab_widget_->addTab(buildTab_IPS(),          "🛡️  IPS / Detection");// 2
    tab_widget_->addTab(buildTab_Firewall(),     "🔥  Firewall");       // 3
    tab_widget_->addTab(buildTab_Statistics(),   "📊  Statistics");     // 4

    root->addWidget(tab_widget_, 1);
}

// ─── buildCaptureToolbar ──────────────────────────────────────────────────────

QWidget* MainWindow::buildCaptureToolbar() {
    auto* bar    = new QWidget(this);
    auto* layout = new QHBoxLayout(bar);
    layout->setContentsMargins(10, 5, 10, 5);
    layout->setSpacing(8);
    bar->setFixedHeight(46);
    bar->setStyleSheet(
        "QWidget { background: #1e2a4a; border-bottom: 2px solid #3355cc; }"
        "QLabel  { color: #ddeeff; font-size: 12px; background: transparent; }"
        "QPushButton {"
        "  background: #2a3a6a; color: #ddeeff;"
        "  border: 1px solid #4466aa; border-radius: 4px;"
        "  padding: 5px 16px; font-size: 12px; font-weight: bold;"
        "}"
        "QPushButton:hover    { background: #3a4a8a; }"
        "QPushButton:disabled { background: #1a1a2a; color: #445566;"
        "                       border-color: #2a2a3a; }");

    auto* title = new QLabel(
        "🛡️  <b>Network IDS/IPS</b>  —  HVKTQS 2025", bar);
    title->setStyleSheet(
        "font-size: 13px; color: #ddeeff; background: transparent;");
    layout->addWidget(title);

    auto* sep1 = new QFrame(bar);
    sep1->setFrameShape(QFrame::VLine);
    sep1->setStyleSheet("color: #3a4a6a; background: #3a4a6a;");
    sep1->setFixedWidth(1);
    layout->addWidget(sep1);

    btn_start_cap_ = new QPushButton("▶  Start Capture", bar);
    btn_stop_cap_  = new QPushButton("■  Stop",          bar);
    btn_save_cap_  = new QPushButton("💾  Save",         bar);

    btn_stop_cap_->setEnabled(false);
    btn_save_cap_->setEnabled(false);
    btn_stop_cap_->setStyleSheet(
        "QPushButton { background: #4a1a1a; color: #ffaaaa;"
        "  border: 1px solid #882222; border-radius: 4px;"
        "  padding: 5px 16px; font-size: 12px; font-weight: bold; }"
        "QPushButton:hover    { background: #6a2a2a; }"
        "QPushButton:disabled { background: #1a1a2a; color: #445566;"
        "                       border-color: #2a2a3a; }");

    connect(btn_start_cap_, &QPushButton::clicked,
            this, &MainWindow::onStartCaptureClicked);
    connect(btn_stop_cap_,  &QPushButton::clicked,
            this, &MainWindow::onStopCaptureClicked);
    connect(btn_save_cap_,  &QPushButton::clicked,
            this, &MainWindow::onSaveCaptureClicked);

    layout->addWidget(btn_start_cap_);
    layout->addWidget(btn_stop_cap_);
    layout->addWidget(btn_save_cap_);

    auto* sep2 = new QFrame(bar);
    sep2->setFrameShape(QFrame::VLine);
    sep2->setStyleSheet("color: #3a4a6a; background: #3a4a6a;");
    sep2->setFixedWidth(1);
    layout->addWidget(sep2);

    lbl_iface_ = new QLabel("No interface selected", bar);
    lbl_iface_->setStyleSheet(
        "color: #8899bb; font-size: 11px; background: transparent;");
    layout->addWidget(lbl_iface_);

    layout->addStretch();

    lbl_ips_badge_ = new QLabel("  🛡️ IPS  ", bar);
    lbl_ips_badge_->setStyleSheet(
        "color: #00ff88; font-weight: bold; font-size: 11px;"
        "background: #0a2a0a; border: 1px solid #226622;"
        "border-radius: 4px; padding: 2px 10px;");
    layout->addWidget(lbl_ips_badge_);

    lbl_fw_badge_ = new QLabel(
        firewall_manager_ ? "  🔥 FW: ON  " : "  🔥 FW: OFF  ", bar);
    lbl_fw_badge_->setStyleSheet(
        firewall_manager_
            ? "color: #ffaa44; font-weight: bold; font-size: 11px;"
              "background: #2a1800; border: 1px solid #664400;"
              "border-radius: 4px; padding: 2px 10px;"
            : "color: #556677; font-size: 11px;"
              "background: #1a1a2a; border: 1px solid #2a2a3a;"
              "border-radius: 4px; padding: 2px 10px;");
    layout->addWidget(lbl_fw_badge_);

    return bar;
}

// ─── buildTab_LiveCapture ─────────────────────────────────────────────────────

QWidget* MainWindow::buildTab_LiveCapture() {
    live_tab_ = new PcapTab(PcapTab::Mode::LIVE, tab_widget_);
    connect(live_tab_, &PcapTab::statusMessage,
            this, [this](const QString& msg) {
                statusBar()->showMessage(msg, 3000);
            });
    return live_tab_;
}

// ─── buildTab_FileAnalysis ────────────────────────────────────────────────────

QWidget* MainWindow::buildTab_FileAnalysis() {
    auto* container = new QWidget(tab_widget_);
    auto* layout    = new QVBoxLayout(container);
    layout->setSpacing(0);
    layout->setContentsMargins(0, 0, 0, 0);

    file_tab_widget_ = new QTabWidget(container);
    file_tab_widget_->setTabsClosable(true);
    file_tab_widget_->setMovable(true);
    file_tab_widget_->setStyleSheet(
        "QTabWidget::pane  { border: none; background: #ffffff; }"
        "QTabBar::tab      { background: #eeeef8; color: #555577;"
        "                    border: 1px solid #c5cae9; padding: 5px 14px; }"
        "QTabBar::tab:selected { background: #ffffff; color: #1a1a6e;"
        "                        border-bottom: 2px solid #3355cc; }"
        "QTabBar::tab:hover    { background: #dde0f8; }");

    auto* placeholder = new QWidget(file_tab_widget_);
    auto* ph_layout   = new QVBoxLayout(placeholder);
    ph_layout->setAlignment(Qt::AlignCenter);
    ph_layout->setSpacing(12);

    auto* ph_icon  = new QLabel("📂", placeholder);
    auto* ph_label = new QLabel("Open a PCAP file to analyze", placeholder);
    auto* ph_btn   = new QPushButton("📂  Open PCAP File…", placeholder);

    ph_icon ->setAlignment(Qt::AlignCenter);
    ph_label->setAlignment(Qt::AlignCenter);
    ph_icon ->setStyleSheet("font-size: 52px; background: transparent;");
    ph_label->setStyleSheet(
        "color: #888899; font-size: 14px; background: transparent;");
    ph_btn  ->setStyleSheet(
        "QPushButton { background: #3355cc; color: #ffffff;"
        "  border: none; border-radius: 6px;"
        "  padding: 10px 28px; font-size: 13px; font-weight: bold; }"
        "QPushButton:hover { background: #4466dd; }");
    connect(ph_btn, &QPushButton::clicked,
            this, [this]() { addPcapTab(); });

    ph_layout->addWidget(ph_icon);
    ph_layout->addWidget(ph_label);
    ph_layout->addWidget(ph_btn, 0, Qt::AlignCenter);
    file_tab_widget_->addTab(placeholder, "  Welcome  ");

    auto* add_btn = new QPushButton("+", file_tab_widget_);
    add_btn->setFixedSize(28, 28);
    add_btn->setToolTip("Open PCAP file");
    add_btn->setStyleSheet(
        "QPushButton { background: #e8eaf6; color: #3355cc;"
        "  border: 1px solid #b0b8d8; border-radius: 4px;"
        "  font-size: 16px; font-weight: bold; }"
        "QPushButton:hover { background: #d8dcf8; }");
    file_tab_widget_->setCornerWidget(add_btn, Qt::TopRightCorner);
    connect(add_btn, &QPushButton::clicked,
            this, [this]() { addPcapTab(); });

    connect(file_tab_widget_, &QTabWidget::tabCloseRequested,
            this, [this](int idx) {
                if (idx == 0) return;
                delete file_tab_widget_->widget(idx);
            });

    layout->addWidget(file_tab_widget_);
    return container;
}

// ─── addPcapTab ───────────────────────────────────────────────────────────────

void MainWindow::addPcapTab(const QString& filepath) {
    tab_widget_->setCurrentIndex(1);

    auto* tab = new PcapTab(PcapTab::Mode::OFFLINE, file_tab_widget_);
    const int idx = file_tab_widget_->addTab(tab, "📄  New File");
    file_tab_widget_->setCurrentIndex(idx);

    connect(tab, &PcapTab::titleChanged,
            this, [this, tab](const QString& title) {
                const int i = file_tab_widget_->indexOf(tab);
                if (i >= 0) file_tab_widget_->setTabText(i, "📄  " + title);
            });
    connect(tab, &PcapTab::statusMessage,
            this, [this](const QString& msg) {
                statusBar()->showMessage(msg, 3000);
            });

    if (!filepath.isEmpty())
        tab->loadFile(filepath);
    else
        tab->onOpenClicked();
}

// ─── buildTab_IPS ─────────────────────────────────────────────────────────────
//
//  Layout:
//    ┌─────────────────────────────────────────────────────────┐
//    │  [IpsControlWidget 320px]  │  [Live Alert Feed]        │
//    │                            │                            │
//    │  - Toggle Detection        │  AlertPanel (full height) │
//    │  - Toggle ML               │                            │
//    │  - Engine status           │                            │
//    └─────────────────────────────────────────────────────────┘
// ─────────────────────────────────────────────────────────────────────────────

QWidget* MainWindow::buildTab_IPS() {
    auto* container = new QWidget(tab_widget_);
    auto* layout    = new QHBoxLayout(container);
    layout->setSpacing(8);
    layout->setContentsMargins(10, 10, 10, 10);

    // ── Left: IPS controls ────────────────────────────────────────────────────
    ips_widget_ = new IpsControlWidget(container);
    ips_widget_->setFixedWidth(320);
    layout->addWidget(ips_widget_);

    // ── Separator ─────────────────────────────────────────────────────────────
    auto* sep = new QFrame(container);
    sep->setFrameShape(QFrame::VLine);
    sep->setStyleSheet("color: #c5cae9; background: #c5cae9;");
    sep->setFixedWidth(1);
    layout->addWidget(sep);

    // ── Right: Live Alert Feed ────────────────────────────────────────────────
    auto* right     = new QWidget(container);
    auto* right_lay = new QVBoxLayout(right);
    right_lay->setSpacing(6);
    right_lay->setContentsMargins(0, 0, 0, 0);

    auto* feed_label = new QLabel("🚨  Live Alert Feed", right);
    feed_label->setStyleSheet(
        "font-size: 13px; font-weight: bold; color: #3355cc;"
        "background: transparent; padding: 2px 0;");
    right_lay->addWidget(feed_label);

    alert_panel_ips_ = new AlertPanel(right);
    right_lay->addWidget(alert_panel_ips_, 1);

    layout->addWidget(right, 1);
    return container;
}

// ─── buildTab_Firewall ────────────────────────────────────────────────────────

QWidget* MainWindow::buildTab_Firewall() {
    firewall_tab_ = new FirewallWidget(tab_widget_);

    // Kết nối statusMessage → statusBar
    connect(firewall_tab_, &FirewallWidget::statusMessage,
            this, [this](const QString& msg) {
                statusBar()->showMessage(msg, 4000);
            });

    // QUAN TRỌNG: gọi ngay tại đây, trước khi widget được show
    // firewall_manager_ đã được gán trong constructor trước khi setupUI()
    if (firewall_manager_) {
        firewall_tab_->setFirewallManager(firewall_manager_);
    }

    return firewall_tab_;
}

// ─── buildTab_Statistics ──────────────────────────────────────────────────────
//
//  Chỉ giữ TrafficChart + MetricsWidget (bỏ stats panel cũ)
//
//  Layout:
//    ┌──────────────────────────────────────────┐
//    │  [MetricsWidget — cards hàng ngang]      │  ← fixed height 120px
//    ├──────────────────────────────────────────┤
//    │  📈 Traffic Monitor                      │
//    │  [TrafficChart — chiếm phần còn lại]     │
//    └──────────────────────────────────────────┘
// ─────────────────────────────────────────────────────────────────────────────

QWidget* MainWindow::buildTab_Statistics() {
    auto* container = new QWidget(tab_widget_);
    auto* layout    = new QVBoxLayout(container);
    layout->setSpacing(8);
    layout->setContentsMargins(10, 10, 10, 10);

    // ── Chart label ───────────────────────────────────────────────────────────
    auto* chart_label = new QLabel("📈  Traffic Monitor", container);
    chart_label->setStyleSheet(
        "font-size: 13px; font-weight: bold; color: #3355cc;"
        "background: transparent; padding: 2px 0;");
    layout->addWidget(chart_label);

    // ── Traffic chart (chiếm toàn bộ phần còn lại) ───────────────────────────
    traffic_chart_ = new TrafficChart(container);
    layout->addWidget(traffic_chart_, 1);

    return container;
}

// ═══════════════════════════════════════════════════════════════════════════════
// setupMenuBar
// ═══════════════════════════════════════════════════════════════════════════════

void MainWindow::setupMenuBar() {
    // ── File ──────────────────────────────────────────────────────────────────
    auto* file_menu = menuBar()->addMenu("&File");

    auto* open_act = new QAction("📂  Open PCAP File…", this);
    open_act->setShortcut(QKeySequence::Open);
    connect(open_act, &QAction::triggered,
            this, [this]() { addPcapTab(); });
    file_menu->addAction(open_act);

    file_menu->addSeparator();

    act_start_cap_ = new QAction("▶  Start Live Capture…", this);
    act_start_cap_->setShortcut(QKeySequence("Ctrl+Shift+S"));
    connect(act_start_cap_, &QAction::triggered,
            this, &MainWindow::onStartCaptureClicked);
    file_menu->addAction(act_start_cap_);

    act_stop_cap_ = new QAction("■  Stop Capture", this);
    act_stop_cap_->setShortcut(QKeySequence("Ctrl+Shift+X"));
    act_stop_cap_->setEnabled(false);
    connect(act_stop_cap_, &QAction::triggered,
            this, &MainWindow::onStopCaptureClicked);
    file_menu->addAction(act_stop_cap_);

    act_save_cap_ = new QAction("💾  Save Capture As…", this);
    act_save_cap_->setShortcut(QKeySequence("Ctrl+Shift+W"));
    act_save_cap_->setEnabled(false);
    connect(act_save_cap_, &QAction::triggered,
            this, &MainWindow::onSaveCaptureClicked);
    file_menu->addAction(act_save_cap_);

    file_menu->addSeparator();
    auto* quit_act = new QAction("&Quit", this);
    quit_act->setShortcut(QKeySequence::Quit);
    connect(quit_act, &QAction::triggered, qApp, &QApplication::quit);
    file_menu->addAction(quit_act);

    // ── IPS ───────────────────────────────────────────────────────────────────
    auto* ips_menu = menuBar()->addMenu("🛡️  &IPS");

    act_toggle_det_ = new QAction("🔍  Detection Engine: ENABLED", this);
    act_toggle_det_->setShortcut(QKeySequence("Ctrl+D"));
    act_toggle_det_->setCheckable(true);
    act_toggle_det_->setChecked(true);
    connect(act_toggle_det_, &QAction::triggered,
            this, [this](bool on) {
                if (ui_bridge_) ui_bridge_->setDetectionEnabled(on);
            });
    ips_menu->addAction(act_toggle_det_);

    act_toggle_ml_ = new QAction("🤖  ML Engine: ENABLED", this);
    act_toggle_ml_->setShortcut(QKeySequence("Ctrl+M"));
    act_toggle_ml_->setCheckable(true);
    act_toggle_ml_->setChecked(true);
    connect(act_toggle_ml_, &QAction::triggered,
            this, [this](bool on) {
                if (ui_bridge_) ui_bridge_->setMlEnabled(on);
            });
    ips_menu->addAction(act_toggle_ml_);

    ips_menu->addSeparator();

    auto* enable_all = new QAction("✅  Enable All Engines", this);
    connect(enable_all, &QAction::triggered, this, [this]() {
        if (ui_bridge_) {
            ui_bridge_->setDetectionEnabled(true);
            ui_bridge_->setMlEnabled(true);
        }
    });
    ips_menu->addAction(enable_all);

    auto* disable_all = new QAction("⛔  Disable All Engines", this);
    connect(disable_all, &QAction::triggered, this, [this]() {
        if (ui_bridge_) {
            ui_bridge_->setDetectionEnabled(false);
            ui_bridge_->setMlEnabled(false);
        }
    });
    ips_menu->addAction(disable_all);

    ips_menu->addSeparator();
    auto* show_ips = new QAction("🛡️  Show IPS Tab", this);
    show_ips->setShortcut(QKeySequence("Ctrl+3"));
    connect(show_ips, &QAction::triggered, this,
            [this]() { tab_widget_->setCurrentIndex(2); });
    ips_menu->addAction(show_ips);

    // ── Firewall ──────────────────────────────────────────────────────────────
    setupFirewallMenu();

    // ── View ──────────────────────────────────────────────────────────────────
    auto* view_menu = menuBar()->addMenu("&View");

    // ── 5 tabs (bỏ Alerts) ────────────────────────────────────────────────────
    struct TabEntry { QString name; int idx; QString sc; };
    const TabEntry tabs[] = {
        { "📡  Live Capture",    0, "Ctrl+1" },
        { "📂  File Analysis",   1, "Ctrl+2" },
        { "🛡️  IPS / Detection", 2, "Ctrl+3" },
        { "🔥  Firewall",        3, "Ctrl+4" },
        { "📊  Statistics",      4, "Ctrl+5" },
    };
    for (const auto& t : tabs) {
        auto* act = new QAction(t.name, this);
        act->setShortcut(QKeySequence(t.sc));
        const int idx = t.idx;
        connect(act, &QAction::triggered, this,
                [this, idx]() { tab_widget_->setCurrentIndex(idx); });
        view_menu->addAction(act);
    }

    // ── Help ──────────────────────────────────────────────────────────────────
    auto* help_menu = menuBar()->addMenu("&Help");
    auto* about_act = new QAction("&About", this);
    connect(about_act, &QAction::triggered, this, &MainWindow::onAbout);
    help_menu->addAction(about_act);

    menuBar()->setStyleSheet(
        "QMenuBar {"
        "  background: #1e2a4a; color: #ddeeff;"
        "  border-bottom: 1px solid #3355cc; font-size: 12px;"
        "}"
        "QMenuBar::item:selected { background: #2a3a6a; }"
        "QMenu {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #b0b8d8; font-size: 12px;"
        "}"
        "QMenu::item:selected { background: #dde8ff; color: #0a0a6e; }"
        "QMenu::separator { height: 1px; background: #c5cae9;"
        "                   margin: 3px 8px; }");
}

// ─── setupFirewallMenu ────────────────────────────────────────────────────────

void MainWindow::setupFirewallMenu() {
    auto* fw_menu = menuBar()->addMenu("🔥  &Firewall");

    act_fw_block_ = new QAction("⛔  Block IP…", this);
    act_fw_block_->setShortcut(QKeySequence("Ctrl+B"));
    act_fw_block_->setEnabled(firewall_manager_ != nullptr);
    connect(act_fw_block_, &QAction::triggered, this, [this]() {
        if (!firewall_manager_ || !ui_bridge_) return;
        bool ok = false;
        const QString ip = QInputDialog::getText(
            this, "Block IP", "Enter IP address to block:",
            QLineEdit::Normal, "", &ok);
        if (!ok || ip.trimmed().isEmpty()) return;
        ui_bridge_->blockIp(ip.trimmed(), "Manual block via menu");
        statusBar()->showMessage(
            QString("⛔  Blocked: %1").arg(ip.trimmed()), 4000);
    });
    fw_menu->addAction(act_fw_block_);

    act_fw_unblock_ = new QAction("✅  Unblock IP…", this);
    act_fw_unblock_->setShortcut(QKeySequence("Ctrl+U"));
    act_fw_unblock_->setEnabled(firewall_manager_ != nullptr);
    connect(act_fw_unblock_, &QAction::triggered, this, [this]() {
        if (!firewall_manager_ || !ui_bridge_) return;
        bool ok = false;
        const QString ip = QInputDialog::getText(
            this, "Unblock IP", "Enter IP address to unblock:",
            QLineEdit::Normal, "", &ok);
        if (!ok || ip.trimmed().isEmpty()) return;
        ui_bridge_->unblockIp(ip.trimmed());
        statusBar()->showMessage(
            QString("✅  Unblocked: %1").arg(ip.trimmed()), 4000);
    });
    fw_menu->addAction(act_fw_unblock_);

    fw_menu->addSeparator();

    auto* act_flush = new QAction("🗑  Flush Blacklist", this);
    act_flush->setEnabled(firewall_manager_ != nullptr);
    connect(act_flush, &QAction::triggered, this, [this]() {
        if (!firewall_manager_) return;
        if (QMessageBox::question(
                this, "Flush Blacklist",
                "Remove ALL blacklist rules?\n(Whitelist rules will be kept)",
                QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes)
            return;
        const auto rules = firewall_manager_->listBlacklist();
        for (const auto& r : rules) firewall_manager_->removeRule(r.id);
        statusBar()->showMessage(
            QString("🗑  Flushed %1 blacklist rule(s)").arg(rules.size()),
            4000);
    });
    fw_menu->addAction(act_flush);

    fw_menu->addSeparator();

    act_fw_save_ = new QAction("💾  Save Firewall Rules", this);
    act_fw_save_->setShortcut(QKeySequence("Ctrl+Shift+F"));
    act_fw_save_->setEnabled(firewall_manager_ != nullptr);
    connect(act_fw_save_, &QAction::triggered, this, [this]() {
        if (!firewall_manager_) return;
        const QString path = QFileDialog::getSaveFileName(
            this, "Save Firewall Rules",
            "/etc/ids/firewall_rules.json",
            "JSON Files (*.json);;All Files (*)");
        if (path.isEmpty()) return;
        statusBar()->showMessage(
            firewall_manager_->saveRules(path.toStdString())
                ? QString("💾  Rules saved → %1").arg(path)
                : QString("❌  Failed to save → %1").arg(path),
            4000);
    });
    fw_menu->addAction(act_fw_save_);

    auto* act_load = new QAction("📂  Load Firewall Rules…", this);
    act_load->setEnabled(firewall_manager_ != nullptr);
    connect(act_load, &QAction::triggered, this, [this]() {
        if (!firewall_manager_) return;
        const QString path = QFileDialog::getOpenFileName(
            this, "Load Firewall Rules", "/etc/ids/",
            "JSON Files (*.json);;All Files (*)");
        if (path.isEmpty()) return;
        const bool ok = firewall_manager_->loadRules(path.toStdString());
        if (ok && firewall_tab_) firewall_tab_->refresh();
        statusBar()->showMessage(
            ok ? QString("📂  Rules loaded ← %1").arg(path)
               : QString("❌  Failed to load ← %1").arg(path),
            4000);
    });
    fw_menu->addAction(act_load);

    fw_menu->addSeparator();
    auto* show_fw = new QAction("🔥  Show Firewall Tab", this);
    show_fw->setShortcut(QKeySequence("Ctrl+4"));
    connect(show_fw, &QAction::triggered, this,
            [this]() { tab_widget_->setCurrentIndex(3); });
    fw_menu->addAction(show_fw);
}

// ═══════════════════════════════════════════════════════════════════════════════
// setupStatusBar
// ═══════════════════════════════════════════════════════════════════════════════

void MainWindow::setupStatusBar() {
    statusBar()->setStyleSheet(
        "QStatusBar {"
        "  background: #e8eaf6; color: #444466;"
        "  border-top: 1px solid #c5cae9; font-size: 11px;"
        "}");

    const auto mkLabel = [this](const QString& txt,
                                 const QString& style) -> QLabel* {
        auto* l = new QLabel(txt, this);
        l->setStyleSheet(style);
        return l;
    };
    const QString sep_s  = "color: #b0b8d8; background: transparent;";
    const QString base_s = "background: transparent;";

    status_state_ = mkLabel("  ● READY  ",
        "color: #228822; font-weight: bold; font-size: 11px;" + base_s);

    status_iface_ = mkLabel("",
        "color: #3355cc; font-size: 11px; font-weight: bold;" + base_s);
    status_iface_->hide();

    status_ips_mode_ = mkLabel("  🛡️ IPS  ",
        "color: #116611; font-size: 11px; font-weight: bold;"
        "background: #e8f8e8; border: 1px solid #88cc88;"
        "border-radius: 3px; padding: 1px 6px;");

    status_fw_badge_ = mkLabel(
        firewall_manager_ ? "  🔴 BL:0  🟢 WL:0  " : "  🔥 FW:OFF  ",
        firewall_manager_
            ? "color: #884400; font-size: 11px; font-weight: bold;"
              "background: #fff4e0; border: 1px solid #ddaa44;"
              "border-radius: 3px; padding: 1px 6px;"
            : "color: #888888; font-size: 11px;"
              "background: #f0f0f0; border: 1px solid #cccccc;"
              "border-radius: 3px; padding: 1px 6px;");

    status_uptime_ = mkLabel("  Uptime: 00:00:00  ",
        "color: #888899; font-size: 11px;" + base_s);

    statusBar()->addWidget(status_state_);
    statusBar()->addWidget(mkLabel("  |  ", sep_s));
    statusBar()->addWidget(status_iface_);
    statusBar()->addWidget(status_ips_mode_);
    statusBar()->addWidget(mkLabel("  |  ", sep_s));
    statusBar()->addWidget(status_fw_badge_);
    statusBar()->addPermanentWidget(status_uptime_);
}

// ═══════════════════════════════════════════════════════════════════════════════
// IPS badge
// ═══════════════════════════════════════════════════════════════════════════════

void MainWindow::onDetectionToggled(bool enabled) {
    act_toggle_det_->setChecked(enabled);
    act_toggle_det_->setText(enabled
        ? "🔍  Detection Engine: ENABLED"
        : "🔍  Detection Engine: DISABLED");
    updateIpsModeBadge();
}

void MainWindow::onMlToggled(bool enabled) {
    act_toggle_ml_->setChecked(enabled);
    act_toggle_ml_->setText(enabled
        ? "🤖  ML Engine: ENABLED"
        : "🤖  ML Engine: DISABLED");
    updateIpsModeBadge();
}

void MainWindow::updateIpsModeBadge() {
    const bool det = ENGINE_CFG.detection_enabled.load(std::memory_order_relaxed);
    const bool ml  = ENGINE_CFG.ml_enabled       .load(std::memory_order_relaxed);

    struct Badge { QString text, light_style, dark_style; };
    Badge b;

    if (det && ml) {
        b = { "🛡️ IPS",
              "color:#116611;background:#e8f8e8;border:1px solid #88cc88;",
              "color:#00ff88;background:#0a2a0a;border:1px solid #226622;" };
    } else if (det) {
        b = { "🔍 IDS",
              "color:#114488;background:#e8eeff;border:1px solid #88aadd;",
              "color:#44aaff;background:#0a1a2a;border:1px solid #224466;" };
    } else if (ml) {
        b = { "🤖 ML",
              "color:#551188;background:#f0e8ff;border:1px solid #aa88dd;",
              "color:#aa66ff;background:#1a0a2a;border:1px solid #663388;" };
    } else {
        b = { "⛔ OFF",
              "color:#884444;background:#fff0f0;border:1px solid #dd8888;",
              "color:#ff6666;background:#2a0a0a;border:1px solid #882222;" };
    }

    const QString base_sb =
        "font-size:11px;font-weight:bold;border-radius:3px;padding:1px 6px;";
    const QString base_tb =
        "font-size:11px;font-weight:bold;border-radius:4px;padding:2px 10px;";

    if (status_ips_mode_) {
        status_ips_mode_->setText("  " + b.text + "  ");
        status_ips_mode_->setStyleSheet(b.light_style + base_sb);
    }
    if (lbl_ips_badge_) {
        lbl_ips_badge_->setText("  " + b.text + "  ");
        lbl_ips_badge_->setStyleSheet(b.dark_style + base_tb);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Capture helpers
// ═══════════════════════════════════════════════════════════════════════════════

void MainWindow::setCaptureRunningState(bool running) {
    capture_running_ = running;

    act_start_cap_->setEnabled(!running);
    act_stop_cap_ ->setEnabled(running);
    act_save_cap_ ->setEnabled(running);
    btn_start_cap_->setEnabled(!running);
    btn_stop_cap_ ->setEnabled(running);
    btn_save_cap_ ->setEnabled(running);

    if (running) {
        status_state_->setText("  🔴 CAPTURING  ");
        status_state_->setStyleSheet(
            "color: #cc2222; font-weight: bold; font-size: 11px;"
            "background: transparent;");
    } else {
        status_state_->setText("  ■ STOPPED  ");
        status_state_->setStyleSheet(
            "color: #888888; font-weight: bold; font-size: 11px;"
            "background: transparent;");
        status_iface_->hide();
        lbl_iface_->setText("No interface selected");
    }
}

void MainWindow::onStartCaptureClicked() {
    if (capture_running_) {
        QMessageBox::information(this, "Capture Running",
            QString("Already capturing on: <b>%1</b><br>"
                    "Stop current capture first.").arg(capture_iface_));
        return;
    }

    CaptureControlDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted) return;

    const QString iface  = dlg.selectedInterface();
    const QString filter = dlg.bpfFilter();

    if (iface.isEmpty()) {
        QMessageBox::warning(this, "No Interface",
            "Please select a network interface.");
        return;
    }

    startLiveCapture(iface, filter);
}

void MainWindow::startLiveCapture(const QString& iface,
                                   const QString& filter) {
    if (capture_thread_ && capture_thread_->joinable())
        capture_thread_->join();
    capture_thread_.reset();

    capture_iface_ = iface;

    const QString temp_path = QDir::tempPath()
        + QString("/ids_capture_%1.pcap")
              .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"));

    live_tab_->startLiveWriter(temp_path);
    setCaptureRunningState(true);

    const QString iface_label = filter.isEmpty()
        ? iface : QString("%1  |  %2").arg(iface, filter);
    status_iface_->setText("  " + iface_label + "  ");
    status_iface_->show();
    lbl_iface_->setText(iface_label);

    tab_widget_->setCurrentIndex(0);

    active_capture_ = std::make_shared<PacketCapture>();

    capture_thread_ = std::make_unique<std::thread>(
        [this,
         iface_str     = iface.toStdString(),
         filter_str    = filter.toStdString(),
         temp_path_str = temp_path.toStdString(),
         capture       = active_capture_]()
    {
        if (!capture->openLive(iface_str, filter_str)) {
            QMetaObject::invokeMethod(this, [this, iface_str]() {
                active_capture_.reset();
                live_tab_->stopLiveWriter();
                setCaptureRunningState(false);
                QMessageBox::critical(this, "Capture Error",
                    QString("Cannot open interface: <b>%1</b>")
                        .arg(QString::fromStdString(iface_str)));
            }, Qt::QueuedConnection);
            return;
        }

        capture->startCapture(
            [this, temp_path_str]
            (PacketInfo pkt, const uint8_t* raw_bytes, uint32_t raw_len)
        {
            if (!capture_running_.load(std::memory_order_relaxed)) return;

            const int64_t offset = live_tab_->writeLivePacket(
                raw_bytes, raw_len, pkt.orig_len, pkt.timestamp);

            pkt.file_offset = offset;
            pkt.source_file = temp_path_str;
            pkt.raw_data    = std::make_shared<std::vector<uint8_t>>(
                                  raw_bytes, raw_bytes + raw_len);

            dispatcher_.dispatch(std::move(pkt));
        });

        capture->waitForStop();

        QMetaObject::invokeMethod(this, [this]() {
            active_capture_.reset();
            live_tab_->stopLiveWriter();
            setCaptureRunningState(false);
            statusBar()->showMessage(
                QString("■  Capture stopped  —  %1").arg(capture_iface_),
                5000);
        }, Qt::QueuedConnection);
    });
}

void MainWindow::stopLiveCapture() {
    if (!capture_running_) return;
    capture_running_ = false;
    if (active_capture_) active_capture_->stopCapture();
}

void MainWindow::onStopCaptureClicked()  { stopLiveCapture(); }

void MainWindow::onSaveCaptureClicked() {
    const QString path = QFileDialog::getSaveFileName(
        this, "Save Capture",
        QDir::homePath()
            + QString("/capture_%1.pcap")
                  .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss")),
        "PCAP Files (*.pcap);;All Files (*)");
    if (path.isEmpty()) return;
    live_tab_->saveToFile(path);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Uptime / About / closeEvent
// ═══════════════════════════════════════════════════════════════════════════════

void MainWindow::updateUptime() {
    const int s = start_time_.secsTo(QTime::currentTime());
    status_uptime_->setText(
        QString("  Uptime: %1:%2:%3  ")
            .arg(s / 3600,        2, 10, QChar('0'))
            .arg((s % 3600) / 60, 2, 10, QChar('0'))
            .arg(s % 60,          2, 10, QChar('0')));
}

void MainWindow::onAbout() {
    QMessageBox::about(this, "About Network IDS/IPS",
        "<b style='font-size:14px'>Network IDS/IPS Monitor</b><br>"
        "<span style='color:#666666'>Version 0.1.0 — HVKTQS 2025</span>"
        "<br><br>"
        "<i>Đề tài NCKH: Xây dựng Hệ thống Giám sát và<br>"
        "Phân tích Mạng Dựa trên Công nghệ AI</i>"
        "<br><br>"
        "<b>Tabs:</b><br>"
        "&nbsp;&nbsp;📡 <b>Live Capture</b> — bắt gói tin realtime<br>"
        "&nbsp;&nbsp;📂 <b>File Analysis</b> — phân tích PCAP offline<br>"
        "&nbsp;&nbsp;🛡️ <b>IPS/Detection</b> — quản lý engine + live alerts<br>"
        "&nbsp;&nbsp;🔥 <b>Firewall</b> — blacklist / whitelist<br>"
        "&nbsp;&nbsp;📊 <b>Statistics</b> — metrics cards & traffic chart<br>"
        "<br>"
        "<b>IPS Modes:</b><br>"
        "&nbsp;&nbsp;🛡️ <b>IPS</b> — Detection + ML enabled<br>"
        "&nbsp;&nbsp;🔍 <b>IDS</b> — Detection only<br>"
        "&nbsp;&nbsp;🤖 <b>ML</b>  — ML only<br>"
        "&nbsp;&nbsp;⛔ <b>OFF</b> — Monitor only<br>"
        "<br>"
        "<b>Firewall:</b><br>"
        "&nbsp;&nbsp;🔴 Blacklist — auto-block từ detection engine<br>"
        "&nbsp;&nbsp;🟢 Whitelist — bypass detection hoàn toàn");
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (ui_bridge_) ui_bridge_->stopPolling();
    stopLiveCapture();
    if (capture_thread_ && capture_thread_->joinable())
        capture_thread_->join();
    event->accept();
}
