// ── main_window.cpp ───────────────────────────────────────────────────────────
#include "main_window.hpp"

// Full includes chỉ trong .cpp — tránh MOC redefinition
#include "pcap_tab.hpp"
#include "alert_panel.hpp"
#include "metrics_widget.hpp"
#include "traffic_chart.hpp"
#include "ui_bridge.hpp"

#include <QApplication>
#include <QMenuBar>
#include <QCloseEvent>
#include <QMessageBox>
#include <QSplitter>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QStatusBar>
// ─── Constructor ──────────────────────────────────────────────────────────────
MainWindow::MainWindow(AlertManager&     alert_manager,
                       Dispatcher&       dispatcher,
                       MLEngine&         ml_engine,
                       PacketRingBuffer& ring_buf,
                       QWidget*          parent)
    : QMainWindow(parent)
    , bridge_(std::make_unique<UiBridge>(
          alert_manager, dispatcher, ml_engine, ring_buf, this))
    , start_time_(QTime::currentTime())
{
    setWindowTitle("🛡️  Network IDS/IPS Monitor — HVKTQS 2025");
    setMinimumSize(1200, 700);
    resize(1400, 800);

    applyDarkTheme();
    setupUI();
    setupMenuBar();
    setupStatusBar();

    // ── UiBridge → Widgets ────────────────────────────────────────────────────
    connect(bridge_.get(), &UiBridge::metricsUpdated,
            metrics_widget_, &MetricsWidget::onMetricsUpdated);
    connect(bridge_.get(), &UiBridge::metricsUpdated,
            this, &MainWindow::onMetricsUpdated);
    connect(bridge_.get(), &UiBridge::newAlerts,
            alert_panel_, &AlertPanel::onNewAlerts);
    connect(bridge_.get(), &UiBridge::trafficUpdated,
            traffic_chart_, &TrafficChart::onTrafficUpdated);
    connect(bridge_.get(), &UiBridge::systemStatusChanged,
            this, &MainWindow::onSystemStatusChanged);

    // ── Live packets → PcapTab (batch — không loop từng packet) ──────────────
    connect(bridge_.get(), &UiBridge::newPacketRecords,
            live_tab_, &PcapTab::appendLivePackets);

    // ── Uptime ────────────────────────────────────────────────────────────────
    connect(&uptime_timer_, &QTimer::timeout,
            this, &MainWindow::updateUptime);
    uptime_timer_.start(1000);

    bridge_->startPolling(200);
}

// ─── Destructor ───────────────────────────────────────────────────────────────
MainWindow::~MainWindow() {
    bridge_->stopPolling();
}

// ─── setupUI ──────────────────────────────────────────────────────────────────
void MainWindow::setupUI() {
    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* root_layout = new QVBoxLayout(central);
    root_layout->setSpacing(0);
    root_layout->setContentsMargins(6, 6, 6, 6);

    // Main splitter: left (metrics) | right (tabs)
    auto* h_splitter = new QSplitter(Qt::Horizontal, central);
    h_splitter->setHandleWidth(4);
    h_splitter->setStyleSheet("QSplitter::handle { background: #333344; }");

    // Left: MetricsWidget
    metrics_widget_ = new MetricsWidget(h_splitter);
    metrics_widget_->setFixedWidth(240);

    // Right: QTabWidget
    tab_widget_ = new QTabWidget(h_splitter);
    tab_widget_->setTabsClosable(true);
    tab_widget_->setMovable(true);
    tab_widget_->setStyleSheet(
        "QTabWidget::pane { border: 1px solid #333; background: #0f0f1a; }"
        "QTabBar::tab { background: #1a1a2e; color: #aaaaaa; "
        "border: 1px solid #333; padding: 5px 12px; margin-right: 2px; }"
        "QTabBar::tab:selected { background: #2a2a4a; color: #ffffff; "
        "border-bottom: 2px solid #4488ff; }"
        "QTabBar::tab:hover { background: #252540; }");

    // Tab 0: Live Capture
    live_tab_ = new PcapTab(PcapTab::Mode::LIVE, tab_widget_);
    tab_widget_->addTab(live_tab_, "🔴 Live Capture");

    // Tab 1: Traffic Chart
    traffic_chart_ = new TrafficChart(tab_widget_);
    tab_widget_->addTab(traffic_chart_, "📈 Traffic");

    // Tab 2: Alert Panel
    alert_panel_ = new AlertPanel(tab_widget_);
    tab_widget_->addTab(alert_panel_, "🚨 Alerts");

    // Nút "+" mở PCAP file mới
    auto* add_btn = new QPushButton("+", tab_widget_);
    add_btn->setFixedSize(24, 24);
    add_btn->setToolTip("Open PCAP file in new tab");
    add_btn->setStyleSheet(
        "QPushButton { background: #2a2a3e; color: #88aaff; "
        "border: 1px solid #444; border-radius: 3px; font-size: 14px; }"
        "QPushButton:hover { background: #3a3a5a; }");
    tab_widget_->setCornerWidget(add_btn, Qt::TopRightCorner);

    connect(add_btn, &QPushButton::clicked,
            this, [this]() { addPcapTab(); });

    // Bảo vệ 3 tab cố định (index 0, 1, 2)
    connect(tab_widget_, &QTabWidget::tabCloseRequested,
            this, [this](int index) {
                if (index < 3) return;
                QWidget* w = tab_widget_->widget(index);
                tab_widget_->removeTab(index);
                delete w;
            });

    h_splitter->addWidget(metrics_widget_);
    h_splitter->addWidget(tab_widget_);
    h_splitter->setSizes({240, 1160});
    root_layout->addWidget(h_splitter);
}

// ─── addPcapTab ───────────────────────────────────────────────────────────────
void MainWindow::addPcapTab(const QString& filepath) {
    auto* tab = new PcapTab(PcapTab::Mode::OFFLINE, tab_widget_);

    const int idx = tab_widget_->addTab(tab, "📂 New Tab");
    tab_widget_->setCurrentIndex(idx);

    connect(tab, &PcapTab::titleChanged,
            this, [this, tab](const QString& title) {
                const int i = tab_widget_->indexOf(tab);
                if (i >= 0) tab_widget_->setTabText(i, title);
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

// ─── setupMenuBar ─────────────────────────────────────────────────────────────
void MainWindow::setupMenuBar() {
    auto* file_menu = menuBar()->addMenu("&File");

    auto* open_act = new QAction("📂 Open PCAP File…", this);
    open_act->setShortcut(QKeySequence::Open);
    connect(open_act, &QAction::triggered,
            this, [this]() { addPcapTab(); });
    file_menu->addAction(open_act);

    auto* toggle_act = new QAction("⏸ Pause Monitoring", this);
    toggle_act->setShortcut(QKeySequence("Ctrl+P"));
    connect(toggle_act, &QAction::triggered,
            this, &MainWindow::onToggleCapture);
    file_menu->addAction(toggle_act);

    file_menu->addSeparator();

    auto* quit_act = new QAction("&Quit", this);
    quit_act->setShortcut(QKeySequence::Quit);
    connect(quit_act, &QAction::triggered, qApp, &QApplication::quit);
    file_menu->addAction(quit_act);

    auto* help_menu = menuBar()->addMenu("&Help");
    auto* about_act = new QAction("&About", this);
    connect(about_act, &QAction::triggered, this, &MainWindow::onAbout);
    help_menu->addAction(about_act);

    menuBar()->setStyleSheet(
        "QMenuBar { background: #1a1a2e; color: #cccccc; "
        "border-bottom: 1px solid #333; }"
        "QMenuBar::item:selected { background: #2a2a4a; }"
        "QMenu { background: #1a1a2e; color: #cccccc; border: 1px solid #444; }"
        "QMenu::item:selected { background: #2a2a4a; }");
}

// ─── setupStatusBar ───────────────────────────────────────────────────────────
void MainWindow::setupStatusBar() {
    status_running_ = new QLabel("  ● RUNNING  ", this);
    status_running_->setStyleSheet(
        "color: #00ff88; font-weight: bold; font-size: 11px;");

    status_pps_ = new QLabel("  0 pkt/s  ", this);
    status_pps_->setStyleSheet("color: #aaaaaa; font-size: 11px;");

    status_uptime_ = new QLabel("  Uptime: 00:00:00  ", this);
    status_uptime_->setStyleSheet("color: #888888; font-size: 11px;");

    statusBar()->addWidget(status_running_);
    statusBar()->addWidget(new QLabel(" | ", this));
    statusBar()->addWidget(status_pps_);
    statusBar()->addWidget(new QLabel(" | ", this));
    statusBar()->addPermanentWidget(status_uptime_);
    statusBar()->setStyleSheet(
        "QStatusBar { background: #0f0f1a; color: #888888; "
        "border-top: 1px solid #333; font-size: 11px; }");
}

// ─── applyDarkTheme ───────────────────────────────────────────────────────────
void MainWindow::applyDarkTheme() {
    setStyleSheet(
        "QMainWindow { background: #0f0f1a; }"
        "QWidget { background: #0f0f1a; color: #cccccc; }"
        "QScrollBar:vertical { background: #1a1a2e; width: 8px; }"
        "QScrollBar::handle:vertical { background: #444; "
        "border-radius: 4px; min-height: 20px; }"
        "QScrollBar::add-line:vertical, "
        "QScrollBar::sub-line:vertical { height: 0; }");
}

// ─── Slots ────────────────────────────────────────────────────────────────────
void MainWindow::onMetricsUpdated(MetricsSnapshot snapshot) {
    status_pps_->setText(
        QString("  %1 cap  |  %2 drop  ")
            .arg(snapshot.packets_captured)
            .arg(snapshot.packets_dropped));
}

void MainWindow::onSystemStatusChanged(bool running) {
    is_running_ = running;
    if (running) {
        status_running_->setText("  ● RUNNING  ");
        status_running_->setStyleSheet(
            "color: #00ff88; font-weight: bold; font-size: 11px;");
    } else {
        status_running_->setText("  ■ STOPPED  ");
        status_running_->setStyleSheet(
            "color: #ff4444; font-weight: bold; font-size: 11px;");
    }
}

void MainWindow::onToggleCapture() {
    is_running_ = !is_running_;
    if (is_running_) bridge_->startPolling(200);
    else             bridge_->stopPolling();
    onSystemStatusChanged(is_running_);
}

void MainWindow::updateUptime() {
    const int secs = start_time_.secsTo(QTime::currentTime());
    status_uptime_->setText(
        QString("  Uptime: %1:%2:%3  ")
            .arg(secs / 3600,        2, 10, QChar('0'))
            .arg((secs % 3600) / 60, 2, 10, QChar('0'))
            .arg(secs % 60,          2, 10, QChar('0')));
}

void MainWindow::onAbout() {
    QMessageBox::about(this,
        "About Network IDS/IPS",
        "<b>Network IDS/IPS Monitor</b><br>"
        "Version 0.1.0 — Lab Prototype<br><br>"
        "Học viện Kỹ thuật Quân sự — 2025<br>"
        "Layer 1: IPS Engine (Signature + Protocol Anomaly)<br>"
        "Layer 2: AI/ML Engine (Isolation Forest + Autoencoder)<br><br>"
        "<i>Đề tài NCKH: Xây dựng Hệ thống Giám sát và<br>"
        "Phân tích Mạng Dựa trên Công nghệ AI</i>");
}

void MainWindow::closeEvent(QCloseEvent* event) {
    bridge_->stopPolling();
    event->accept();
}
