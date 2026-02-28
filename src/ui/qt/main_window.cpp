#include "main_window.hpp"
#include <QApplication>
#include <QMenuBar>
#include <QCloseEvent>
#include <QMessageBox>
#include <QTime>
#include <QSplitter>

MainWindow::MainWindow(AlertManager& alert_manager,
                       Dispatcher&   dispatcher,
                       MLEngine&     ml_engine,
                       QWidget*      parent)
    : QMainWindow(parent)
    , bridge_(std::make_unique<UiBridge>(
          alert_manager, dispatcher, ml_engine, this))
    , start_time_(QTime::currentTime())
{
    setWindowTitle("🛡️  Network IDS/IPS Monitor — HVKTQS 2025");
    setMinimumSize(1200, 700);
    resize(1400, 800);

    applyDarkTheme();
    setupUI();
    setupMenuBar();
    setupStatusBar();

    // ── Connect UiBridge signals → widget slots ───────────────────────────────
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

    // ── Uptime timer ──────────────────────────────────────────────────────────
    connect(&uptime_timer_, &QTimer::timeout,
            this, &MainWindow::updateUptime);
    uptime_timer_.start(1000);

    // ── Start polling ─────────────────────────────────────────────────────────
    bridge_->startPolling(500);
}

MainWindow::~MainWindow() {
    bridge_->stopPolling();
}

void MainWindow::setupUI() {
    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* root_layout = new QVBoxLayout(central);
    root_layout->setSpacing(0);
    root_layout->setContentsMargins(6, 6, 6, 6);

    // ── Main splitter: left panel | right panel ───────────────────────────────
    auto* h_splitter = new QSplitter(Qt::Horizontal, central);
    h_splitter->setHandleWidth(4);
    h_splitter->setStyleSheet(
        "QSplitter::handle { background: #333344; }");

    // Left: Metrics widget (fixed width)
    metrics_widget_ = new MetricsWidget(h_splitter);
    metrics_widget_->setFixedWidth(240);

    // Right: vertical splitter (chart | alert panel)
    auto* v_splitter = new QSplitter(Qt::Vertical, h_splitter);
    v_splitter->setHandleWidth(4);
    v_splitter->setStyleSheet(
        "QSplitter::handle { background: #333344; }");

    traffic_chart_ = new TrafficChart(v_splitter);
    alert_panel_   = new AlertPanel(v_splitter);

    // Chart chiếm 35%, alert panel 65%
    v_splitter->setSizes({280, 520});

    h_splitter->addWidget(metrics_widget_);
    h_splitter->addWidget(v_splitter);
    h_splitter->setSizes({240, 1160});

    root_layout->addWidget(h_splitter);
}

void MainWindow::setupMenuBar() {
    // ── File menu ─────────────────────────────────────────────────────────────
    auto* file_menu = menuBar()->addMenu("&File");

    auto* toggle_act = new QAction("⏸ Pause Monitoring", this);
    toggle_act->setShortcut(QKeySequence("Ctrl+P"));
    connect(toggle_act, &QAction::triggered,
            this, &MainWindow::onToggleCapture);
    file_menu->addAction(toggle_act);

    file_menu->addSeparator();

    auto* quit_act = new QAction("&Quit", this);
    quit_act->setShortcut(QKeySequence::Quit);
    connect(quit_act, &QAction::triggered,
            qApp, &QApplication::quit);
    file_menu->addAction(quit_act);

    // ── Help menu ─────────────────────────────────────────────────────────────
    auto* help_menu = menuBar()->addMenu("&Help");
    auto* about_act = new QAction("&About", this);
    connect(about_act, &QAction::triggered,
            this, &MainWindow::onAbout);
    help_menu->addAction(about_act);

    menuBar()->setStyleSheet(
        "QMenuBar { background: #1a1a2e; color: #cccccc; "
        "border-bottom: 1px solid #333; }"
        "QMenuBar::item:selected { background: #2a2a4a; }"
        "QMenu { background: #1a1a2e; color: #cccccc; "
        "border: 1px solid #444; }"
        "QMenu::item:selected { background: #2a2a4a; }");
}

void MainWindow::setupStatusBar() {
    status_running_ = new QLabel("  ● RUNNING  ", this);
    status_running_->setStyleSheet(
        "color: #00ff88; font-weight: bold; font-size: 11px;");

    status_pps_ = new QLabel("  0 pkt/s  ", this);
    status_pps_->setStyleSheet("color: #aaaaaa; font-size: 11px;");

    status_uptime_ = new QLabel("  Uptime: 00:00:00  ", this);
    status_uptime_->setStyleSheet("color: #888888; font-size: 11px;");

    statusBar()->addWidget(status_running_);
    statusBar()->addWidget(new QLabel(" | "));
    statusBar()->addWidget(status_pps_);
    statusBar()->addWidget(new QLabel(" | "));
    statusBar()->addPermanentWidget(status_uptime_);

    statusBar()->setStyleSheet(
        "QStatusBar { background: #0f0f1a; color: #888888; "
        "border-top: 1px solid #333; font-size: 11px; }");
}

void MainWindow::applyDarkTheme() {
    setStyleSheet(
        "QMainWindow { background: #0f0f1a; }"
        "QWidget { background: #0f0f1a; color: #cccccc; }"
        "QScrollBar:vertical { background: #1a1a2e; width: 8px; }"
        "QScrollBar::handle:vertical { background: #444; "
        "border-radius: 4px; min-height: 20px; }"
        "QScrollBar::add-line:vertical, "
        "QScrollBar::sub-line:vertical { height: 0; }"
    );
}

// ─── Slots ────────────────────────────────────────────────────────────────────
void MainWindow::onMetricsUpdated(MetricsSnapshot snapshot) {
    status_pps_->setText(
        "  " + QString::number(snapshot.packets_captured) + " captured  ");
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
    if (is_running_)
        bridge_->startPolling(500);
    else
        bridge_->stopPolling();
    onSystemStatusChanged(is_running_);
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
        "Phân tích Mạng Dựa trên Công nghệ AI</i>"
    );
}

void MainWindow::updateUptime() {
    int secs  = start_time_.secsTo(QTime::currentTime());
    int h     = secs / 3600;
    int m     = (secs % 3600) / 60;
    int s     = secs % 60;
    status_uptime_->setText(
        QString("  Uptime: %1:%2:%3  ")
            .arg(h, 2, 10, QChar('0'))
            .arg(m, 2, 10, QChar('0'))
            .arg(s, 2, 10, QChar('0'))
    );
}

void MainWindow::closeEvent(QCloseEvent* event) {
    bridge_->stopPolling();
    event->accept();
}

