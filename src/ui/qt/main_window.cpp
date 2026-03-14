#include "main_window.hpp"

#include "pcap_tab.hpp"
#include "alert_panel.hpp"
#include "metrics_widget.hpp"
#include "traffic_chart.hpp"
#include "ui_bridge.hpp"
#include "capture_control_dialog.hpp"

#include "../../capture/packet_capture.hpp"
#include "../../core/packet_info.hpp"

#include <QApplication>
#include <QMenuBar>
#include <QCloseEvent>
#include <QMessageBox>
#include <QSplitter>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QStatusBar>
#include <QFileDialog>
#include <QDateTime>
#include <QDir>


MainWindow::MainWindow(AlertManager&     alert_manager,
                       Dispatcher&       dispatcher,
                       MLEngine&         ml_engine,
                       PacketRingBuffer& ring_buf,
                       QWidget*          parent)
    : QMainWindow(parent)
    , ring_buf_(ring_buf)
    , bridge_(std::make_unique<UiBridge>(
          alert_manager, dispatcher, ml_engine, ring_buf, this))
    , start_time_(QTime::currentTime())
    , self_ref_(std::make_shared<MainWindow*>(this))
{
    setWindowTitle("🛡️  Network IDS/IPS Monitor — HVKTQS 2025");
    setMinimumSize(1200, 700);
    resize(1400, 800);

    applyDarkTheme();
    setupUI();
    setupMenuBar();
    setupStatusBar();

    // ── UiBridge → Widgets 
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

    // ── Live packets từ IDS engine → PcapTab 
    connect(bridge_.get(), &UiBridge::newPacketInfos,
            live_tab_, &PcapTab::appendLivePackets);


    connect(act_toggle_detection_, &QAction::toggled,
            bridge_.get(), &UiBridge::setDetectionEnabled);

    connect(bridge_.get(), &UiBridge::detectionStatusChanged,
            this, [this](bool enabled) {
                // Tránh vòng lặp signal: block signal khi setChecked
                QSignalBlocker blocker(act_toggle_detection_);
                act_toggle_detection_->setChecked(enabled);
                statusBar()->showMessage(
                    QString("Detection engine %1")
                        .arg(enabled ? "● ENABLED" : "○ DISABLED"), 3000);
            });

    // ── Toggle ML ─────────────────────────────────────────────────────────────
    connect(act_toggle_ml_, &QAction::toggled,
            bridge_.get(), &UiBridge::setMlEnabled);

    connect(bridge_.get(), &UiBridge::mlStatusChanged,
            this, [this](bool enabled) {
                QSignalBlocker blocker(act_toggle_ml_);
                act_toggle_ml_->setChecked(enabled);
                statusBar()->showMessage(
                    QString("ML engine %1")
                        .arg(enabled ? "● ENABLED" : "○ DISABLED"), 3000);
            });

    // ── Uptime timer 
    connect(&uptime_timer_, &QTimer::timeout,
            this, &MainWindow::updateUptime);
    uptime_timer_.start(1000);

    bridge_->startPolling(200);
}

MainWindow::~MainWindow() {
    capture_running_ = false;

    self_ref_.reset();

    if (active_capture_)
        active_capture_->stopCapture();

    if (capture_thread_ && capture_thread_->joinable())
        capture_thread_->join();

    bridge_->stopPolling();
}

void MainWindow::setupUI() {
    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* root_layout = new QVBoxLayout(central);
    root_layout->setSpacing(0);
    root_layout->setContentsMargins(6, 6, 6, 6);

    auto* h_splitter = new QSplitter(Qt::Horizontal, central);
    h_splitter->setHandleWidth(4);
    h_splitter->setStyleSheet(
        "QSplitter::handle { background: #333344; }");

    metrics_widget_ = new MetricsWidget(h_splitter);
    metrics_widget_->setFixedWidth(240);

    tab_widget_ = new QTabWidget(h_splitter);
    tab_widget_->setTabsClosable(true);
    tab_widget_->setMovable(true);
    tab_widget_->setStyleSheet(
        "QTabWidget::pane  { border: 1px solid #333; background: #0f0f1a; }"
        "QTabBar::tab      { background: #1a1a2e; color: #aaaaaa; "
        "                    border: 1px solid #333; padding: 5px 12px; "
        "                    margin-right: 2px; }"
        "QTabBar::tab:selected { background: #2a2a4a; color: #ffffff; "
        "                        border-bottom: 2px solid #4488ff; }"
        "QTabBar::tab:hover    { background: #252540; }");

    live_tab_ = new PcapTab(PcapTab::Mode::LIVE, tab_widget_);
    tab_widget_->addTab(live_tab_, "🔴 Live Capture");

    traffic_chart_ = new TrafficChart(tab_widget_);
    tab_widget_->addTab(traffic_chart_, "📈 Traffic");

    alert_panel_ = new AlertPanel(tab_widget_);
    tab_widget_->addTab(alert_panel_, "🚨 Alerts");

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

    connect(tab_widget_, &QTabWidget::tabCloseRequested,
            this, [this](int index) {
                if (index < 3) return;
                QWidget* w = tab_widget_->widget(index);
                tab_widget_->removeTab(index);
                delete w;
            });

    connect(tab_widget_, &QTabWidget::currentChanged,
            this, [this](int index) {
                if (tab_widget_->widget(index) == traffic_chart_)
                    traffic_chart_->forceResize();
            });

    // // ── Toggle Detection ──────────────────────────────────────────────────────────


    // connect(ui_bridge_.get(), &UiBridge::detectionStatusChanged,
    //         this, [this](bool enabled) {
    //             act_toggle_detection_->setChecked(enabled);
    //             statusBar()->showMessage(
    //                 QString("Detection engine %1")
    //                     .arg(enabled ? "● ENABLED" : "○ DISABLED"), 3000);
    //         });

    // // ── Toggle ML ─────────────────────────────────────────────────────────────────

    // connect(ui_bridge_.get(), &UiBridge::mlStatusChanged,
    //         this, [this](bool enabled) {
    //             act_toggle_ml_->setChecked(enabled);
    //             statusBar()->showMessage(
    //                 QString("ML engine %1")
    //                     .arg(enabled ? "● ENABLED" : "○ DISABLED"), 3000);
    //         });

    h_splitter->addWidget(metrics_widget_);
    h_splitter->addWidget(tab_widget_);
    h_splitter->setSizes({240, 1160});

    root_layout->addWidget(h_splitter);
}

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

void MainWindow::setupMenuBar() {
    auto* file_menu = menuBar()->addMenu("&File");

    auto* cap_menu = file_menu->addMenu("🎛  Live Capture");

    act_start_cap_ = new QAction("▶  Start Capture…", this);
    act_start_cap_->setShortcut(QKeySequence("Ctrl+Shift+S"));
    act_start_cap_->setEnabled(true);
    connect(act_start_cap_, &QAction::triggered,
            this, &MainWindow::onStartCaptureClicked);
    cap_menu->addAction(act_start_cap_);

    act_stop_cap_ = new QAction("■  Stop Capture", this);
    act_stop_cap_->setShortcut(QKeySequence("Ctrl+Shift+X"));
    act_stop_cap_->setEnabled(false);
    connect(act_stop_cap_, &QAction::triggered,
            this, &MainWindow::onStopCaptureClicked);
    cap_menu->addAction(act_stop_cap_);

    cap_menu->addSeparator();

    act_save_cap_ = new QAction("💾  Save Capture As…", this);
    act_save_cap_->setShortcut(QKeySequence("Ctrl+Shift+W"));
    act_save_cap_->setEnabled(false);
    connect(act_save_cap_, &QAction::triggered,
            this, &MainWindow::onSaveCaptureClicked);
    cap_menu->addAction(act_save_cap_);

    file_menu->addSeparator();

    // ── Engine toggles ────────────────────────────────────────────────────────
    auto* engine_menu = menuBar()->addMenu("&Engine");   // menu mới

    act_toggle_detection_ = new QAction("🔍 Detection Engine", this);
    act_toggle_detection_->setCheckable(true);
    act_toggle_detection_->setChecked(true);             // mặc định ON
    act_toggle_detection_->setShortcut(QKeySequence("Ctrl+D"));
    act_toggle_detection_->setToolTip("Bật/tắt Signature + Protocol Anomaly engine");
    engine_menu->addAction(act_toggle_detection_);

    act_toggle_ml_ = new QAction("🤖 ML Engine", this);
    act_toggle_ml_->setCheckable(true);
    act_toggle_ml_->setChecked(true);                    // mặc định ON
    act_toggle_ml_->setShortcut(QKeySequence("Ctrl+M"));
    act_toggle_ml_->setToolTip("Bật/tắt Isolation Forest + Autoencoder engine");
    engine_menu->addAction(act_toggle_ml_);

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

    status_iface_ = new QLabel("", this);
    status_iface_->setStyleSheet(
        "color: #44aaff; font-size: 11px; font-weight: bold;");
    status_iface_->hide();

    status_uptime_ = new QLabel("  Uptime: 00:00:00  ", this);
    status_uptime_->setStyleSheet("color: #888888; font-size: 11px;");

    statusBar()->addWidget(status_running_);
    statusBar()->addWidget(new QLabel(" | ", this));
    statusBar()->addWidget(status_pps_);
    statusBar()->addWidget(new QLabel(" | ", this));
    statusBar()->addWidget(status_iface_);
    statusBar()->addPermanentWidget(status_uptime_);
    statusBar()->setStyleSheet(
        "QStatusBar { background: #0f0f1a; color: #888888; "
        "border-top: 1px solid #333; font-size: 11px; }");
}

void MainWindow::applyDarkTheme() {
    setStyleSheet(
        "QMainWindow { background: #0f0f1a; }"
        "QWidget     { background: #0f0f1a; color: #cccccc; }"
        "QChartView  { background: transparent; }"
        "QScrollBar:vertical { background: #1a1a2e; width: 8px; }"
        "QScrollBar::handle:vertical { background: #444; "
        "border-radius: 4px; min-height: 20px; }"
        "QScrollBar::add-line:vertical, "
        "QScrollBar::sub-line:vertical { height: 0; }");
}

void MainWindow::onStartCaptureClicked() {
    if (capture_running_) {
        QMessageBox::information(this, "Capture Already Running",
            QString("Already capturing on: <b>%1</b><br>"
                    "Stop the current capture first.")
                .arg(capture_iface_));
        return;
    }

    CaptureControlDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted) return;

    const QString iface  = dlg.selectedInterface();
    const QString filter = dlg.bpfFilter();

    if (iface.isEmpty()) {
        QMessageBox::warning(this, "No Interface Selected",
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

    capture_iface_   = iface;
    capture_running_ = true;

    act_start_cap_->setEnabled(false);
    act_stop_cap_ ->setEnabled(true);
    act_save_cap_ ->setEnabled(true);

    status_iface_->setText(
        QString("  🔴 %1%2  ")
            .arg(iface)
            .arg(filter.isEmpty() ? "" : "  |  " + filter));
    status_iface_->show();
    tab_widget_->setCurrentIndex(0);

    active_capture_ = std::make_shared<PacketCapture>();

    std::weak_ptr<MainWindow*> weak_self = self_ref_;

    capture_thread_ = std::make_unique<std::thread>(
        [weak_self,
        iface,
        filter,
        capture        = active_capture_,
        live_tab       = live_tab_,
        &cap_running   = capture_running_]()
    {
        auto invoke_safe = [&weak_self](auto fn) {
            auto wp = weak_self;
            QMetaObject::invokeMethod(
                qApp,
                [wp, fn = std::move(fn)]() mutable {
                    if (!wp.expired()) fn();
                },
                Qt::QueuedConnection);
        };

        if (!capture->openLive(iface.toStdString(), filter.toStdString())) {
            invoke_safe([wp = weak_self, iface]() {
                if (wp.expired()) return;
                MainWindow* self = *wp.lock();
                self->capture_running_ = false;
                self->active_capture_.reset();
                self->act_start_cap_->setEnabled(true);
                self->act_stop_cap_ ->setEnabled(false);
                self->status_iface_->hide();
                QMessageBox::critical(self, "Capture Error",
                    QString("Failed to open interface: <b>%1</b>").arg(iface));
            });
            return;
        }

        capture->startCapture(
            [&cap_running, live_tab, wp = weak_self]
            (PacketInfo pkt)
        {
            if (!cap_running) return;

            PacketInfo out;
            out.timestamp   = pkt.timestamp;
            out.timestamp_d = pkt.timestamp_d;
            out.orig_len    = pkt.orig_len;
            out.cap_len     = pkt.cap_len;
            out.src_ip      = pkt.src_ip;
            out.dst_ip      = pkt.dst_ip;
            out.src_port    = pkt.src_port;
            out.dst_port    = pkt.dst_port;
            out.protocol    = pkt.protocol;
            out.eth_type    = pkt.eth_type;
            out.tcp_flags   = pkt.tcp_flags;
            out.payload_len = pkt.payload_len;
            out.src_ip6     = pkt.src_ip6;
            out.dst_ip6     = pkt.dst_ip6;
            out.ttl         = pkt.ttl;
            out.file_offset = -1;

            if (pkt.raw_data && !pkt.raw_data->empty())
                out.raw_data = std::move(pkt.raw_data);

            if (wp.expired()) return;
            QMetaObject::invokeMethod(
                live_tab,
                [live_tab, r = std::move(out)]() mutable {
                    live_tab->appendLivePackets({ std::move(r) });
                },
                Qt::QueuedConnection);
        });

        capture->waitForStop();  

        invoke_safe([wp = weak_self]() {
            if (wp.expired()) return;
            MainWindow* self = *wp.lock();
            self->capture_running_ = false;
            self->active_capture_.reset();
            self->act_start_cap_->setEnabled(true);
            self->act_stop_cap_ ->setEnabled(false);
            self->status_iface_->hide();
            self->onSystemStatusChanged(false);
            self->statusBar()->showMessage(
                QString("■  Capture stopped  —  %1")
                    .arg(self->capture_iface_), 5000);
        });
    });

}

void MainWindow::onStopCaptureClicked() {
    stopLiveCapture();
}

void MainWindow::stopLiveCapture() {
    if (!capture_running_) return;
    capture_running_ = false;

    if (active_capture_)
        active_capture_->stopCapture();  
}

void MainWindow::onSaveCaptureClicked() {
    const QString default_name =
        QString("capture_%1.pcap")
            .arg(QDateTime::currentDateTime()
                     .toString("yyyyMMdd_HHmmss"));

    const QString path = QFileDialog::getSaveFileName(
        this,
        "Save Capture As",
        QDir::homePath() + "/" + default_name,
        "PCAP Files (*.pcap);;All Files (*)");

    if (path.isEmpty()) return;

    live_tab_->saveToFile("/media/linhlinh/learn/nckh/network-ids/data/raw");
    statusBar()->showMessage(
        QString("💾  Saved: %1").arg(path), 5000);
}

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
    capture_running_ = false;
    self_ref_.reset();          

    if (active_capture_)
        active_capture_->stopCapture();

    if (capture_thread_ && capture_thread_->joinable())
        capture_thread_->join();

    bridge_->stopPolling();
    event->accept();
}
