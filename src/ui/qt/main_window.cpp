// ── main_window.cpp ───────────────────────────────────────────────────────────
#include "main_window.hpp"

#include "pcap_tab.hpp"
#include "alert_panel.hpp"
#include "metrics_widget.hpp"
#include "traffic_chart.hpp"
#include "ui_bridge.hpp"
#include "capture_control_dialog.hpp"

#include "../../capture/packet_capture.hpp"
#include "../../common/packet_info.hpp"

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

    // ── Live packets từ IDS engine → PcapTab ─────────────────────────────────
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
    // Dừng capture trước khi destroy
    if (capture_running_) {
        capture_running_ = false;
        if (active_capture_)
            active_capture_->stopCapture();
    }
    if (capture_thread_ && capture_thread_->joinable())
        capture_thread_->join();

    bridge_->stopPolling();
}

// ─── setupUI ──────────────────────────────────────────────────────────────────
void MainWindow::setupUI() {
    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* root_layout = new QVBoxLayout(central);
    root_layout->setSpacing(0);
    root_layout->setContentsMargins(6, 6, 6, 6);

    auto* h_splitter = new QSplitter(Qt::Horizontal, central);
    h_splitter->setHandleWidth(4);
    h_splitter->setStyleSheet("QSplitter::handle { background: #333344; }");

    metrics_widget_ = new MetricsWidget(h_splitter);
    metrics_widget_->setFixedWidth(240);

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

    // ── Capture submenu ───────────────────────────────────────────────────────
    auto* cap_menu = file_menu->addMenu("🎛  Live Capture");

    act_start_cap_ = new QAction("▶  Start Capture…", this);
    act_start_cap_->setShortcut(QKeySequence("Ctrl+Shift+S"));
    act_start_cap_->setEnabled(true);
    connect(act_start_cap_, &QAction::triggered,
            this, &MainWindow::onStartCaptureClicked);
    cap_menu->addAction(act_start_cap_);

    act_stop_cap_ = new QAction("■  Stop Capture", this);
    act_stop_cap_->setShortcut(QKeySequence("Ctrl+Shift+X"));
    act_stop_cap_->setEnabled(false);   // disabled cho đến khi capture chạy
    connect(act_stop_cap_, &QAction::triggered,
            this, &MainWindow::onStopCaptureClicked);
    cap_menu->addAction(act_stop_cap_);

    cap_menu->addSeparator();

    act_save_cap_ = new QAction("💾  Save Capture As…", this);
    act_save_cap_->setShortcut(QKeySequence("Ctrl+Shift+W"));
    act_save_cap_->setEnabled(false);   // disabled cho đến khi có packet
    connect(act_save_cap_, &QAction::triggered,
            this, &MainWindow::onSaveCaptureClicked);
    cap_menu->addAction(act_save_cap_);

    file_menu->addSeparator();

    // ── Open PCAP ─────────────────────────────────────────────────────────────
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

    // ← interface label — ẩn khi chưa capture
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

// ═══════════════════════════════════════════════════════════════════════════════
// CAPTURE CONTROL
// ═══════════════════════════════════════════════════════════════════════════════

// ─── onStartCaptureClicked ────────────────────────────────────────────────────
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

// ─── startLiveCapture ─────────────────────────────────────────────────────────
void MainWindow::startLiveCapture(const QString& iface,
                                   const QString& filter) {
    capture_iface_   = iface;
    capture_running_ = true;

    // ── Update UI state ───────────────────────────────────────────────────────
    act_start_cap_->setEnabled(false);
    act_stop_cap_ ->setEnabled(true);
    act_save_cap_ ->setEnabled(true);

    status_iface_->setText(
        QString("  🔴 %1%2  ")
            .arg(iface)
            .arg(filter.isEmpty() ? "" : "  |  " + filter));
    status_iface_->show();

    // Switch sang live tab
    tab_widget_->setCurrentIndex(0);

    // ── Tạo PacketCapture instance ────────────────────────────────────────────
    active_capture_ = std::make_shared<PacketCapture>();

    // ── Capture thread ────────────────────────────────────────────────────────
    capture_thread_ = std::make_unique<std::thread>(
        [this, iface, filter,
         capture = active_capture_]()          // capture by value (shared_ptr)
    {
        // Mở interface
        if (!capture->openLive(iface.toStdString(),
                               filter.toStdString()))
        {
            QMetaObject::invokeMethod(this, [this, iface]() {
                capture_running_ = false;
                active_capture_.reset();

                act_start_cap_->setEnabled(true);
                act_stop_cap_ ->setEnabled(false);
                status_iface_->hide();

                QMessageBox::critical(this, "Capture Error",
                    QString(
                        "Failed to open interface: <b>%1</b><br><br>"
                        "Common causes:<br>"
                        "• No permission — run with <code>sudo</code> or:<br>"
                        "<code>sudo setcap cap_net_raw+eip &lt;binary&gt;</code><br>"
                        "• Interface does not exist or is down")
                    .arg(iface));
            }, Qt::QueuedConnection);
            return;
        }

        // Callback: mỗi packet từ pcap → PacketRecord → live_tab_
        capture->startCapture([this](PacketInfo pkt) {
            if (!capture_running_) return;

            // PacketInfo → PacketRecord
            PacketRecord rec;
            rec.timestamp   = pkt.timestampSeconds();
            rec.orig_len    = pkt.pkt_len;
            rec.src_ip      = pkt.src_ip;
            rec.dst_ip      = pkt.dst_ip;
            rec.src_port    = pkt.src_port;
            rec.dst_port    = pkt.dst_port;
            rec.protocol    = pkt.protocol;
            rec.eth_type    = pkt.eth_type;
            rec.tcp_flags   = pkt.tcp_flags;
            rec.payload_len = pkt.payload_len;
            rec.file_offset = -1;   // live — không có file offset

            if (!pkt.raw_data.empty())
                rec.raw_data = std::make_shared<std::vector<uint8_t>>(
                    std::move(pkt.raw_data));

            // Gửi lên UI thread (thread-safe, non-blocking)
            QMetaObject::invokeMethod(live_tab_,
                [this, r = std::move(rec)]() mutable {
                    live_tab_->appendLivePackets({r});
                }, Qt::QueuedConnection);
        });

        // startCapture() blocking — thoát sau stopCapture() / pcap_breakloop()
        QMetaObject::invokeMethod(this, [this]() {
            capture_running_ = false;
            active_capture_.reset();

            act_start_cap_->setEnabled(true);
            act_stop_cap_ ->setEnabled(false);
            status_iface_->hide();

            onSystemStatusChanged(false);
            statusBar()->showMessage(
                QString("■  Capture stopped  —  %1")
                    .arg(capture_iface_), 5000);
        }, Qt::QueuedConnection);
    });

    capture_thread_->detach();
}

// ─── onStopCaptureClicked ─────────────────────────────────────────────────────
void MainWindow::onStopCaptureClicked() {
    stopLiveCapture();
}

void MainWindow::stopLiveCapture() {
    if (!capture_running_) return;

    capture_running_ = false;

    if (active_capture_)
        active_capture_->stopCapture();   // pcap_breakloop() — thread-safe
}

// ─── onSaveCaptureClicked ─────────────────────────────────────────────────────
void MainWindow::onSaveCaptureClicked() {
    // Gợi ý tên file theo thời gian
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

    // Delegate sang live_tab_ — nó có ring_buf và PcapWriter
    live_tab_->saveToFile(path);

    statusBar()->showMessage(
        QString("💾  Saved: %1").arg(path), 5000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXISTING SLOTS — giữ nguyên
// ═══════════════════════════════════════════════════════════════════════════════

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
    // Dừng capture sạch trước khi thoát
    if (capture_running_) {
        capture_running_ = false;
        if (active_capture_)
            active_capture_->stopCapture();
    }
    bridge_->stopPolling();
    event->accept();
}
