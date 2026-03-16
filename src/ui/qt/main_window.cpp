#include "main_window.hpp"
#include "pcap_tab.hpp"
#include "capture_control_dialog.hpp"

#include "../../capture/packet_capture.hpp"
#include "../../common/engine_config.hpp"

#include <QApplication>
#include <QMenuBar>
#include <QStatusBar>
#include <QCloseEvent>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QFileDialog>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>

// ─── Constructor ──────────────────────────────────────────────────────────────
MainWindow::MainWindow(AlertManager&     alert_manager,
                       Dispatcher&       dispatcher,
                       MLEngine&         ml_engine,
                       PacketRingBuffer& ring_buf,
                       QWidget*          parent)
    : QMainWindow(parent)
    , alert_manager_(alert_manager)
    , dispatcher_   (dispatcher)
    , ml_engine_    (ml_engine)
    , ring_buf_     (ring_buf)
    , start_time_   (QTime::currentTime())
{
    setWindowTitle("🛡️  Network IDS/IPS — HVKTQS 2025");
    setMinimumSize(1200, 700);
    resize(1440, 860);

    applyDarkTheme();
    setupUI();
    setupMenuBar();
    setupStatusBar();

    // ── UiBridge ──────────────────────────────────────────────────────────────
    ui_bridge_ = std::make_unique<UiBridge>(
        alert_manager_, dispatcher_, ml_engine_, ring_buf_, this);

    live_tab_->setUiBridge(ui_bridge_.get());

    connect(ui_bridge_.get(), &UiBridge::detectionStatusChanged,
            this, &MainWindow::onDetectionToggled);
    connect(ui_bridge_.get(), &UiBridge::mlStatusChanged,
            this, &MainWindow::onMlToggled);

    ui_bridge_->startPolling(200);

    connect(&uptime_timer_, &QTimer::timeout,
            this, &MainWindow::updateUptime);
    uptime_timer_.start(1000);
}

// ─── Destructor ───────────────────────────────────────────────────────────────
MainWindow::~MainWindow() {
    ui_bridge_->stopPolling();
    stopLiveCapture();
    if (capture_thread_ && capture_thread_->joinable())
        capture_thread_->join();
}

// ─── setupUI ──────────────────────────────────────────────────────────────────
void MainWindow::setupUI() {
    auto* central = new QWidget(this);
    setCentralWidget(central);

    auto* layout = new QVBoxLayout(central);
    layout->setSpacing(0);
    layout->setContentsMargins(6, 6, 6, 6);

    tab_widget_ = new QTabWidget(central);
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
                if (index == 0) return;   // live tab không đóng được
                delete tab_widget_->widget(index);
            });

    layout->addWidget(tab_widget_);
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
    auto* cap_menu  = file_menu->addMenu("🎛  Live Capture");

    act_start_cap_ = new QAction("▶  Start Capture…", this);
    act_start_cap_->setShortcut(QKeySequence("Ctrl+Shift+S"));
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

    auto* open_act = new QAction("📂  Open PCAP File…", this);
    open_act->setShortcut(QKeySequence::Open);
    connect(open_act, &QAction::triggered,
            this, [this]() { addPcapTab(); });
    file_menu->addAction(open_act);

    file_menu->addSeparator();
    auto* quit_act = new QAction("&Quit", this);
    quit_act->setShortcut(QKeySequence::Quit);
    connect(quit_act, &QAction::triggered, qApp, &QApplication::quit);
    file_menu->addAction(quit_act);

    // ── IPS menu ──────────────────────────────────────────────────────────────
    auto* ips_menu = menuBar()->addMenu("🛡️ &IPS");

    act_toggle_det_ = new QAction("🔍  Detection Engine: ENABLED", this);
    act_toggle_det_->setShortcut(QKeySequence("Ctrl+D"));
    act_toggle_det_->setCheckable(true);
    act_toggle_det_->setChecked(true);
    connect(act_toggle_det_, &QAction::triggered, this, [this](bool checked) {
        if (ui_bridge_) ui_bridge_->setDetectionEnabled(checked);
    });
    ips_menu->addAction(act_toggle_det_);

    act_toggle_ml_ = new QAction("🤖  ML Engine: ENABLED", this);
    act_toggle_ml_->setShortcut(QKeySequence("Ctrl+M"));
    act_toggle_ml_->setCheckable(true);
    act_toggle_ml_->setChecked(true);
    connect(act_toggle_ml_, &QAction::triggered, this, [this](bool checked) {
        if (ui_bridge_) ui_bridge_->setMlEnabled(checked);
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

    // ── Help menu ─────────────────────────────────────────────────────────────
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
    status_state_ = new QLabel("  ● READY  ", this);
    status_state_->setStyleSheet(
        "color: #00ff88; font-weight: bold; font-size: 11px;");

    status_iface_ = new QLabel("", this);
    status_iface_->setStyleSheet(
        "color: #44aaff; font-size: 11px; font-weight: bold;");
    status_iface_->hide();

    status_ips_mode_ = new QLabel("  🛡️ IPS  ", this);
    status_ips_mode_->setStyleSheet(
        "color: #00ff88; font-size: 11px; font-weight: bold; "
        "background: #1a3a1a; border: 1px solid #336633; "
        "border-radius: 3px; padding: 1px 6px;");

    status_uptime_ = new QLabel("  Uptime: 00:00:00  ", this);
    status_uptime_->setStyleSheet("color: #888888; font-size: 11px;");

    statusBar()->addWidget(status_state_);
    statusBar()->addWidget(new QLabel(" | ", this));
    statusBar()->addWidget(status_iface_);
    statusBar()->addWidget(status_ips_mode_);
    statusBar()->addPermanentWidget(status_uptime_);
    statusBar()->setStyleSheet(
        "QStatusBar { background: #0f0f1a; color: #888888; "
        "border-top: 1px solid #333; font-size: 11px; }");
}

// ─── applyDarkTheme ───────────────────────────────────────────────────────────
void MainWindow::applyDarkTheme() {
    setStyleSheet(
        "QMainWindow { background: #0f0f1a; }"
        "QWidget     { background: #0f0f1a; color: #cccccc; }"
        "QScrollBar:vertical { background: #1a1a2e; width: 8px; }"
        "QScrollBar::handle:vertical { background: #444; "
        "border-radius: 4px; min-height: 20px; }"
        "QScrollBar::add-line:vertical, "
        "QScrollBar::sub-line:vertical { height: 0; }");
}

// ─── IPS toggle callbacks ─────────────────────────────────────────────────────
void MainWindow::onDetectionToggled(bool enabled) {
    act_toggle_det_->setChecked(enabled);
    act_toggle_det_->setText(enabled ? "🔍  Detection Engine: ENABLED"
                                     : "🔍  Detection Engine: DISABLED");
    updateIpsModeBadge();
}

void MainWindow::onMlToggled(bool enabled) {
    act_toggle_ml_->setChecked(enabled);
    act_toggle_ml_->setText(enabled ? "🤖  ML Engine: ENABLED"
                                    : "🤖  ML Engine: DISABLED");
    updateIpsModeBadge();
}

void MainWindow::updateIpsModeBadge() {
    const bool det = ENGINE_CFG.detection_enabled.load(std::memory_order_relaxed);
    const bool ml  = ENGINE_CFG.ml_enabled       .load(std::memory_order_relaxed);

    if (det && ml) {
        status_ips_mode_->setText("  🛡️ IPS  ");
        status_ips_mode_->setStyleSheet(
            "color: #00ff88; font-size: 11px; font-weight: bold; "
            "background: #1a3a1a; border: 1px solid #336633; "
            "border-radius: 3px; padding: 1px 6px;");
    } else if (det) {
        status_ips_mode_->setText("  🔍 IDS  ");
        status_ips_mode_->setStyleSheet(
            "color: #44aaff; font-size: 11px; font-weight: bold; "
            "background: #1a2a3a; border: 1px solid #224466; "
            "border-radius: 3px; padding: 1px 6px;");
    } else if (ml) {
        status_ips_mode_->setText("  🤖 ML  ");
        status_ips_mode_->setStyleSheet(
            "color: #aa66ff; font-size: 11px; font-weight: bold; "
            "background: #2a1a3a; border: 1px solid #663388; "
            "border-radius: 3px; padding: 1px 6px;");
    } else {
        status_ips_mode_->setText("  ⛔ OFF  ");
        status_ips_mode_->setStyleSheet(
            "color: #888888; font-size: 11px; font-weight: bold; "
            "background: #2a2a2a; border: 1px solid #555555; "
            "border-radius: 3px; padding: 1px 6px;");
    }
}

// ─── onStartCaptureClicked ────────────────────────────────────────────────────
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

// ─── startLiveCapture ─────────────────────────────────────────────────────────
//
//  Packet flow:
//    pcapCallback → RawPacketCallback(pkt, raw_bytes, raw_len)
//         │
//         ├─ 1. live_tab_->writeLivePacket() → disk → pkt.file_offset
//         ├─ 2. pkt.source_file = temp_path (std::string, captured by value)
//         ├─ 3. pkt.raw_data = copy(raw_bytes) → detection payload
//         └─ 4. ring_buf_.push(pkt)
//                   │
//                   ├─ Dispatcher → WorkerThread → detection
//                   └─ UiBridge polls → emit newPacketInfos → PcapTab (metadata only)
//
//  temp_path được tạo TRƯỚC khi spawn thread → capture bằng value vào lambda
// ─────────────────────────────────────────────────────────────────────────────
void MainWindow::startLiveCapture(const QString& iface,
                                   const QString& filter) {
    // Join thread cũ nếu còn
    if (capture_thread_ && capture_thread_->joinable())
        capture_thread_->join();
    capture_thread_.reset();

    capture_iface_   = iface;
    capture_running_ = true;

    // ── Tạo temp_path TRƯỚC khi spawn thread ─────────────────────────────────
    // Phải tạo ở đây (main thread) để:
    //   1. live_tab_->startLiveWriter() chạy trên main thread (Qt-safe)
    //   2. Lambda capture temp_path_str by value → không dangling reference
    const QString temp_path = QDir::tempPath()
        + QString("/ids_capture_%1.pcap")
              .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"));

    live_tab_->startLiveWriter(temp_path);   // mở PcapWriter trên main thread

    // ── Update UI ─────────────────────────────────────────────────────────────
    act_start_cap_->setEnabled(false);
    act_stop_cap_ ->setEnabled(true);
    act_save_cap_ ->setEnabled(true);

    status_state_->setText("  🔴 CAPTURING  ");
    status_state_->setStyleSheet(
        "color: #ff4444; font-weight: bold; font-size: 11px;");
    status_iface_->setText(
        QString("  %1%2  ")
            .arg(iface)
            .arg(filter.isEmpty() ? "" : "  |  " + filter));
    status_iface_->show();
    tab_widget_->setCurrentIndex(0);

    active_capture_ = std::make_shared<PacketCapture>();

    // ── Spawn capture thread ──────────────────────────────────────────────────
    // Capture by value: iface_str, filter_str, temp_path_str, capture (shared_ptr)
    // KHÔNG capture `this` bằng reference vào lambda bên trong thread
    // (dùng QMetaObject::invokeMethod để marshal về main thread)
    capture_thread_ = std::make_unique<std::thread>(
        [this,
         iface_str    = iface.toStdString(),
         filter_str   = filter.toStdString(),
         temp_path_str = temp_path.toStdString(),   // ← fix: capture by value
         capture      = active_capture_]()
    {
        if (!capture->openLive(iface_str, filter_str)) {
            QMetaObject::invokeMethod(this, [this, iface_str]() {
                capture_running_ = false;
                active_capture_.reset();
                live_tab_->stopLiveWriter();
                act_start_cap_->setEnabled(true);
                act_stop_cap_ ->setEnabled(false);
                act_save_cap_ ->setEnabled(false);
                status_state_->setText("  ■ STOPPED  ");
                status_state_->setStyleSheet(
                    "color: #888888; font-weight: bold; font-size: 11px;");
                status_iface_->hide();
                QMessageBox::critical(this, "Capture Error",
                    QString("Cannot open interface: <b>%1</b>")
                        .arg(QString::fromStdString(iface_str)));
            }, Qt::QueuedConnection);
            return;
        }

        // ── RawPacketCallback ─────────────────────────────────────────────────
        capture->startCapture(
            [this, temp_path_str]
            (PacketInfo        pkt,
            const uint8_t*    raw_bytes,
            uint32_t          raw_len)
        {
            if (!capture_running_.load(std::memory_order_relaxed)) return;

            // 1. Ghi disk → lấy file_offset (UI lazy-load từ disk khi click)
            const int64_t offset = live_tab_->writeLivePacket(
                raw_bytes, raw_len, pkt.orig_len, pkt.timestamp);

            pkt.file_offset = offset;
            pkt.source_file = temp_path_str;

            // 2. Copy raw_data cho detection engine
            pkt.raw_data = std::make_shared<std::vector<uint8_t>>(
                            raw_bytes, raw_bytes + raw_len);

            // 3. KHÔNG push vào ring_buf ở đây
            //    Dispatcher::dispatch() sẽ push → gán pkt.index đúng
            //    Tránh double push → eviction x2
            dispatcher_.dispatch(std::move(pkt));
        });
        // startCapture() blocking — chờ đến khi stopCapture() được gọi
        capture->waitForStop();

        // ── Cleanup sau khi capture kết thúc ─────────────────────────────────
        QMetaObject::invokeMethod(this, [this]() {
            capture_running_ = false;
            active_capture_.reset();
            live_tab_->stopLiveWriter();   // flush + close file tạm
            act_start_cap_->setEnabled(true);
            act_stop_cap_ ->setEnabled(false);
            status_state_->setText("  ■ STOPPED  ");
            status_state_->setStyleSheet(
                "color: #888888; font-weight: bold; font-size: 11px;");
            status_iface_->hide();
            statusBar()->showMessage(
                QString("■  Capture stopped  —  %1").arg(capture_iface_),
                5000);
        }, Qt::QueuedConnection);
    });
}

// ─── stopLiveCapture ──────────────────────────────────────────────────────────
void MainWindow::stopLiveCapture() {
    if (!capture_running_) return;
    capture_running_ = false;
    if (active_capture_)
        active_capture_->stopCapture();
}

void MainWindow::onStopCaptureClicked() { stopLiveCapture(); }

// ─── onSaveCaptureClicked ─────────────────────────────────────────────────────
void MainWindow::onSaveCaptureClicked() {
    const QString path = QFileDialog::getSaveFileName(
        this, "Save Capture",
        QDir::homePath()
            + QString("/capture_%1.pcap")
                  .arg(QDateTime::currentDateTime()
                           .toString("yyyyMMdd_HHmmss")),
        "PCAP Files (*.pcap);;All Files (*)");
    if (path.isEmpty()) return;
    live_tab_->saveToFile(path);
}

// ─── updateUptime ─────────────────────────────────────────────────────────────
void MainWindow::updateUptime() {
    const int s = start_time_.secsTo(QTime::currentTime());
    status_uptime_->setText(
        QString("  Uptime: %1:%2:%3  ")
            .arg(s / 3600,        2, 10, QChar('0'))
            .arg((s % 3600) / 60, 2, 10, QChar('0'))
            .arg(s % 60,          2, 10, QChar('0')));
}

// ─── onAbout ──────────────────────────────────────────────────────────────────
void MainWindow::onAbout() {
    QMessageBox::about(this, "About",
        "<b>Network IDS/IPS Monitor</b><br>"
        "Version 0.1.0 — HVKTQS 2025<br><br>"
        "<i>Đề tài NCKH: Xây dựng Hệ thống Giám sát và<br>"
        "Phân tích Mạng Dựa trên Công nghệ AI</i><br><br>"
        "<b>IPS Modes:</b><br>"
        "🛡️ IPS — Detection + ML enabled<br>"
        "🔍 IDS — Detection only<br>"
        "🤖 ML  — ML only<br>"
        "⛔ OFF — Monitor only");
}

// ─── closeEvent ───────────────────────────────────────────────────────────────
void MainWindow::closeEvent(QCloseEvent* event) {
    if (ui_bridge_) ui_bridge_->stopPolling();
    stopLiveCapture();
    if (capture_thread_ && capture_thread_->joinable())
        capture_thread_->join();
    event->accept();
}
