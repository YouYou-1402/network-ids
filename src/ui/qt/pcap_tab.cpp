// src/ui/qt/pcap_tab.cpp
#include "pcap_tab.hpp"
#include "packet_list_model.hpp"
#include "packet_detail_tree.hpp"
#include "hex_view.hpp"
#include "filter_bar.hpp"
#include "metrics_widget.hpp"
#include "traffic_chart.hpp"
#include "alert_panel.hpp"
#include "ips_control_widget.hpp"
#include "ui_bridge.hpp"

#include "../../capture/io/pcap_reader.hpp"
#include "../../capture/io/pcap_writer.hpp"

#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QDir>
#include <QDateTime>
#include <QMessageBox>
#include <QHeaderView>
#include <QScrollBar>
#include <QScrollBar>
#include <QAbstractItemView>

// ═════════════════════════════════════════════════════════════════════════════
// Constructor / Destructor
// ═════════════════════════════════════════════════════════════════════════════

PcapTab::PcapTab(Mode mode, QWidget* parent)
    : QWidget(parent)
    , mode_(mode)
{
    if (mode_ == Mode::LIVE)
        setupLiveLayout();
    else
        setupOfflineLayout();
}

PcapTab::~PcapTab() {
    stopLiveWriter();
}

// ═════════════════════════════════════════════════════════════════════════════
// setUiBridge
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::setUiBridge(UiBridge* bridge) {
    bridge_ = bridge;
    if (!bridge_) return;

    if (mode_ == Mode::LIVE) {
        auto* old_model = packet_model_;
        packet_model_   = new PacketListModel(bridge_->ringBuf(), this);
        packet_table_->setModel(packet_model_);

        connect(packet_table_->selectionModel(),
                &QItemSelectionModel::currentRowChanged,
                this, [this](const QModelIndex& cur, const QModelIndex&) {
                    onPacketSelected(cur);
                });

        delete old_model;

        // ── Wireshark: startTimer thay vì QTimer ──────────────────────────────
        // overlay_timer_id_: poll ring_buf + freeze/thaw mỗi 100ms
        // tail_timer_id_   : auto-scroll mỗi 200ms
        if (overlay_timer_id_ == -1)
            overlay_timer_id_ = startTimer(100);
        if (tail_timer_id_ == -1)
            tail_timer_id_ = startTimer(200);

        capture_in_progress_.store(true, std::memory_order_release);
        last_polled_seq_ = bridge_->ringBuf().totalPushed();
    }

    connectBridgeSignals();

    if (ips_control_) {
        ips_control_->syncState(
            bridge_->isDetectionEnabled(),
            bridge_->isMlEnabled());
    }
}
// ═════════════════════════════════════════════════════════════════════════════
// connectBridgeSignals
// ═════════════════════════════════════════════════════════════════════════════
void PcapTab::connectBridgeSignals() {
    if (!bridge_) return;

    if (metrics_widget_)
        connect(bridge_, &UiBridge::metricsUpdated,
                metrics_widget_, &MetricsWidget::onMetricsUpdated);

    if (traffic_chart_)
        connect(bridge_, &UiBridge::trafficUpdated,
                traffic_chart_, &TrafficChart::onTrafficUpdated);

    if (alert_panel_)
        connect(bridge_, &UiBridge::newAlerts,
                alert_panel_, &AlertPanel::onNewAlerts);

    // ── captureStarted / captureStopped signal → điều khiển timerEvent ────────
    connect(bridge_, &UiBridge::captureStarted, this, [this]() {
        capture_in_progress_.store(true, std::memory_order_release);
        tail_at_end_     = true;
        last_polled_seq_ = bridge_->ringBuf().totalPushed();
        if (overlay_timer_id_ == -1) overlay_timer_id_ = startTimer(100);
        if (tail_timer_id_    == -1) tail_timer_id_    = startTimer(200);
    });

    connect(bridge_, &UiBridge::captureStopped, this, [this]() {
        capture_in_progress_.store(false, std::memory_order_release);
    });

    if (ips_control_) {
        connect(ips_control_, &IpsControlWidget::toggleDetection,
                bridge_,      &UiBridge::setDetectionEnabled);
        connect(ips_control_, &IpsControlWidget::toggleMl,
                bridge_,      &UiBridge::setMlEnabled);
        connect(bridge_,      &UiBridge::detectionStatusChanged,
                ips_control_, &IpsControlWidget::onDetectionStatusChanged);
        connect(bridge_,      &UiBridge::mlStatusChanged,
                ips_control_, &IpsControlWidget::onMlStatusChanged);
    }
}
// ═════════════════════════════════════════════════════════════════════════════
// setupPacketTable
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::setupPacketTable() {
    packet_model_ = new PacketListModel(dummy_ring_buf_, this);

    packet_table_ = new QTableView(this);
    packet_table_->setModel(packet_model_);
    packet_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    packet_table_->setSelectionMode(QAbstractItemView::SingleSelection);
    packet_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packet_table_->setAlternatingRowColors(false);
    packet_table_->verticalHeader()->setVisible(false);
    packet_table_->verticalHeader()->setDefaultSectionSize(20);
    packet_table_->setShowGrid(false);
    packet_table_->setFocusPolicy(Qt::NoFocus);
    packet_table_->horizontalHeader()->setStretchLastSection(true);
    packet_table_->horizontalHeader()->setHighlightSections(false);

    packet_table_->setColumnWidth(0,  55);
    packet_table_->setColumnWidth(1,  85);
    packet_table_->setColumnWidth(2, 115);
    packet_table_->setColumnWidth(3, 115);
    packet_table_->setColumnWidth(4,  55);
    packet_table_->setColumnWidth(5,  60);
    packet_table_->setColumnWidth(6,  80);
    packet_table_->setColumnWidth(7, 100);

    packet_table_->setStyleSheet(
        "QTableView {"
        "  background: #0a0a14; color: #cccccc;"
        "  border: 1px solid #2a2a3e;"
        "  gridline-color: #1a1a2a;"
        "  font-size: 11px; font-family: 'Consolas', monospace; }"
        "QTableView::item { padding: 1px 4px; border: none; }"
        "QTableView::item:selected { background: #2a2a5a; color: #ffffff; }"
        "QHeaderView::section {"
        "  background: #1a1a2e; color: #8888aa;"
        "  border: none; border-bottom: 1px solid #333;"
        "  padding: 3px 4px; font-size: 10px; font-weight: bold; }");
}

// ═════════════════════════════════════════════════════════════════════════════
// setupLiveLayout
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::setupLiveLayout() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(4);
    root->setContentsMargins(4, 4, 4, 4);

    filter_bar_ = new FilterBar(this);
    root->addWidget(filter_bar_);

    auto* main_split = new QSplitter(Qt::Horizontal, this);
    main_split->setHandleWidth(5);
    main_split->setStyleSheet(
        "QSplitter::handle { background: #1e1e30; border: 1px solid #2a2a3e; }");

    auto* sidebar = new QWidget(main_split);
    sidebar->setMinimumWidth(240);
    sidebar->setMaximumWidth(300);
    auto* sb_lay = new QVBoxLayout(sidebar);
    sb_lay->setSpacing(0);
    sb_lay->setContentsMargins(0, 0, 0, 0);

    metrics_widget_ = new MetricsWidget(sidebar);
    sb_lay->addWidget(metrics_widget_, 0);

    auto* divider = new QFrame(sidebar);
    divider->setFrameShape(QFrame::HLine);
    divider->setFixedHeight(2);
    divider->setStyleSheet("background: #2a2a4a; border: none;");
    sb_lay->addWidget(divider);

    ips_control_ = new IpsControlWidget(sidebar);
    sb_lay->addWidget(ips_control_, 0);
    sb_lay->addStretch(1);

    main_split->addWidget(sidebar);

    auto* right_w   = new QWidget(main_split);
    auto* right_lay = new QVBoxLayout(right_w);
    right_lay->setSpacing(4);
    right_lay->setContentsMargins(0, 0, 0, 0);

    auto* v_split = new QSplitter(Qt::Vertical, right_w);
    v_split->setHandleWidth(5);
    v_split->setStyleSheet(
        "QSplitter::handle { background: #1e1e30; border: 1px solid #2a2a3e; }");

    setupPacketTable();
    v_split->addWidget(packet_table_);

    auto* bot_split = new QSplitter(Qt::Horizontal, v_split);
    bot_split->setHandleWidth(5);
    bot_split->setStyleSheet(
        "QSplitter::handle { background: #1e1e30; border: 1px solid #2a2a3e; }");

    auto* detail_w   = new QWidget(bot_split);
    auto* detail_lay = new QVBoxLayout(detail_w);
    detail_lay->setSpacing(0);
    detail_lay->setContentsMargins(0, 0, 0, 0);

    auto* dh_split = new QSplitter(Qt::Horizontal, detail_w);
    dh_split->setHandleWidth(4);
    dh_split->setStyleSheet("QSplitter::handle { background: #2a2a3e; }");

    detail_tree_ = new PacketDetailTree(detail_w);
    hex_view_    = new HexView(detail_w);
    dh_split->addWidget(detail_tree_);
    dh_split->addWidget(hex_view_);
    dh_split->setSizes({280, 280});
    detail_lay->addWidget(dh_split);
    bot_split->addWidget(detail_w);

    auto* info_tabs = new QTabWidget(bot_split);
    info_tabs->setMinimumWidth(280);
    info_tabs->setStyleSheet(
        "QTabWidget::pane  { border: 1px solid #2a2a3e; background: #0f0f1a; }"
        "QTabBar::tab      { background: #1a1a2e; color: #888888;"
        "                    border: 1px solid #2a2a3e; padding: 4px 10px;"
        "                    font-size: 10px; margin-right: 1px; }"
        "QTabBar::tab:selected { background: #2a2a4a; color: #ffffff;"
        "                        border-bottom: 2px solid #4488ff; }"
        "QTabBar::tab:hover    { background: #252540; }");

    traffic_chart_ = new TrafficChart(info_tabs);
    info_tabs->addTab(traffic_chart_, "📈 Traffic");

    alert_panel_ = new AlertPanel(info_tabs);
    info_tabs->addTab(alert_panel_, "🚨 Alerts");

    info_tabs->setCurrentIndex(0);
    bot_split->addWidget(info_tabs);
    bot_split->setSizes({560, 320});

    v_split->addWidget(bot_split);
    v_split->setSizes({420, 260});

    right_lay->addWidget(v_split);
    main_split->addWidget(right_w);
    main_split->setSizes({260, 1000});
    main_split->setStretchFactor(0, 0);
    main_split->setStretchFactor(1, 1);

    root->addWidget(main_split);

    connect(filter_bar_, &FilterBar::filterChanged,
            this, [this](const DisplayFilter& f) {
                if (f.valid) onFilterApplied(QString::fromStdString(f.raw_expr));
                else         onFilterCleared();
            });

    connect(packet_table_->selectionModel(),
            &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex& cur, const QModelIndex&) {
                onPacketSelected(cur);
            });
}

// ═════════════════════════════════════════════════════════════════════════════
// setupOfflineLayout
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::setupOfflineLayout() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(4);
    root->setContentsMargins(4, 4, 4, 4);

    auto* toolbar = new QWidget(this);
    auto* tb_lay  = new QHBoxLayout(toolbar);
    tb_lay->setContentsMargins(0, 0, 0, 4);
    tb_lay->setSpacing(6);

    auto* open_btn = new QPushButton("📂 Open PCAP", toolbar);
    open_btn->setStyleSheet(
        "QPushButton { background: #2a2a3e; color: #88aaff;"
        "  border: 1px solid #444; border-radius: 4px; padding: 4px 12px; }"
        "QPushButton:hover { background: #3a3a5a; }");

    auto* export_btn = new QPushButton("💾 Export", toolbar);
    export_btn->setStyleSheet(
        "QPushButton { background: #2a3a2a; color: #88ff88;"
        "  border: 1px solid #446644; border-radius: 4px; padding: 4px 12px; }"
        "QPushButton:hover { background: #3a4a3a; }");

    tb_lay->addWidget(open_btn);
    tb_lay->addWidget(export_btn);
    tb_lay->addStretch();
    root->addWidget(toolbar);

    filter_bar_ = new FilterBar(this);
    root->addWidget(filter_bar_);

    auto* v_split = new QSplitter(Qt::Vertical, this);
    v_split->setHandleWidth(4);
    v_split->setStyleSheet("QSplitter::handle { background: #2a2a3e; }");

    setupPacketTable();
    v_split->addWidget(packet_table_);

    auto* dh_split = new QSplitter(Qt::Horizontal, v_split);
    dh_split->setHandleWidth(4);
    dh_split->setStyleSheet("QSplitter::handle { background: #2a2a3e; }");

    detail_tree_ = new PacketDetailTree(dh_split);
    hex_view_    = new HexView(dh_split);
    dh_split->addWidget(detail_tree_);
    dh_split->addWidget(hex_view_);
    dh_split->setSizes({400, 400});

    v_split->addWidget(dh_split);
    v_split->setSizes({500, 300});

    root->addWidget(v_split);

    connect(open_btn,   &QPushButton::clicked, this, &PcapTab::onOpenClicked);
    connect(export_btn, &QPushButton::clicked, this, &PcapTab::onExportClicked);

    connect(filter_bar_, &FilterBar::filterChanged,
            this, [this](const DisplayFilter& f) {
                if (f.valid) onFilterApplied(QString::fromStdString(f.raw_expr));
                else         onFilterCleared();
            });

    connect(packet_table_->selectionModel(),
            &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex& cur, const QModelIndex&) {
                onPacketSelected(cur);
            });
}

// ═════════════════════════════════════════════════════════════════════════════
// Live writer
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::startLiveWriter(const QString& temp_path) {
    std::lock_guard<std::mutex> lk(live_writer_mutex_);

    if (live_writer_ && live_writer_->isOpen())
        live_writer_->close();

    live_writer_ = std::make_unique<PcapWriter>();
    if (!live_writer_->open(temp_path.toStdString())) {
        live_writer_.reset();
        live_writer_path_.clear();
        emit statusMessage("⚠️  Cannot open temp capture file: " + temp_path);
        return;
    }
    live_writer_path_ = temp_path;
    emit statusMessage("🔴 Recording → " + temp_path);
}

void PcapTab::stopLiveWriter() {
    std::lock_guard<std::mutex> lk(live_writer_mutex_);
    if (live_writer_) {
        live_writer_->close();
        live_writer_.reset();
    }
}

// ─── writeLivePacket ─────────────────────────────────────────────────────────
// FIX: writePacket() trả về data_offset (sau PcapPacketHeader 16B)
//      → gán trực tiếp vào pkt.file_offset — đúng cho loadRawBytes()
//
// Trước đây: currentOffset() trả về offset TRƯỚC khi ghi header
//            → file_offset lệch 16 bytes → hex dump sai hoàn toàn
int64_t PcapTab::writeLivePacket(const uint8_t*        raw_bytes,
                                   uint32_t              raw_len,
                                   uint32_t              orig_len,
                                   const struct timeval& ts) {
    std::lock_guard<std::mutex> lk(live_writer_mutex_);
    if (!live_writer_ || !live_writer_->isOpen()) return -1;

    // writePacket() trả về data_offset = vị trí DATA trong file
    // = global_header(24) + bytes_written_so_far + packet_header(16)
    return live_writer_->writePacket(raw_bytes, raw_len, orig_len, ts);
}

// ═════════════════════════════════════════════════════════════════════════════
// lazyLoadRawData
// ═════════════════════════════════════════════════════════════════════════════
// FIX 1: LIVE mode flush writer trước khi fread để đảm bảo data đã xuống disk
// FIX 2: pcap_reader_ mới (mmap_ptr_ = MAP_FAILED) → fread với file_offset đúng
bool PcapTab::lazyLoadRawData(int row, PacketInfo& pkt) {
    // Cache hit — không cần đọc disk
    if (pkt.raw_data && !pkt.raw_data->empty()) return true;

    // Không có thông tin để đọc
    if (pkt.file_offset < 0 || pkt.source_file.empty()) return false;

    // LIVE mode: flush writer trước để đảm bảo packet đã xuống disk
    // Không cần lock live_writer_mutex_ ở đây vì flush() tự lock bên trong
    if (mode_ == Mode::LIVE) {
        std::lock_guard<std::mutex> lk(live_writer_mutex_);
        if (live_writer_ && live_writer_->isOpen())
            live_writer_->flush();
    }

    // Tạo pcap_reader_ nếu chưa có
    // OFFLINE: pcap_reader_ đã được tạo trong loadFile() và giữ mmap mở
    //          → loadRawBytes() dùng mmap path (nhanh, zero-copy)
    // LIVE:    pcap_reader_ mới, mmap_ptr_ = MAP_FAILED
    //          → loadRawBytes() fallback fread với file_offset đúng (data_offset)
    if (!pcap_reader_)
        pcap_reader_ = std::make_unique<PcapReader>();

    if (!pcap_reader_->loadRawBytes(pkt, pkt.source_file))
        return false;

    // Cache lại vào model — click tiếp không đọc disk nữa
    packet_model_->updateRawData(row, pkt.raw_data);
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// Slots
// ═════════════════════════════════════════════════════════════════════════════


// ─── onPacketSelected ────────────────────────────────────────────────────────
// Lazy-load raw bytes từ disk khi user click vào row
// Sau đó cập nhật detail tree và hex view
void PcapTab::onPacketSelected(const QModelIndex& index) {
    if (!index.isValid()) return;

    PacketInfo pkt;
    if (!packet_model_->getRecord(index.row(), pkt)) return;

    // Lazy-load raw_data nếu chưa có
    // lazyLoadRawData() cập nhật pkt.raw_data và cache vào model
    lazyLoadRawData(index.row(), pkt);

    if (detail_tree_) detail_tree_->showPacket(pkt);

    if (hex_view_) {
        if (pkt.raw_data && !pkt.raw_data->empty())
            hex_view_->setData(*pkt.raw_data);
        else
            hex_view_->clearData();
    }
}

void PcapTab::onFilterApplied(const QString& /*expr*/) {
    if (!packet_model_ || !filter_bar_) return;
    packet_model_->applyFilter(filter_bar_->currentFilter());
}

void PcapTab::onFilterCleared() {
    if (!packet_model_) return;
    packet_model_->applyFilter(DisplayFilter{});
}

void PcapTab::onOpenClicked() {
    const QString path = QFileDialog::getOpenFileName(
        this, "Open PCAP File", QDir::homePath(),
        "PCAP Files (*.pcap *.pcapng);;All Files (*)");
    if (!path.isEmpty())
        loadFile(path);
}

void PcapTab::onExportClicked() {
    const QString path = QFileDialog::getSaveFileName(
        this, "Export PCAP",
        QDir::homePath() + "/export.pcap",
        "PCAP Files (*.pcap);;All Files (*)");
    if (!path.isEmpty())
        saveToFile(path);
}

// ═════════════════════════════════════════════════════════════════════════════
// loadFile  (OFFLINE mode)
// ═════════════════════════════════════════════════════════════════════════════
// FIX: scanFile() KHÔNG copy raw_data — chỉ lưu metadata + file_offset
//      mmap giữ mở sau scanFile() → loadRawBytes() dùng mmap (zero-copy)
//      source_file được gán trong scanFile() cho từng record
void PcapTab::loadFile(const QString& path) {
    packet_model_->clear();
    dummy_ring_buf_.clear();

    // Tạo PcapReader mới — đóng mmap cũ nếu có
    pcap_reader_ = std::make_unique<PcapReader>();

    const bool ok = pcap_reader_->scanFile(
        path.toStdString(),
        dummy_ring_buf_,
        [](uint64_t, uint64_t, double) {},
        nullptr);

    if (!ok) {
        emit statusMessage("❌ Cannot open: " + path);
        return;
    }

    // Poll toàn bộ metadata từ ring_buf vào model
    // raw_data = nullptr trong mọi record — lazy-load khi click
    uint64_t last_seq = 0;
    auto pkts = dummy_ring_buf_.pollNew(last_seq);
    packet_model_->appendRecords(pkts);

    emit titleChanged ("📂 " + QFileInfo(path).fileName());
    emit statusMessage("✅ Loaded: " + path
                       + "  (" + QString::number(packet_model_->rowCount())
                       + " packets)");
}

// ═════════════════════════════════════════════════════════════════════════════
// saveToFile
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::saveToFile(const QString& path) {

    // LIVE: copy file tạm → đích (nhanh, không re-encode)
    if (mode_ == Mode::LIVE && !live_writer_path_.isEmpty()) {
        // Flush trước khi copy để đảm bảo mọi packet đã xuống disk
        {
            std::lock_guard<std::mutex> lk(live_writer_mutex_);
            if (live_writer_ && live_writer_->isOpen())
                live_writer_->flush();
        }

        if (QFile::exists(path)) QFile::remove(path);

        if (QFile::copy(live_writer_path_, path)) {
            emit statusMessage(
                QString("💾 Saved: %1  (%2 packets)")
                    .arg(QFileInfo(path).fileName())
                    .arg(packet_model_->rowCount()));
        } else {
            emit statusMessage("❌ Copy failed: " + path);
        }
        return;
    }

    // OFFLINE / fallback: dump từ model (lazy-load raw_data từng packet)
    PcapWriter writer;
    if (!writer.open(path.toStdString())) {
        emit statusMessage("❌ Cannot save: " + path);
        return;
    }

    const int n = packet_model_->rowCount();
    for (int i = 0; i < n; ++i) {
        PacketInfo pkt;
        if (!packet_model_->getRecord(i, pkt)) continue;

        if (!pkt.raw_data || pkt.raw_data->empty())
            lazyLoadRawData(i, pkt);

        if (pkt.raw_data && !pkt.raw_data->empty())
            writer.writePacket(pkt);
    }
    writer.close();

    emit statusMessage(
        QString("💾 Saved: %1  (%2 packets)")
            .arg(QFileInfo(path).fileName())
            .arg(n));
}
// ─── timerEvent ───────────────────────────────────────────────────────────────
//
//  Wireshark algorithm (packet_list.cpp::timerEvent):
//
//  overlay_timer (100ms):
//    1. freeze()                   ← tắt Qt model notification
//    2. pollRange(last_seq, MAX)   ← lấy packet mới từ ring_buf
//    3. appendRecords(batch)       ← gom vào pending (frozen → không flush)
//    4. thaw()                     ← 1 beginInsertRows/endInsertRows duy nhất
//    5. viewport()->update()       ← schedule 1 repaint
//
//  tail_timer (200ms):
//    scrollToBottom() nếu tail_at_end_
//
//  Tại sao timerEvent tốt hơn QTimer::timeout:
//    - Qt queue timerEvent sau khi event loop rảnh
//    - Không fire giữa paint event → không flicker
//    - Có thể killTimer chính xác theo timer ID
//
void PcapTab::timerEvent(QTimerEvent* event) {
    if (!packet_model_) return;

    // ── overlay_timer: poll + freeze/thaw ─────────────────────────────────────
    if (event->timerId() == overlay_timer_id_) {

        const bool capturing = capture_in_progress_.load(std::memory_order_acquire);
        const uint64_t total_now = bridge_
            ? bridge_->ringBuf().totalPushed()
            : 0;

        const bool has_new = (total_now > last_polled_seq_);

        if (has_new) {
            // MAX_PER_TICK: 2000 pps × 100ms = 200 pkt/tick
            // Dùng 500 để có buffer cho burst ngắn
            constexpr uint64_t MAX_PER_TICK = 500;
            const uint64_t to_fetch =
                std::min(total_now - last_polled_seq_, MAX_PER_TICK);

            auto batch = bridge_->ringBuf().pollRange(last_polled_seq_, to_fetch);
            last_polled_seq_ += to_fetch;

            if (!batch.empty()) {
                // ── Wireshark freeze/thaw ─────────────────────────────────────
                packet_model_->freeze();
                packet_model_->appendRecords(batch);  // gom vào pending
                packet_model_->thaw();                // 1 beginInsertRows duy nhất

                // 1 lần viewport update thay vì N lần
                if (packet_model_->isDirty()) {
                    packet_table_->viewport()->update();
                    packet_model_->clearDirty();
                }
            }
        }

        // Dừng timer khi capture kết thúc VÀ đã drain hết ring_buf
        if (!capturing && !has_new) {
            killTimer(overlay_timer_id_);
            overlay_timer_id_ = -1;
            emit statusMessage(
                QString("⏹ Capture stopped — %1 packets")
                    .arg(packet_model_->rowCount()));
        }

        return;
    }

    // ── tail_timer: auto-scroll ───────────────────────────────────────────────
    if (event->timerId() == tail_timer_id_) {
        if (tail_at_end_ && packet_model_->rowCount() > 0) {
            auto* vsb = packet_table_->verticalScrollBar();
            // Chỉ scroll nếu user đang ở gần cuối (±3 rows)
            // Tránh scroll khi user đang xem packet ở giữa
            if (vsb->value() >= vsb->maximum() - 3)
                packet_table_->scrollToBottom();
        }

        // Dừng tail timer khi capture kết thúc
        if (!capture_in_progress_.load(std::memory_order_acquire)) {
            killTimer(tail_timer_id_);
            tail_timer_id_ = -1;
        }
        return;
    }

    QWidget::timerEvent(event);
}

// ─── onNewPacketInfos (giữ lại để tương thích) ───────────────────────────────
// timerEvent đã xử lý LIVE mode → hàm này chỉ dùng nếu ai đó vẫn emit signal
void PcapTab::onNewPacketInfos(std::vector<PacketInfo> records) {
    if (records.empty() || mode_ == Mode::LIVE) return;
    // OFFLINE fallback
    packet_model_->appendRecords(records);
}
