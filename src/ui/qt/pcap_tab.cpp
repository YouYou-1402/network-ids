// ── pcap_tab.cpp ──────────────────────────────────────────────────────────────
#include "pcap_tab.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QHeaderView>
#include <QAction>
#include <QThread>
#include <QApplication>
#include <QFileInfo>
#include <QDir>
#include <thread>
#include <algorithm>

// ─── Constructor ──────────────────────────────────────────────────────────────
PcapTab::PcapTab(Mode mode, QWidget* parent)
    : QWidget(parent)
    , mode_(mode)
    , ring_buf_(200'000, 2000)          // 200K slots, giữ raw bytes 2000 gần nhất
    , reader_(std::make_unique<PcapReader>())
    , writer_(std::make_unique<PcapWriter>())
{
    tab_title_ = (mode == Mode::LIVE) ? "🔴 Live Capture" : "📂 No file";
    list_model_ = std::make_unique<PacketListModel>(ring_buf_, this);

    setupUI();
    setupToolbar();

    if (mode_ == Mode::LIVE) {
        // Flush pending → model mỗi RENDER_INTERVAL_NORMAL_MS
        connect(&live_timer_, &QTimer::timeout,
                this, &PcapTab::onLiveTimer);
        live_timer_.start(RENDER_INTERVAL_NORMAL_MS);

        // Đo PPS mỗi 1s → tự chỉnh render interval (Wireshark adaptive)
        connect(&pps_check_timer_, &QTimer::timeout,
                this, &PcapTab::onPpsCheckTimer);
        pps_check_timer_.start(1000);
    }
}

// ─── Destructor ───────────────────────────────────────────────────────────────
PcapTab::~PcapTab() {
    cancel_scan_ = true;
    live_timer_.stop();
    pps_check_timer_.stop();
    if (writer_->isOpen())
        writer_->close();
}

// ─── setupUI ──────────────────────────────────────────────────────────────────
void PcapTab::setupUI() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(0);
    root->setContentsMargins(0, 0, 0, 0);

    // Toolbar placeholder
    toolbar_ = new QToolBar(this);
    toolbar_->setMovable(false);
    toolbar_->setStyleSheet(
        "QToolBar { background: #1a1a2e; border-bottom: 1px solid #333; "
        "spacing: 4px; padding: 2px 4px; }"
        "QToolButton { color: #cccccc; background: #2a2a3e; "
        "border: 1px solid #444; border-radius: 3px; padding: 3px 8px; }"
        "QToolButton:hover { background: #3a3a5a; }"
        "QToolButton:checked { background: #1a3a5a; color: #4488ff; }");
    root->addWidget(toolbar_);

    // Filter bar
    filter_bar_ = new FilterBar(this);
    root->addWidget(filter_bar_);

    // Progress bar (ẩn khi không dùng)
    progress_bar_ = new QProgressBar(this);
    progress_bar_->setRange(0, 100);
    progress_bar_->setFixedHeight(4);
    progress_bar_->setTextVisible(false);
    progress_bar_->setStyleSheet(
        "QProgressBar { background: #1a1a2e; border: none; }"
        "QProgressBar::chunk { background: #4488ff; }");
    progress_bar_->hide();
    root->addWidget(progress_bar_);

    // Main splitter (vertical)
    auto* v_split = new QSplitter(Qt::Vertical, this);
    v_split->setHandleWidth(3);
    v_split->setStyleSheet("QSplitter::handle { background: #333; }");

    // Packet list (top)
    packet_table_ = new QTableView(v_split);
    packet_table_->setModel(list_model_.get());
    packet_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    packet_table_->setSelectionMode(QAbstractItemView::SingleSelection);
    packet_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packet_table_->setShowGrid(false);
    packet_table_->setAlternatingRowColors(false);
    packet_table_->verticalHeader()->setVisible(false);
    packet_table_->verticalHeader()->setDefaultSectionSize(20);
    packet_table_->horizontalHeader()->setStretchLastSection(false);
    packet_table_->setStyleSheet(
        "QTableView { background: #0a0a14; color: #cccccc; "
        "border: none; font-family: monospace; font-size: 11px; }"
        "QTableView::item:selected { background: #2a2a5a; }"
        "QHeaderView::section { background: #1a1a2e; color: #8888aa; "
        "border: none; border-bottom: 1px solid #444; "
        "padding: 3px 6px; font-size: 11px; }");

    // Column widths
    packet_table_->setColumnWidth(PacketListModel::COL_NO,     55);
    packet_table_->setColumnWidth(PacketListModel::COL_TIME,  110);
    packet_table_->setColumnWidth(PacketListModel::COL_SRC_IP,150);
    packet_table_->setColumnWidth(PacketListModel::COL_DST_IP,150);
    packet_table_->setColumnWidth(PacketListModel::COL_PROTO,  70);
    packet_table_->setColumnWidth(PacketListModel::COL_LEN,    55);
    packet_table_->setColumnWidth(PacketListModel::COL_THREAT,100);
    packet_table_->horizontalHeader()->setSectionResizeMode(
        PacketListModel::COL_INFO, QHeaderView::Stretch);

    // Bottom splitter (detail | hex)
    auto* h_split = new QSplitter(Qt::Horizontal, v_split);
    h_split->setHandleWidth(3);
    h_split->setStyleSheet("QSplitter::handle { background: #333; }");

    detail_tree_ = new PacketDetailTree(h_split);
    hex_view_    = new HexView(h_split);
    h_split->setSizes({500, 400});

    v_split->addWidget(packet_table_);
    v_split->addWidget(h_split);
    v_split->setSizes({450, 250});
    root->addWidget(v_split);

    // Stats bar (bottom)
    auto* stats_bar = new QWidget(this);
    stats_bar->setFixedHeight(22);
    stats_bar->setStyleSheet(
        "QWidget { background: #0f0f1a; border-top: 1px solid #333; }");
    auto* stats_layout = new QHBoxLayout(stats_bar);
    stats_layout->setContentsMargins(8, 0, 8, 0);
    stats_layout->setSpacing(16);

    stats_label_ = new QLabel("Ready", stats_bar);
    stats_label_->setStyleSheet("color: #888888; font-size: 10px;");

    pps_label_ = new QLabel("", stats_bar);
    pps_label_->setStyleSheet("color: #4488ff; font-size: 10px;");
    pps_label_->setVisible(mode_ == Mode::LIVE);

    stats_layout->addWidget(stats_label_);
    stats_layout->addStretch();
    stats_layout->addWidget(pps_label_);
    root->addWidget(stats_bar);

    // Connections
    connect(packet_table_->selectionModel(),
            &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex& cur, const QModelIndex&) {
                onPacketSelected(cur);
            });

    // Detect user scroll — tắt auto-scroll khi user cuộn lên
    connect(packet_table_->verticalScrollBar(), &QScrollBar::valueChanged,
            this, [this](int value) {
                const QScrollBar* sb = packet_table_->verticalScrollBar();
                auto_scroll_ = (value >= sb->maximum() - 5);
            });

    connect(filter_bar_, &FilterBar::filterChanged,
            this, &PcapTab::onFilterChanged);
}

// ─── setupToolbar ─────────────────────────────────────────────────────────────
void PcapTab::setupToolbar() {
    // Open
    auto* open_act = new QAction("📂 Open", this);
    open_act->setToolTip("Open pcap file (Ctrl+O)");
    open_act->setShortcut(QKeySequence::Open);
    connect(open_act, &QAction::triggered, this, &PcapTab::onOpenClicked);
    toolbar_->addAction(open_act);

    // Save
    auto* save_act = new QAction("💾 Save", this);
    save_act->setToolTip("Save packets to pcap file");
    connect(save_act, &QAction::triggered, this, &PcapTab::onSaveClicked);
    toolbar_->addAction(save_act);

    toolbar_->addSeparator();

    // Clear
    auto* clear_act = new QAction("🗑 Clear", this);
    clear_act->setToolTip("Clear all packets");
    connect(clear_act, &QAction::triggered, this, &PcapTab::onClearClicked);
    toolbar_->addAction(clear_act);

    toolbar_->addSeparator();

    // Pause render (Wireshark-style "Update list in real time")
    if (mode_ == Mode::LIVE) {
        pause_act_ = new QAction("⏸ Pause Render", this);
        pause_act_->setToolTip(
            "Pause UI rendering (capture continues in background)");
        pause_act_->setCheckable(true);
        pause_act_->setChecked(false);
        connect(pause_act_, &QAction::toggled,
                this, [this](bool checked) {
                    setRenderPaused(checked);
                    pause_act_->setText(checked ? "▶ Resume Render"
                                                : "⏸ Pause Render");
                });
        toolbar_->addAction(pause_act_);
        toolbar_->addSeparator();
    }

    // Spacer + info label
    auto* spacer = new QWidget(toolbar_);
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    toolbar_->addWidget(spacer);

    auto* info_lbl = new QLabel("  Ring buffer: 200K packets  ", toolbar_);
    info_lbl->setStyleSheet("color: #666688; font-size: 10px;");
    toolbar_->addWidget(info_lbl);
}

// ─── setRenderPaused ─────────────────────────────────────────────────────────
void PcapTab::setRenderPaused(bool paused) {
    render_paused_ = paused;
    if (paused) {
        live_timer_.stop();
        stats_label_->setText(
            QString("⏸ Render paused | buffered: %1 packets")
                .arg(ring_buf_.totalReceived()));
    } else {
        live_timer_.start(RENDER_INTERVAL_NORMAL_MS);
        // Flush ngay lập tức khi resume
        flushPendingToModel();
    }
}

// ─── appendLivePackets — batch API (ưu tiên dùng cái này) ────────────────────
// Gọi từ UiBridge (Qt queued connection) — đã ở main thread
void PcapTab::appendLivePackets(std::vector<PacketRecord> records) {
    if (records.empty()) return;

    {
        std::lock_guard<std::mutex> lock(live_mutex_);

        // Move toàn bộ batch vào pending — 1 lần lock duy nhất
        for (auto& r : records)
            live_pending_.push_back(std::move(r));

        // Wireshark ringbuffer pattern: khi tràn, drop packet cũ nhất
        if (live_pending_.size() > MAX_PENDING_BUFFER) {
            const size_t excess = live_pending_.size() - DROP_TO_SIZE;
            live_pending_.erase(
                live_pending_.begin(),
                live_pending_.begin() + static_cast<ptrdiff_t>(excess));
        }
    }
}

// ─── appendLivePacket — single packet (backward compat) ──────────────────────
void PcapTab::appendLivePacket(const PacketRecord& record) {
    std::lock_guard<std::mutex> lock(live_mutex_);
    live_pending_.push_back(record);

    if (live_pending_.size() > MAX_PENDING_BUFFER) {
        const size_t excess = live_pending_.size() - DROP_TO_SIZE;
        live_pending_.erase(
            live_pending_.begin(),
            live_pending_.begin() + static_cast<ptrdiff_t>(excess));
    }
}

// ─── onLiveTimer — flush pending → model (main thread) ───────────────────────
void PcapTab::onLiveTimer() {
    if (render_paused_) return;
    flushPendingToModel();
}

// ─── flushPendingToModel — core render logic ──────────────────────────────────
void PcapTab::flushPendingToModel() {
    std::vector<PacketRecord> batch;
    {
        std::lock_guard<std::mutex> lock(live_mutex_);
        if (live_pending_.empty()) return;

        if (live_pending_.size() <= MAX_ROWS_PER_FLUSH) {
            batch.swap(live_pending_);
        } else {
            batch.assign(
                std::make_move_iterator(live_pending_.begin()),
                std::make_move_iterator(
                    live_pending_.begin()
                    + static_cast<ptrdiff_t>(MAX_ROWS_PER_FLUSH)));
            live_pending_.erase(
                live_pending_.begin(),
                live_pending_.begin()
                    + static_cast<ptrdiff_t>(MAX_ROWS_PER_FLUSH));
        }
    }

    if (batch.empty()) return;

    // ✅ FIX: Push vào ring_buf_ TRƯỚC khi đưa vào model
    // Live packet chưa bao giờ được push → getByIndex() luôn trả nullptr
    for (auto& r : batch)
        ring_buf_.push(r);   // push copy (raw_data shared_ptr vẫn valid)

    list_model_->appendRecords(batch);

    if (auto_scroll_)
        packet_table_->scrollToBottom();

    const size_t pending_left = [this]() -> size_t {
        std::lock_guard<std::mutex> lock(live_mutex_);
        return live_pending_.size();
    }();

    QString stats = QString("🔴 %1 packets").arg(list_model_->rowCount());
    if (pending_left > 0)
        stats += QString("  |  queued: %1").arg(pending_left);
    stats_label_->setText(stats);
}


// ─── onPpsCheckTimer — đo PPS thực tế mỗi 1s → adaptive interval ─────────────
void PcapTab::onPpsCheckTimer() {
    const uint64_t current_count = ring_buf_.totalReceived();
    const double   pps = static_cast<double>(current_count - pps_last_count_);
    pps_last_count_    = current_count;
    current_pps_       = pps;

    updateAdaptiveInterval(pps);

    // Hiển thị PPS + trạng thái render
    QString pps_str;
    if (render_paused_) {
        pps_str = QString("⏸ %1 pps (render paused)").arg(pps, 0, 'f', 0);
        pps_label_->setStyleSheet("color: #ff8844; font-size: 10px;");
    } else if (pps > 2000) {
        pps_str = QString("⚡ %1 pps (turbo)").arg(pps, 0, 'f', 0);
        pps_label_->setStyleSheet("color: #ff4444; font-size: 10px;");
    } else if (pps > 500) {
        pps_str = QString("🔥 %1 pps (fast)").arg(pps, 0, 'f', 0);
        pps_label_->setStyleSheet("color: #ffaa44; font-size: 10px;");
    } else {
        pps_str = QString("📡 %1 pps").arg(pps, 0, 'f', 0);
        pps_label_->setStyleSheet("color: #4488ff; font-size: 10px;");
    }
    pps_label_->setText(pps_str);
}

// ─── updateAdaptiveInterval — Wireshark adaptive render ───────────────────────
void PcapTab::updateAdaptiveInterval(double pps) {
    int new_interval;
    if (pps > 2000) {
        new_interval = RENDER_INTERVAL_TURBO_MS;   // 1000ms — giảm render load
    } else if (pps > 500) {
        new_interval = RENDER_INTERVAL_FAST_MS;    // 500ms
    } else {
        new_interval = RENDER_INTERVAL_NORMAL_MS;  // 200ms — mượt nhất
    }

    if (live_timer_.interval() != new_interval && !render_paused_) {
        live_timer_.setInterval(new_interval);
    }
}

// ─── loadFile ─────────────────────────────────────────────────────────────────
void PcapTab::loadFile(const QString& filepath) {
    cancel_scan_ = false;
    current_filepath_ = filepath;

    ring_buf_.clear();
    list_model_->clear();
    detail_tree_->clearDetail();
    hex_view_->clearData();

    tab_title_ = "📂 " + QFileInfo(filepath).fileName();
    emit titleChanged(tab_title_);

    progress_bar_->show();
    progress_bar_->setValue(0);
    stats_label_->setText("Loading " + filepath + "...");

    // Scan trong background thread — không block Qt UI
    std::thread([this, filepath]() {
        const bool ok = reader_->scanFile(
            filepath.toStdString(),
            ring_buf_,
            [this](uint64_t loaded, uint64_t total, double pct) {
                QMetaObject::invokeMethod(this,
                    [this, loaded, total, pct]() {
                        onLoadProgress(loaded, total, pct);
                    }, Qt::QueuedConnection);
            },
            &cancel_scan_
        );

        QMetaObject::invokeMethod(this, [this, ok]() {
            progress_bar_->hide();

            if (!ok) {
                stats_label_->setText("❌ Failed to load file");
                return;
            }

            const auto& stats = reader_->stats();
            list_model_->applyFilter(filter_bar_->currentFilter());

            stats_label_->setText(
                QString("✅ %1 packets  |  %2 MB  |  %3s  |  %4")
                    .arg(stats.total_packets)
                    .arg(stats.total_bytes / 1024.0 / 1024.0, 0, 'f', 2)
                    .arg(stats.duration_sec, 0, 'f', 3)
                    .arg(QString::fromStdString(stats.linktype_name)));
        }, Qt::QueuedConnection);
    }).detach();
}

// ─── onPacketSelected ─────────────────────────────────────────────────────────
void PcapTab::onPacketSelected(const QModelIndex& index) {
    if (!index.isValid()) return;

    auto record_ptr = list_model_->recordAt(index.row());
    if (!record_ptr) return;

    PacketRecord record = *record_ptr;

    if (!record.raw_data) {
        if (record.file_offset >= 0) {
            // Offline: lazy load từ file
            loadRawBytesForRecord(record);
        } else {
            // Live: raw_data bị evict → thử lấy lại từ ring_buf
            // (chỉ còn nếu trong keep_raw window 2000 gần nhất)
            auto fresh = ring_buf_.getByIndex(record.index);
            if (fresh && fresh->raw_data)
                record.raw_data = fresh->raw_data;
        }
    }

    detail_tree_->showPacket(record);

    if (record.raw_data && !record.raw_data->empty())
        hex_view_->setData(*record.raw_data);
    else
        hex_view_->clearData();
}



void PcapTab::loadRawBytesForRecord(PacketRecord& record) {
    if (current_filepath_.isEmpty()) return;
    reader_->loadRawBytes(record, current_filepath_.toStdString());
}

// ─── onFilterChanged ──────────────────────────────────────────────────────────
void PcapTab::onFilterChanged(DisplayFilter filter) {
    list_model_->applyFilter(filter);

    const uint64_t total   = ring_buf_.totalReceived();
    const int      visible = list_model_->rowCount();
    stats_label_->setText(
        QString("Filter: %1 / %2 packets shown").arg(visible).arg(total));
}

// ─── onSaveClicked / saveToFile ───────────────────────────────────────────────
void PcapTab::onSaveClicked() {
    const QString filepath = QFileDialog::getSaveFileName(
        this, "Save Packets",
        QDir::homePath() + "/capture.pcap",
        "PCAP Files (*.pcap);;All Files (*)");
    if (!filepath.isEmpty())
        saveToFile(filepath);
}

void PcapTab::saveToFile(const QString& filepath) {
    PcapWriter writer;
    if (!writer.open(filepath.toStdString())) {
        QMessageBox::critical(this, "Error",
            "Cannot open file for writing:\n" + filepath);
        return;
    }

    uint64_t saved   = 0;
    auto     records = ring_buf_.getRange(
        ring_buf_.oldestIndex(), ring_buf_.newestIndex() + 1);

    for (auto& rec : records) {
        if (!rec.raw_data && rec.file_offset >= 0)
            reader_->loadRawBytes(rec, current_filepath_.toStdString());

        if (rec.raw_data && !rec.raw_data->empty()) {
            writer.writePacket(rec);
            ++saved;
        }
    }
    writer.close();

    QMessageBox::information(this, "Saved",
        QString("Saved %1 packets to:\n%2").arg(saved).arg(filepath));
    stats_label_->setText(
        QString("💾 Saved %1 packets → %2").arg(saved).arg(filepath));
}

// ─── onOpenClicked ────────────────────────────────────────────────────────────
void PcapTab::onOpenClicked() {
    const QString filepath = QFileDialog::getOpenFileName(
        this, "Open PCAP File", QDir::homePath(),
        "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)");
    if (!filepath.isEmpty())
        loadFile(filepath);
}

// ─── onClearClicked ───────────────────────────────────────────────────────────
void PcapTab::onClearClicked() {
    ring_buf_.clear();
    list_model_->clear();
    detail_tree_->clearDetail();
    hex_view_->clearData();
    pps_last_count_ = 0;
    stats_label_->setText("Cleared");
}

// ─── onLoadProgress ───────────────────────────────────────────────────────────
void PcapTab::onLoadProgress(uint64_t loaded, uint64_t /*total*/, double pct) {
    progress_bar_->setValue(static_cast<int>(pct));
    stats_label_->setText(
        QString("Loading... %1 packets (%2%)")
            .arg(loaded).arg(static_cast<int>(pct)));
}

int PcapTab::visibleCount() const {
    return list_model_->rowCount();
}
