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
#include <thread>

PcapTab::PcapTab(Mode mode, QWidget* parent)
    : QWidget(parent)
    , mode_(mode)
    // Ring buffer: 200K packets, giữ raw bytes 2000 gần nhất
    , ring_buf_(200000, 2000)
    , reader_(std::make_unique<PcapReader>())
    , writer_(std::make_unique<PcapWriter>())
{
    tab_title_ = (mode == Mode::LIVE)
        ? "🔴 Live Capture"
        : "📂 No file";

    list_model_ = std::make_unique<PacketListModel>(ring_buf_, this);

    setupUI();
    setupToolbar();

    // Live mode: flush pending packets mỗi 200ms
    if (mode_ == Mode::LIVE) {
        connect(&live_timer_, &QTimer::timeout,
                this, &PcapTab::onLiveTimer);
        live_timer_.start(200);
    }
}

PcapTab::~PcapTab() {
    cancel_scan_ = true;
    live_timer_.stop();
    if (writer_->isOpen())
        writer_->close();
}

void PcapTab::setupUI() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(0);
    root->setContentsMargins(0, 0, 0, 0);

    // ── Toolbar placeholder (setupToolbar sẽ điền) ────────────────────────────
    toolbar_ = new QToolBar(this);
    toolbar_->setMovable(false);
    toolbar_->setStyleSheet(
        "QToolBar { background: #1a1a2e; border-bottom: 1px solid #333; "
        "spacing: 4px; padding: 2px 4px; }"
        "QToolButton { color: #cccccc; background: #2a2a3e; "
        "border: 1px solid #444; border-radius: 3px; padding: 3px 8px; }"
        "QToolButton:hover { background: #3a3a5a; }");
    root->addWidget(toolbar_);

    // ── Filter bar ────────────────────────────────────────────────────────────
    filter_bar_ = new FilterBar(this);
    root->addWidget(filter_bar_);

    // ── Progress bar (ẩn khi không dùng) ─────────────────────────────────────
    progress_bar_ = new QProgressBar(this);
    progress_bar_->setRange(0, 100);
    progress_bar_->setFixedHeight(4);
    progress_bar_->setTextVisible(false);
    progress_bar_->setStyleSheet(
        "QProgressBar { background: #1a1a2e; border: none; }"
        "QProgressBar::chunk { background: #4488ff; }");
    progress_bar_->hide();
    root->addWidget(progress_bar_);

    // ── Main splitter (vertical) ──────────────────────────────────────────────
    auto* v_split = new QSplitter(Qt::Vertical, this);
    v_split->setHandleWidth(3);
    v_split->setStyleSheet("QSplitter::handle { background: #333; }");

    // ── Packet list (top) ─────────────────────────────────────────────────────
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
    packet_table_->setColumnWidth(PacketListModel::COL_NO,    55);
    packet_table_->setColumnWidth(PacketListModel::COL_TIME,  110);
    packet_table_->setColumnWidth(PacketListModel::COL_SRC_IP,150);
    packet_table_->setColumnWidth(PacketListModel::COL_DST_IP,150);
    packet_table_->setColumnWidth(PacketListModel::COL_PROTO,  70);
    packet_table_->setColumnWidth(PacketListModel::COL_LEN,    55);
    packet_table_->setColumnWidth(PacketListModel::COL_THREAT, 100);
    packet_table_->horizontalHeader()
        ->setSectionResizeMode(PacketListModel::COL_INFO,
                               QHeaderView::Stretch);

    // ── Bottom splitter (detail | hex) ────────────────────────────────────────
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

    // ── Stats bar ─────────────────────────────────────────────────────────────
    stats_label_ = new QLabel("Ready", this);
    stats_label_->setStyleSheet(
        "QLabel { background: #0f0f1a; color: #888888; "
        "border-top: 1px solid #333; padding: 2px 8px; font-size: 10px; }");
    root->addWidget(stats_label_);

    // ── Connections ───────────────────────────────────────────────────────────
    connect(packet_table_->selectionModel(),
            &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex& cur, const QModelIndex&) {
                onPacketSelected(cur);
            });

    connect(filter_bar_, &FilterBar::filterChanged,
            this, &PcapTab::onFilterChanged);
}

void PcapTab::setupToolbar() {
    // ── Open ──────────────────────────────────────────────────────────────────
    auto* open_act = new QAction("📂 Open", this);
    open_act->setToolTip("Open pcap file");
    connect(open_act, &QAction::triggered,
            this, &PcapTab::onOpenClicked);
    toolbar_->addAction(open_act);

    // ── Save ──────────────────────────────────────────────────────────────────
    auto* save_act = new QAction("💾 Save", this);
    save_act->setToolTip("Save packets to pcap file");
    connect(save_act, &QAction::triggered,
            this, &PcapTab::onSaveClicked);
    toolbar_->addAction(save_act);

    toolbar_->addSeparator();

    // ── Clear ─────────────────────────────────────────────────────────────────
    auto* clear_act = new QAction("🗑 Clear", this);
    connect(clear_act, &QAction::triggered,
            this, &PcapTab::onClearClicked);
    toolbar_->addAction(clear_act);

    toolbar_->addSeparator();

    // ── Stats label trong toolbar ─────────────────────────────────────────────
    auto* spacer = new QWidget(toolbar_);
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    toolbar_->addWidget(spacer);

    auto* info_lbl = new QLabel("  Ring buffer: 200K packets max  ", toolbar_);
    info_lbl->setStyleSheet("color: #666688; font-size: 10px;");
    toolbar_->addWidget(info_lbl);
}

// ─── Load file (chạy scan trong background thread) ────────────────────────────
void PcapTab::loadFile(const QString& filepath) {
    cancel_scan_ = false;
    current_filepath_ = filepath;

    // Reset
    ring_buf_.clear();
    list_model_->clear();
    detail_tree_->clearDetail();
    hex_view_->clearData();

    tab_title_ = "📂 " + QFileInfo(filepath).fileName();
    emit titleChanged(tab_title_);

    progress_bar_->show();
    progress_bar_->setValue(0);
    stats_label_->setText("Loading " + filepath + "...");

    // Chạy scan trong thread riêng — không block Qt UI
    std::thread([this, filepath]() {
        bool ok = reader_->scanFile(
            filepath.toStdString(),
            ring_buf_,
            [this](uint64_t loaded, uint64_t, double pct) {
                // Emit progress về Qt thread
                QMetaObject::invokeMethod(this, [this, loaded, pct]() {
                    onLoadProgress(loaded, 0, pct);
                }, Qt::QueuedConnection);
            },
            &cancel_scan_
        );

        // Khi xong → update UI trong Qt thread
        QMetaObject::invokeMethod(this, [this, ok]() {
            progress_bar_->hide();

            if (!ok) {
                stats_label_->setText("❌ Failed to load file");
                return;
            }

            const auto& stats = reader_->stats();

            // Apply filter hiện tại
            list_model_->applyFilter(
                filter_bar_->currentFilter());

            stats_label_->setText(
                QString("✅ %1 packets | %2 MB | Duration: %3s | %4")
                    .arg(stats.total_packets)
                    .arg(stats.total_bytes / 1024.0 / 1024.0, 0, 'f', 2)
                    .arg(stats.duration_sec, 0, 'f', 3)
                    .arg(QString::fromStdString(stats.linktype_name))
            );
        }, Qt::QueuedConnection);
    }).detach();
}

// ─── Live capture: nhận packet từ engine thread ───────────────────────────────
void PcapTab::appendLivePacket(const PacketRecord& record) {
    // Gọi từ engine thread → buffer vào live_pending_
    std::lock_guard<std::mutex> lock(live_mutex_);
    live_pending_.push_back(record);

    // Giới hạn pending buffer (tránh tràn RAM nếu UI lag)
    if (live_pending_.size() > 5000)
        live_pending_.erase(live_pending_.begin(),
                            live_pending_.begin() + 2500);
}

// ─── Timer: flush pending packets vào model (Qt thread) ──────────────────────
void PcapTab::onLiveTimer() {
    std::vector<PacketRecord> batch;
    {
        std::lock_guard<std::mutex> lock(live_mutex_);
        if (live_pending_.empty()) return;
        batch.swap(live_pending_);
    }

    // Live mode: KHÔNG push vào ring_buf_ local (đã có trong global ring_buf)
    // Chỉ notify model append indices
    list_model_->appendRecords(batch);

    if (!batch.empty())
        packet_table_->scrollToBottom();

    stats_label_->setText(
        QString("🔴 Live | %1 packets displayed | cap: %2K")
            .arg(list_model_->rowCount())
            .arg(ring_buf_.totalReceived() / 1000)
    );
}
// ─── Packet selected → hiển thị detail + hex ─────────────────────────────────
void PcapTab::onPacketSelected(const QModelIndex& index) {
    if (!index.isValid()) return;

    auto record_ptr = list_model_->recordAt(index.row());
    if (!record_ptr) return;

    PacketRecord record = *record_ptr;

    // Lazy load raw bytes nếu chưa có
    if (!record.raw_data && record.file_offset >= 0) {
        loadRawBytesForRecord(record);
    }

    // Hiển thị detail tree
    detail_tree_->showPacket(record);

    // Hiển thị hex dump
    if (record.raw_data && !record.raw_data->empty()) {
        hex_view_->setData(*record.raw_data);
    } else {
        hex_view_->clearData();
    }
}

void PcapTab::loadRawBytesForRecord(PacketRecord& record) {
    if (current_filepath_.isEmpty()) return;
    reader_->loadRawBytes(record, current_filepath_.toStdString());
}

// ─── Filter changed ───────────────────────────────────────────────────────────
void PcapTab::onFilterChanged(DisplayFilter filter) {
    list_model_->applyFilter(filter);

    uint64_t total   = ring_buf_.totalReceived();
    int      visible = list_model_->rowCount();
    stats_label_->setText(
        QString("Filter: %1 / %2 packets shown")
            .arg(visible)
            .arg(total)
    );
}

// ─── Save ─────────────────────────────────────────────────────────────────────
void PcapTab::onSaveClicked() {
    QString filepath = QFileDialog::getSaveFileName(
        this, "Save Packets",
        QDir::homePath() + "/capture.pcap",
        "PCAP Files (*.pcap);;All Files (*)"
    );
    if (filepath.isEmpty()) return;
    saveToFile(filepath);
}

void PcapTab::saveToFile(const QString& filepath) {
    PcapWriter writer;
    if (!writer.open(filepath.toStdString())) {
        QMessageBox::critical(this, "Error",
            "Cannot open file for writing:\n" + filepath);
        return;
    }

    // Lưu tất cả packets có raw_data
    uint64_t saved = 0;
    uint64_t oldest = ring_buf_.oldestIndex();
    uint64_t newest = ring_buf_.newestIndex();
    auto records = ring_buf_.getRange(oldest, newest + 1);

    for (auto& rec : records) {
        // Lazy load nếu cần
        if (!rec.raw_data && rec.file_offset >= 0)
            reader_->loadRawBytes(rec, current_filepath_.toStdString());

        if (rec.raw_data && !rec.raw_data->empty()) {
            writer.writePacket(rec);
            saved++;
        }
    }

    writer.close();

    QMessageBox::information(this, "Saved",
        QString("Saved %1 packets to:\n%2").arg(saved).arg(filepath));

    stats_label_->setText(
        QString("💾 Saved %1 packets → %2").arg(saved).arg(filepath));
}

// ─── Open ─────────────────────────────────────────────────────────────────────
void PcapTab::onOpenClicked() {
    QString filepath = QFileDialog::getOpenFileName(
        this, "Open PCAP File",
        QDir::homePath(),
        "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)"
    );
    if (!filepath.isEmpty())
        loadFile(filepath);
}

// ─── Clear ────────────────────────────────────────────────────────────────────
void PcapTab::onClearClicked() {
    ring_buf_.clear();
    list_model_->clear();
    detail_tree_->clearDetail();
    hex_view_->clearData();
    stats_label_->setText("Cleared");
}

void PcapTab::onLoadProgress(uint64_t loaded, uint64_t, double pct) {
    progress_bar_->setValue(static_cast<int>(pct));
    stats_label_->setText(
        QString("Loading... %1 packets (%2%)")
            .arg(loaded).arg(static_cast<int>(pct)));
}

int PcapTab::visibleCount() const {
    return list_model_->rowCount();
}
