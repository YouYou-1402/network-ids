// src/ui/qt/pcap_tab.cpp
#include "pcap_tab.hpp"
#include "packet_list_model.hpp"
#include "packet_detail_tree.hpp"
#include "hex_view.hpp"
#include "filter_bar.hpp"
#include "metrics_widget.hpp"
#include "traffic_chart.hpp"
#include "ui_bridge.hpp"

#include "../../capture/io/pcap_reader.hpp"
#include "../../capture/io/pcap_writer.hpp"

#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QPushButton>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QDir>
#include <QMessageBox>
#include <QHeaderView>
#include <QScrollBar>
#include <QAbstractItemView>
#include <algorithm>

// ─── Palette (light theme) ────────────────────────────────────────────────────
//   BG_PAGE   #f5f6fa   nền tổng
//   BG_PANEL  #ffffff   nền panel / table
//   BG_HEADER #eef0f7   header row / sidebar
//   BORDER    #d0d4e8   viền
//   TEXT_PRI  #1a1a3e   chữ chính
//   TEXT_SEC  #555577   chữ phụ
//   ACCENT    #3355cc   xanh accent
//   SEL_BG    #dce3ff   nền selected row
// ─────────────────────────────────────────────────────────────────────────────

// ═════════════════════════════════════════════════════════════════════════════
// Constructor / Destructor
// ═════════════════════════════════════════════════════════════════════════════

PcapTab::PcapTab(Mode mode, QWidget* parent)
    : QWidget(parent), mode_(mode)
{
    setStyleSheet("QWidget { background: #f5f6fa; color: #1a1a3e; }");

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

        if (overlay_timer_id_ == -1) overlay_timer_id_ = startTimer(100);
        if (tail_timer_id_    == -1) tail_timer_id_    = startTimer(200);

        capture_in_progress_.store(true, std::memory_order_release);
        last_polled_seq_ = bridge_->ringBuf().totalPushed();
    }

    connectBridgeSignals();
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
}

// ═════════════════════════════════════════════════════════════════════════════
// setupPacketTable  — light theme, Wireshark-style
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::setupPacketTable() {
    packet_model_ = new PacketListModel(dummy_ring_buf_, this);

    packet_table_ = new QTableView(this);
    packet_table_->setModel(packet_model_);
    packet_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    packet_table_->setSelectionMode   (QAbstractItemView::SingleSelection);
    packet_table_->setEditTriggers    (QAbstractItemView::NoEditTriggers);
    packet_table_->setAlternatingRowColors(true);
    packet_table_->verticalHeader()->setVisible(false);
    packet_table_->verticalHeader()->setDefaultSectionSize(20);
    packet_table_->setShowGrid(false);
    packet_table_->setFocusPolicy(Qt::NoFocus);
    packet_table_->horizontalHeader()->setStretchLastSection(true);
    packet_table_->horizontalHeader()->setHighlightSections(false);

    packet_table_->setColumnWidth(0,  55);   // No.
    packet_table_->setColumnWidth(1,  90);   // Time
    packet_table_->setColumnWidth(2, 120);   // Source
    packet_table_->setColumnWidth(3, 120);   // Destination
    packet_table_->setColumnWidth(4,  60);   // Protocol
    packet_table_->setColumnWidth(5,  60);   // Length
    packet_table_->setColumnWidth(6, 200);   // Info
    // col 7 (Threat) → stretch

    packet_table_->setStyleSheet(
        // ── Table body ──────────────────────────────────────────────────────
        "QTableView {"
        "  background: #ffffff;"
        "  alternate-background-color: #f4f5fb;"
        "  color: #1a1a3e;"
        "  border: 1px solid #d0d4e8;"
        "  gridline-color: transparent;"
        "  font-size: 11px;"
        "  font-family: 'Consolas', 'Courier New', monospace; }"
        "QTableView::item { padding: 1px 6px; border: none; }"
        "QTableView::item:selected {"
        "  background: #dce3ff; color: #0a0a6e; }"
        "QTableView::item:hover { background: #eef0ff; }"
        // ── Header ──────────────────────────────────────────────────────────
        "QHeaderView::section {"
        "  background: #eef0f7;"
        "  color: #333366;"
        "  border: none;"
        "  border-right: 1px solid #d0d4e8;"
        "  border-bottom: 2px solid #b0b8d8;"
        "  padding: 3px 6px;"
        "  font-size: 10px;"
        "  font-weight: bold; }"
        "QHeaderView::section:last { border-right: none; }"
        // ── Scrollbar ───────────────────────────────────────────────────────
        "QScrollBar:vertical   { background: #f0f1f8; width: 8px; }"
        "QScrollBar:horizontal { background: #f0f1f8; height: 8px; }"
        "QScrollBar::handle:vertical   { background: #b0b8d8;"
        "  border-radius: 4px; min-height: 20px; }"
        "QScrollBar::handle:horizontal { background: #b0b8d8;"
        "  border-radius: 4px; min-width: 20px; }"
        "QScrollBar::add-line, QScrollBar::sub-line { height:0; width:0; }");
}

// ═════════════════════════════════════════════════════════════════════════════
// setupLiveLayout
// ═════════════════════════════════════════════════════════════════════════════
//
//  ┌─ root (QVBoxLayout) ──────────────────────────────────────────────────┐
//  │  FilterBar                                                             │
//  │  ┌─ main_split (H) ────────────────────────────────────────────────┐  │
//  │  │  ┌─ sidebar (200px) ─┐  ┌─ right ──────────────────────────┐   │  │
//  │  │  │  MetricsWidget    │  │  ┌─ v_split (V) ───────────────┐ │   │  │
//  │  │  └───────────────────┘  │  │  PacketTable                │ │   │  │
//  │  │                         │  │  ┌─ bot_split (H) ─────────┐│ │   │  │
//  │  │                         │  │  │ detail+hex │ TrafficChart│││ │   │  │
//  │  │                         │  │  └─────────────────────────┘│ │   │  │
//  │  │                         │  └─────────────────────────────┘ │   │  │
//  │  │                         └──────────────────────────────────┘   │  │
//  │  └─────────────────────────────────────────────────────────────────┘  │
//  └───────────────────────────────────────────────────────────────────────┘

void PcapTab::setupLiveLayout() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(4);
    root->setContentsMargins(6, 6, 6, 6);

    // ── FilterBar ─────────────────────────────────────────────────────────────
    filter_bar_ = new FilterBar(this);
    root->addWidget(filter_bar_);

    // ── Main splitter (H) ─────────────────────────────────────────────────────
    auto* main_split = new QSplitter(Qt::Horizontal, this);
    main_split->setHandleWidth(4);
    main_split->setStyleSheet(
        "QSplitter::handle { background: #d0d4e8; }");

    // ┌── SIDEBAR ──────────────────────────────────────────────────────────────
    auto* sidebar_w   = new QWidget(main_split);
    auto* sidebar_lay = new QVBoxLayout(sidebar_w);
    sidebar_lay->setSpacing(0);
    sidebar_lay->setContentsMargins(0, 0, 0, 0);
    sidebar_w->setMinimumWidth(180);
    sidebar_w->setMaximumWidth(240);
    sidebar_w->setStyleSheet(
        "QWidget { background: #ffffff;"
        "          border-right: 1px solid #d0d4e8; }");

    metrics_widget_ = new MetricsWidget(sidebar_w);
    sidebar_lay->addWidget(metrics_widget_);
    sidebar_lay->addStretch();

    main_split->addWidget(sidebar_w);

    // ┌── RIGHT PANEL ──────────────────────────────────────────────────────────
    auto* right_w   = new QWidget(main_split);
    auto* right_lay = new QVBoxLayout(right_w);
    right_lay->setSpacing(0);
    right_lay->setContentsMargins(0, 0, 0, 0);

    // Vertical splitter: table | bottom
    auto* v_split = new QSplitter(Qt::Vertical, right_w);
    v_split->setHandleWidth(4);
    v_split->setStyleSheet(
        "QSplitter::handle { background: #d0d4e8; }");

    setupPacketTable();
    v_split->addWidget(packet_table_);

    // ── Bottom: detail+hex (trái) | traffic chart (phải) ─────────────────────
    auto* bot_split = new QSplitter(Qt::Horizontal, v_split);
    bot_split->setHandleWidth(4);
    bot_split->setStyleSheet(
        "QSplitter::handle { background: #d0d4e8; }");

    // Detail + Hex
    auto* dh_split = new QSplitter(Qt::Horizontal, bot_split);
    dh_split->setHandleWidth(3);
    dh_split->setStyleSheet(
        "QSplitter::handle { background: #e0e3f0; }");

    detail_tree_ = new PacketDetailTree(dh_split);
    hex_view_    = new HexView(dh_split);
    dh_split->addWidget(detail_tree_);
    dh_split->addWidget(hex_view_);
    dh_split->setSizes({320, 280});
    bot_split->addWidget(dh_split);

    // Traffic chart — wrap trong QGroupBox để có title
    auto* chart_box = new QGroupBox("📈 Traffic Monitor", bot_split);
    chart_box->setStyleSheet(
        "QGroupBox {"
        "  background: #ffffff;"
        "  border: 1px solid #d0d4e8;"
        "  border-radius: 4px;"
        "  margin-top: 6px;"
        "  font-size: 10px; font-weight: bold; color: #3355cc; }"
        "QGroupBox::title {"
        "  subcontrol-origin: margin; subcontrol-position: top left;"
        "  padding: 0 6px; left: 8px; }");
    auto* chart_lay = new QVBoxLayout(chart_box);
    chart_lay->setContentsMargins(4, 8, 4, 4);
    chart_lay->setSpacing(0);

    traffic_chart_ = new TrafficChart(chart_box);
    chart_lay->addWidget(traffic_chart_);
    bot_split->addWidget(chart_box);

    bot_split->setSizes({580, 280});
    bot_split->setStretchFactor(0, 1);
    bot_split->setStretchFactor(1, 0);

    v_split->addWidget(bot_split);
    v_split->setSizes({420, 220});
    v_split->setStretchFactor(0, 3);
    v_split->setStretchFactor(1, 2);

    right_lay->addWidget(v_split);
    main_split->addWidget(right_w);

    main_split->setSizes({200, 1000});
    main_split->setStretchFactor(0, 0);
    main_split->setStretchFactor(1, 1);

    root->addWidget(main_split);

    // ── Connections ───────────────────────────────────────────────────────────
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
// setupOfflineLayout  — light theme
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::setupOfflineLayout() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(4);
    root->setContentsMargins(6, 6, 6, 6);

    // ── Toolbar ───────────────────────────────────────────────────────────────
    auto* toolbar = new QWidget(this);
    toolbar->setStyleSheet(
        "QWidget { background: #eef0f7;"
        "          border-bottom: 1px solid #d0d4e8; }");
    auto* tb_lay = new QHBoxLayout(toolbar);
    tb_lay->setContentsMargins(6, 4, 6, 4);
    tb_lay->setSpacing(6);

    const QString btn_base =
        "QPushButton { border: 1px solid #b0b8d8; border-radius: 4px;"
        "              padding: 4px 14px; font-size: 12px; }"
        "QPushButton:hover   { border-color: #3355cc; }"
        "QPushButton:pressed { padding: 5px 13px 3px 15px; }";

    auto* open_btn = new QPushButton("📂  Open PCAP", toolbar);
    open_btn->setStyleSheet(btn_base +
        "QPushButton { background: #ffffff; color: #3355cc; }");

    auto* export_btn = new QPushButton("💾  Export", toolbar);
    export_btn->setStyleSheet(btn_base +
        "QPushButton { background: #ffffff; color: #226622; }");

    tb_lay->addWidget(open_btn);
    tb_lay->addWidget(export_btn);
    tb_lay->addStretch();
    root->addWidget(toolbar);

    // ── FilterBar ─────────────────────────────────────────────────────────────
    filter_bar_ = new FilterBar(this);
    root->addWidget(filter_bar_);

    // ── Vertical splitter: table | detail+hex ─────────────────────────────────
    auto* v_split = new QSplitter(Qt::Vertical, this);
    v_split->setHandleWidth(4);
    v_split->setStyleSheet("QSplitter::handle { background: #d0d4e8; }");

    setupPacketTable();
    v_split->addWidget(packet_table_);

    auto* dh_split = new QSplitter(Qt::Horizontal, v_split);
    dh_split->setHandleWidth(4);
    dh_split->setStyleSheet("QSplitter::handle { background: #d0d4e8; }");

    detail_tree_ = new PacketDetailTree(dh_split);
    hex_view_    = new HexView(dh_split);
    dh_split->addWidget(detail_tree_);
    dh_split->addWidget(hex_view_);
    dh_split->setSizes({420, 420});

    v_split->addWidget(dh_split);
    v_split->setSizes({520, 280});
    root->addWidget(v_split);

    // ── Connections ───────────────────────────────────────────────────────────
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
    if (live_writer_ && live_writer_->isOpen()) live_writer_->close();

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
    if (live_writer_) { live_writer_->close(); live_writer_.reset(); }
}

int64_t PcapTab::writeLivePacket(const uint8_t*        raw_bytes,
                                   uint32_t              raw_len,
                                   uint32_t              orig_len,
                                   const struct timeval& ts) {
    std::lock_guard<std::mutex> lk(live_writer_mutex_);
    if (!live_writer_ || !live_writer_->isOpen()) return -1;
    return live_writer_->writePacket(raw_bytes, raw_len, orig_len, ts);
}

// ═════════════════════════════════════════════════════════════════════════════
// lazyLoadRawData
// ═════════════════════════════════════════════════════════════════════════════

bool PcapTab::lazyLoadRawData(int row, PacketInfo& pkt) {
    if (pkt.raw_data && !pkt.raw_data->empty()) return true;
    if (pkt.file_offset < 0 || pkt.source_file.empty()) return false;

    if (mode_ == Mode::LIVE) {
        std::lock_guard<std::mutex> lk(live_writer_mutex_);
        if (live_writer_ && live_writer_->isOpen()) live_writer_->flush();
    }

    if (!pcap_reader_) pcap_reader_ = std::make_unique<PcapReader>();
    if (!pcap_reader_->loadRawBytes(pkt, pkt.source_file)) return false;

    packet_model_->updateRawData(row, pkt.raw_data);
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// Slots
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::onPacketSelected(const QModelIndex& index) {
    if (!index.isValid()) return;
    PacketInfo pkt;
    if (!packet_model_->getRecord(index.row(), pkt)) return;
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
    if (!path.isEmpty()) loadFile(path);
}

void PcapTab::onExportClicked() {
    const QString path = QFileDialog::getSaveFileName(
        this, "Export PCAP",
        QDir::homePath() + "/export.pcap",
        "PCAP Files (*.pcap);;All Files (*)");
    if (!path.isEmpty()) saveToFile(path);
}

// ═════════════════════════════════════════════════════════════════════════════
// loadFile / saveToFile
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::loadFile(const QString& path) {
    packet_model_->clear();
    dummy_ring_buf_.clear();
    pcap_reader_ = std::make_unique<PcapReader>();

    const bool ok = pcap_reader_->scanFile(
        path.toStdString(), dummy_ring_buf_,
        [](uint64_t, uint64_t, double) {}, nullptr);

    if (!ok) { emit statusMessage("❌ Cannot open: " + path); return; }

    uint64_t last_seq = 0;
    packet_model_->appendRecords(dummy_ring_buf_.pollNew(last_seq));

    emit titleChanged ("📂 " + QFileInfo(path).fileName());
    emit statusMessage("✅ Loaded: " + path
        + "  (" + QString::number(packet_model_->rowCount()) + " packets)");
}

void PcapTab::saveToFile(const QString& path) {
    if (mode_ == Mode::LIVE && !live_writer_path_.isEmpty()) {
        {
            std::lock_guard<std::mutex> lk(live_writer_mutex_);
            if (live_writer_ && live_writer_->isOpen()) live_writer_->flush();
        }
        if (QFile::exists(path)) QFile::remove(path);
        if (QFile::copy(live_writer_path_, path))
            emit statusMessage(QString("💾 Saved: %1  (%2 packets)")
                .arg(QFileInfo(path).fileName())
                .arg(packet_model_->rowCount()));
        else
            emit statusMessage("❌ Copy failed: " + path);
        return;
    }

    PcapWriter writer;
    if (!writer.open(path.toStdString())) {
        emit statusMessage("❌ Cannot save: " + path); return;
    }
    const int n = packet_model_->rowCount();
    for (int i = 0; i < n; ++i) {
        PacketInfo pkt;
        if (!packet_model_->getRecord(i, pkt)) continue;
        if (!pkt.raw_data || pkt.raw_data->empty()) lazyLoadRawData(i, pkt);
        if (pkt.raw_data && !pkt.raw_data->empty()) writer.writePacket(pkt);
    }
    writer.close();
    emit statusMessage(QString("💾 Saved: %1  (%2 packets)")
        .arg(QFileInfo(path).fileName()).arg(n));
}

// ═════════════════════════════════════════════════════════════════════════════
// timerEvent
// ═════════════════════════════════════════════════════════════════════════════

void PcapTab::timerEvent(QTimerEvent* event) {
    if (!packet_model_) return;

    if (event->timerId() == overlay_timer_id_) {
        const bool     capturing = capture_in_progress_.load(std::memory_order_acquire);
        const uint64_t total_now = bridge_ ? bridge_->ringBuf().totalPushed() : 0;
        const bool     has_new   = (total_now > last_polled_seq_);

        if (has_new) {
            constexpr uint64_t MAX_PER_TICK = 500;
            const uint64_t to_fetch = std::min(total_now - last_polled_seq_, MAX_PER_TICK);
            auto batch = bridge_->ringBuf().pollRange(last_polled_seq_, to_fetch);
            last_polled_seq_ += to_fetch;

            if (!batch.empty()) {
                packet_model_->freeze();
                packet_model_->appendRecords(batch);
                packet_model_->thaw();
                if (packet_model_->isDirty()) {
                    packet_table_->viewport()->update();
                    packet_model_->clearDirty();
                }
            }
        }

        if (!capturing && !has_new) {
            killTimer(overlay_timer_id_);
            overlay_timer_id_ = -1;
            emit statusMessage(QString("⏹ Capture stopped — %1 packets")
                .arg(packet_model_->rowCount()));
        }
        return;
    }

    if (event->timerId() == tail_timer_id_) {
        if (tail_at_end_ && packet_model_->rowCount() > 0) {
            auto* vsb = packet_table_->verticalScrollBar();
            if (vsb->value() >= vsb->maximum() - 3)
                packet_table_->scrollToBottom();
        }
        if (!capture_in_progress_.load(std::memory_order_acquire)) {
            killTimer(tail_timer_id_);
            tail_timer_id_ = -1;
        }
        return;
    }

    QWidget::timerEvent(event);
}

void PcapTab::onNewPacketInfos(std::vector<PacketInfo> records) {
    if (records.empty() || mode_ == Mode::LIVE) return;
    packet_model_->appendRecords(records);
}

void PcapTab::clearDisplay() {
    // Clear model (danh sách gói tin)
    if (packet_model_)
        packet_model_->clear();

    // Clear panel chi tiết
    if (detail_tree_)
        detail_tree_->clearDetail();

    // Clear hex view
    if (hex_view_)
        hex_view_->clearData();
}
