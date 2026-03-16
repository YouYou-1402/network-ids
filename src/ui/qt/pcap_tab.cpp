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
#include <QDir>
#include <QMessageBox>
#include <QScrollBar>
#include <QHeaderView>

// ─── Constructor ──────────────────────────────────────────────────────────────
PcapTab::PcapTab(Mode mode, QWidget* parent)
    : QWidget(parent)
    , mode_(mode)
{
    if (mode_ == Mode::LIVE)
        setupLiveLayout();
    else
        setupOfflineLayout();
}

// ─── setUiBridge ──────────────────────────────────────────────────────────────
//
//  Gọi sau constructor — bridge_ chưa có lúc setupPacketTable() chạy
//  Bước 1: rebuild PacketListModel với ring_buf_ thật từ bridge
//  Bước 2: connectBridgeSignals() — kết nối tất cả signal/slot
// ─────────────────────────────────────────────────────────────────────────────
void PcapTab::setUiBridge(UiBridge* bridge) {
    bridge_ = bridge;
    if (!bridge_) return;

    if (mode_ == Mode::LIVE) {
        // ── Rebuild PacketListModel với ring_buf_ thật ─────────────────────────
        // dummy_ring_buf_ được dùng tạm trong setupPacketTable()
        // Giờ thay bằng ring_buf_ thật để getRecord() đọc đúng data
        auto* old_model = packet_model_;
        packet_model_ = new PacketListModel(bridge_->ringBuf(), this);
        packet_table_->setModel(packet_model_);

        // Reconnect selection signal với model mới
        connect(packet_table_->selectionModel(),
                &QItemSelectionModel::currentRowChanged,
                this, [this](const QModelIndex& cur, const QModelIndex&) {
                    onPacketSelected(cur);
                });

        delete old_model;   // xóa model cũ sau khi đã swap
    }

    // ── Kết nối tất cả bridge signals ─────────────────────────────────────────
    // PHẢI gọi sau khi bridge_ đã được set
    connectBridgeSignals();

    if (ips_control_) {
        ips_control_->syncState(
            bridge_->isDetectionEnabled(),
            bridge_->isMlEnabled());
    }
}

// ─── connectBridgeSignals ─────────────────────────────────────────────────────
void PcapTab::connectBridgeSignals() {
    if (!bridge_) return;

    // Metrics → MetricsWidget
    if (metrics_widget_)
        connect(bridge_, &UiBridge::metricsUpdated,
                metrics_widget_, &MetricsWidget::onMetricsUpdated);

    // Traffic → TrafficChart
    if (traffic_chart_)
        connect(bridge_, &UiBridge::trafficUpdated,
                traffic_chart_, &TrafficChart::onTrafficUpdated);

    // Alerts → AlertPanel
    if (alert_panel_)
        connect(bridge_, &UiBridge::newAlerts,
                alert_panel_, &AlertPanel::onNewAlerts);

    // Live packets → onNewPacketInfos (single source of truth)
    connect(bridge_, &UiBridge::newPacketInfos,
            this,    &PcapTab::onNewPacketInfos);

    // IpsControlWidget ↔ UiBridge
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

// ─── setupLiveLayout ──────────────────────────────────────────────────────────
void PcapTab::setupLiveLayout() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(4);
    root->setContentsMargins(4, 4, 4, 4);

    filter_bar_ = new FilterBar(this);
    root->addWidget(filter_bar_);

    auto* h_splitter = new QSplitter(Qt::Horizontal, this);
    h_splitter->setHandleWidth(4);
    h_splitter->setStyleSheet("QSplitter::handle { background: #2a2a3e; }");

    // ── Left panel ────────────────────────────────────────────────────────────
    auto* left_widget = new QWidget(h_splitter);
    auto* left_layout = new QVBoxLayout(left_widget);
    left_layout->setSpacing(4);
    left_layout->setContentsMargins(0, 0, 0, 0);

    setupPacketTable();
    left_layout->addWidget(packet_table_, 3);

    auto* detail_splitter = new QSplitter(Qt::Horizontal, left_widget);
    detail_splitter->setHandleWidth(4);
    detail_splitter->setStyleSheet("QSplitter::handle { background: #2a2a3e; }");

    detail_tree_ = new PacketDetailTree(left_widget);
    hex_view_    = new HexView(left_widget);

    detail_splitter->addWidget(detail_tree_);
    detail_splitter->addWidget(hex_view_);
    detail_splitter->setSizes({300, 300});

    left_layout->addWidget(detail_splitter, 2);
    h_splitter->addWidget(left_widget);

    // ── Right panel ───────────────────────────────────────────────────────────
    auto* right_tabs = new QTabWidget(h_splitter);
    right_tabs->setFixedWidth(300);
    right_tabs->setStyleSheet(
        "QTabWidget::pane  { border: 1px solid #333; background: #0f0f1a; }"
        "QTabBar::tab      { background: #1a1a2e; color: #888888; "
        "                    border: 1px solid #333; padding: 4px 8px; "
        "                    font-size: 10px; }"
        "QTabBar::tab:selected { background: #2a2a4a; color: #ffffff; "
        "                        border-bottom: 2px solid #4488ff; }"
        "QTabBar::tab:hover    { background: #252540; }");

    metrics_widget_ = new MetricsWidget(right_tabs);
    right_tabs->addTab(metrics_widget_, "📊 Stats");

    traffic_chart_ = new TrafficChart(right_tabs);
    right_tabs->addTab(traffic_chart_, "📈 Traffic");

    alert_panel_ = new AlertPanel(right_tabs);
    right_tabs->addTab(alert_panel_, "🚨 Alerts");

    ips_control_ = new IpsControlWidget(right_tabs);
    right_tabs->addTab(ips_control_, "🛡️ IPS");

    right_tabs->setCurrentIndex(3);

    h_splitter->addWidget(right_tabs);
    h_splitter->setSizes({900, 300});

    root->addWidget(h_splitter);

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

// ─── setupOfflineLayout ───────────────────────────────────────────────────────
void PcapTab::setupOfflineLayout() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(4);
    root->setContentsMargins(4, 4, 4, 4);

    filter_bar_ = new FilterBar(this);
    root->addWidget(filter_bar_);

    auto* v_splitter = new QSplitter(Qt::Vertical, this);
    v_splitter->setHandleWidth(4);
    v_splitter->setStyleSheet("QSplitter::handle { background: #2a2a3e; }");

    setupPacketTable();
    v_splitter->addWidget(packet_table_);

    auto* detail_splitter = new QSplitter(Qt::Horizontal, v_splitter);
    detail_splitter->setHandleWidth(4);
    detail_splitter->setStyleSheet("QSplitter::handle { background: #2a2a3e; }");

    detail_tree_ = new PacketDetailTree(v_splitter);
    hex_view_    = new HexView(v_splitter);

    detail_splitter->addWidget(detail_tree_);
    detail_splitter->addWidget(hex_view_);
    detail_splitter->setSizes({400, 400});

    v_splitter->addWidget(detail_splitter);
    v_splitter->setSizes({500, 300});

    root->addWidget(v_splitter);

    // Toolbar
    auto* toolbar = new QWidget(this);
    auto* tb_ly   = new QHBoxLayout(toolbar);
    tb_ly->setContentsMargins(0, 4, 0, 0);

    auto* open_btn = new QPushButton("📂 Open PCAP", toolbar);
    open_btn->setStyleSheet(
        "QPushButton { background: #2a2a3e; color: #88aaff; "
        "border: 1px solid #444; border-radius: 4px; padding: 4px 12px; }"
        "QPushButton:hover { background: #3a3a5a; }");

    auto* export_btn = new QPushButton("💾 Export", toolbar);
    export_btn->setStyleSheet(
        "QPushButton { background: #2a3a2a; color: #88ff88; "
        "border: 1px solid #446644; border-radius: 4px; padding: 4px 12px; }"
        "QPushButton:hover { background: #3a4a3a; }");

    tb_ly->addWidget(open_btn);
    tb_ly->addWidget(export_btn);
    tb_ly->addStretch();
    root->insertWidget(0, toolbar);

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

// ─── setupPacketTable ─────────────────────────────────────────────────────────
//  Dùng dummy_ring_buf_ tạm thời.
//  LIVE mode: setUiBridge() sẽ rebuild với ring_buf_ thật.
//  OFFLINE mode: loadFile() sẽ scan vào dummy_ring_buf_.
// ─────────────────────────────────────────────────────────────────────────────
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

    packet_table_->setColumnWidth(0, 55);
    packet_table_->setColumnWidth(1, 85);
    packet_table_->setColumnWidth(2, 115);
    packet_table_->setColumnWidth(3, 115);
    packet_table_->setColumnWidth(4, 55);
    packet_table_->setColumnWidth(5, 60);
    packet_table_->setColumnWidth(6, 80);
    packet_table_->setColumnWidth(7, 100);

    packet_table_->setStyleSheet(
        "QTableView { background: #0a0a14; color: #cccccc; "
        "border: 1px solid #2a2a3e; gridline-color: #1a1a2a; "
        "font-size: 11px; font-family: 'Consolas', monospace; }"
        "QTableView::item { padding: 1px 4px; border: none; }"
        "QTableView::item:selected { background: #2a2a5a; color: #ffffff; }"
        "QHeaderView::section { background: #1a1a2e; color: #8888aa; "
        "border: none; border-bottom: 1px solid #333; "
        "padding: 3px 4px; font-size: 10px; font-weight: bold; }");
}

// ─── onNewPacketInfos ─────────────────────────────────────────────────────────
//  Single entry point cho live packets — chỉ UiBridge gọi signal này
//  pkt.index đã được set bởi ring_buf_.push() → getRecord() hoạt động đúng
// ─────────────────────────────────────────────────────────────────────────────
void PcapTab::onNewPacketInfos(std::vector<PacketInfo> records) {
    if (records.empty()) return;
    packet_model_->appendRecords(records);
    if (auto_scroll_)
        packet_table_->scrollToBottom();
}

// ─── onPacketSelected ─────────────────────────────────────────────────────────
void PcapTab::onPacketSelected(const QModelIndex& index) {
    if (!index.isValid()) return;

    PacketInfo pkt;
    if (!packet_model_->getRecord(index.row(), pkt)) return;

    if (detail_tree_) detail_tree_->showPacket(pkt);
    if (hex_view_) {
        if (pkt.raw_data && !pkt.raw_data->empty())
            hex_view_->setData(*pkt.raw_data);
        else
            hex_view_->clearData();
    }
}

// ─── Filter ───────────────────────────────────────────────────────────────────
void PcapTab::onFilterApplied(const QString& /*filter*/) {
    if (!packet_model_) return;
    DisplayFilter f = filter_bar_->currentFilter();
    packet_model_->applyFilter(f);
}

void PcapTab::onFilterCleared() {
    if (!packet_model_) return;
    packet_model_->applyFilter(DisplayFilter{});
}

// ─── loadFile ─────────────────────────────────────────────────────────────────
void PcapTab::loadFile(const QString& path) {
    pcap_reader_ = std::make_unique<PcapReader>();
    packet_model_->clear();
    dummy_ring_buf_.clear();

    const bool ok = pcap_reader_->scanFile(
        path.toStdString(),
        dummy_ring_buf_,
        [](uint64_t, uint64_t, double) {},
        nullptr);

    if (!ok) {
        emit statusMessage("❌ Cannot open: " + path);
        return;
    }

    uint64_t last_seq = 0;
    std::vector<PacketInfo> pkts = dummy_ring_buf_.pollNew(last_seq);
    packet_model_->appendRecords(pkts);

    emit titleChanged("📂 " + QFileInfo(path).fileName());
    emit statusMessage("✅ Loaded: " + path
                       + "  (" + QString::number(packet_model_->rowCount()) + " packets)");
}

// ─── saveToFile ───────────────────────────────────────────────────────────────
void PcapTab::saveToFile(const QString& path) {
    pcap_writer_ = std::make_unique<PcapWriter>();
    if (!pcap_writer_->open(path.toStdString())) {
        emit statusMessage("❌ Cannot save: " + path);
        return;
    }
    const int n = packet_model_->rowCount();
    for (int i = 0; i < n; ++i) {
        PacketInfo pkt;
        if (packet_model_->getRecord(i, pkt))
            pcap_writer_->writePacket(pkt);
    }
    pcap_writer_->close();
    emit statusMessage("💾 Saved: " + path
                       + "  (" + QString::number(n) + " packets)");
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
