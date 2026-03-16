// src/ui/qt/pcap_tab.hpp
#pragma once
#include <QWidget>
#include <QSplitter>
#include <QTableView>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QTimer>
#include <vector>
#include <memory>

#include "../../core/packet_info.hpp"
#include "../../capture/io/pcap_reader.hpp"
#include "../../capture/io/pcap_writer.hpp"
#include "../../capture/io/packet_ring_buffer.hpp"

class PacketListModel;
class PacketDetailTree;
class HexView;
class FilterBar;
class MetricsWidget;
class TrafficChart;
class AlertPanel;
class IpsControlWidget;
class UiBridge;

class PcapTab : public QWidget {
    Q_OBJECT

public:
    enum class Mode { LIVE, OFFLINE };

    explicit PcapTab(Mode mode, QWidget* parent = nullptr);

    void setUiBridge(UiBridge* bridge);
    // appendLivePackets đã bị xóa — live packet đi qua UiBridge::newPacketInfos
    void loadFile   (const QString& path);
    void saveToFile (const QString& path);
    void onOpenClicked();

signals:
    void titleChanged  (const QString& title);
    void statusMessage (const QString& msg);

private slots:
    void onPacketSelected (const QModelIndex& index);
    void onFilterApplied  (const QString& filter);
    void onFilterCleared  ();
    void onExportClicked  ();
    void onNewPacketInfos (std::vector<PacketInfo> records);  // từ UiBridge

private:
    void setupLiveLayout   ();
    void setupOfflineLayout();
    void setupPacketTable  ();
    void connectBridgeSignals();

    Mode      mode_;
    UiBridge* bridge_ = nullptr;

    // dummy_ring_buf_ dùng cho:
    //   - LIVE mode: PacketListModel tạm thời trước khi setUiBridge() được gọi
    //   - OFFLINE mode: PcapReader scan vào đây, PacketListModel đọc từ đây
    PacketRingBuffer dummy_ring_buf_{500'000, 50'000};

    // ── Packet view ───────────────────────────────────────────────────────────
    QTableView*       packet_table_  = nullptr;
    PacketListModel*  packet_model_  = nullptr;
    PacketDetailTree* detail_tree_   = nullptr;
    HexView*          hex_view_      = nullptr;
    FilterBar*        filter_bar_    = nullptr;

    // ── Live-only widgets ─────────────────────────────────────────────────────
    MetricsWidget*    metrics_widget_  = nullptr;
    TrafficChart*     traffic_chart_   = nullptr;
    AlertPanel*       alert_panel_     = nullptr;
    IpsControlWidget* ips_control_     = nullptr;

    // ── Offline ───────────────────────────────────────────────────────────────
    std::unique_ptr<PcapReader> pcap_reader_;
    std::unique_ptr<PcapWriter> pcap_writer_;

    bool auto_scroll_ = true;
};
