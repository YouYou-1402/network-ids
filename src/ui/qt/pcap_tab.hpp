// src/ui/qt/pcap_tab.hpp
#pragma once
#include <QWidget>
#include <QTableView>
#include <QSplitter>
#include <QPushButton>
#include <QLabel>
#include <QFrame>
#include <QTabWidget>
#include <QTimerEvent>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>

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
class UiBridge;
struct DisplayFilter;

class PcapTab : public QWidget {
    Q_OBJECT

public:
    enum class Mode { LIVE, OFFLINE };

    explicit PcapTab(Mode mode, QWidget* parent = nullptr);
    ~PcapTab();

    void setUiBridge   (UiBridge* bridge);
    void loadFile      (const QString& path);
    void saveToFile    (const QString& path);
    void startLiveWriter(const QString& temp_path);
    void stopLiveWriter ();
    int64_t writeLivePacket(const uint8_t*        raw_bytes,
                             uint32_t              raw_len,
                             uint32_t              orig_len,
                             const struct timeval& ts);

    QString liveWriterPath() const { return live_writer_path_; }
    void    onOpenClicked  ();


signals:
    void titleChanged  (const QString& title);
    void statusMessage (const QString& msg);

protected:
    void timerEvent(QTimerEvent* event) override;

private slots:
    void onPacketSelected(const QModelIndex& index);
    void onFilterApplied (const QString& filter);
    void onFilterCleared ();
    void onExportClicked ();
    void onNewPacketInfos(std::vector<PacketInfo> records);

private:
    void setupLiveLayout   ();
    void setupOfflineLayout();
    void setupPacketTable  ();
    void connectBridgeSignals();
    bool lazyLoadRawData(int row, PacketInfo& pkt);

    Mode      mode_;
    UiBridge* bridge_ = nullptr;

    PacketRingBuffer dummy_ring_buf_{1000'000};

    QTableView*       packet_table_    = nullptr;
    PacketListModel*  packet_model_    = nullptr;
    PacketDetailTree* detail_tree_     = nullptr;
    HexView*          hex_view_        = nullptr;
    FilterBar*        filter_bar_      = nullptr;
    MetricsWidget*    metrics_widget_  = nullptr;
    TrafficChart*     traffic_chart_   = nullptr;

    std::unique_ptr<PcapReader> pcap_reader_;
    std::unique_ptr<PcapWriter> live_writer_;
    mutable std::mutex          live_writer_mutex_;
    QString                     live_writer_path_;

    bool auto_scroll_ = true;

    int  overlay_timer_id_ = -1;
    int  tail_timer_id_    = -1;
    bool tail_at_end_      = true;

    std::atomic<bool> capture_in_progress_{false};
    uint64_t          last_polled_seq_ = 0;
};
