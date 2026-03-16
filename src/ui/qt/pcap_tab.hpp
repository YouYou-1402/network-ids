#pragma once
#include <QWidget>
#include <QTableView>
#include <QSplitter>
#include <QPushButton>
#include <QLabel>
#include <QFrame>
#include <QTabWidget>
#include <vector>
#include <memory>
#include <mutex>

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
struct DisplayFilter;

class PcapTab : public QWidget {
    Q_OBJECT

public:
    enum class Mode { LIVE, OFFLINE };

    explicit PcapTab(Mode mode, QWidget* parent = nullptr);
    ~PcapTab();

    // ── Bridge (LIVE only) ────────────────────────────────────────────────────
    void setUiBridge(UiBridge* bridge);

    // ── File I/O ──────────────────────────────────────────────────────────────
    void loadFile  (const QString& path);   // OFFLINE: scan + hiển thị
    void saveToFile(const QString& path);   // LIVE: copy temp; OFFLINE: dump

    // ── Live writer API — gọi từ MainWindow ───────────────────────────────────
    // startLiveWriter: mở file tạm trước khi capture thread chạy
    // stopLiveWriter : flush + close sau khi capture thread kết thúc
    // writeLivePacket: ghi từng packet (thread-safe), trả về file_offset
    void    startLiveWriter(const QString& temp_path);
    void    stopLiveWriter ();
    int64_t writeLivePacket(const uint8_t*        raw_bytes,
                             uint32_t              raw_len,
                             uint32_t              orig_len,
                             const struct timeval& ts);

    QString liveWriterPath() const { return live_writer_path_; }

    // ── Toolbar slot (public — MainWindow có thể gọi) ─────────────────────────
    void onOpenClicked();

signals:
    void titleChanged  (const QString& title);
    void statusMessage (const QString& msg);

private slots:
    void onPacketSelected(const QModelIndex& index);
    void onFilterApplied (const QString& filter);
    void onFilterCleared ();
    void onExportClicked ();
    void onNewPacketInfos(std::vector<PacketInfo> records);

private:
    // ── Layout builders ───────────────────────────────────────────────────────
    void setupLiveLayout   ();
    void setupOfflineLayout();
    void setupPacketTable  ();
    void connectBridgeSignals();

    // ── Lazy-load raw bytes từ disk cho 1 packet ──────────────────────────────
    // Trả về true nếu load thành công, cập nhật pkt.raw_data
    bool lazyLoadRawData(int row, PacketInfo& pkt);

    // ── Mode ──────────────────────────────────────────────────────────────────
    Mode      mode_;
    UiBridge* bridge_ = nullptr;

    // dummy_ring_buf_:
    //   LIVE    — PacketListModel tạm trước khi setUiBridge() được gọi
    //   OFFLINE — PcapReader scan vào đây, PacketListModel đọc metadata
    PacketRingBuffer dummy_ring_buf_{100'000};

    // ── Packet view ───────────────────────────────────────────────────────────
    QTableView*       packet_table_ = nullptr;
    PacketListModel*  packet_model_ = nullptr;
    PacketDetailTree* detail_tree_  = nullptr;
    HexView*          hex_view_     = nullptr;
    FilterBar*        filter_bar_   = nullptr;

    // ── Live-only widgets ─────────────────────────────────────────────────────
    MetricsWidget*    metrics_widget_ = nullptr;
    TrafficChart*     traffic_chart_  = nullptr;
    AlertPanel*       alert_panel_    = nullptr;
    IpsControlWidget* ips_control_    = nullptr;

    // ── I/O ───────────────────────────────────────────────────────────────────
    // pcap_reader_: dùng cho OFFLINE load + lazy-load khi click (cả LIVE)
    std::unique_ptr<PcapReader> pcap_reader_;

    // live_writer_: ghi liên tục trong khi capture
    std::unique_ptr<PcapWriter> live_writer_;
    mutable std::mutex          live_writer_mutex_;
    QString                     live_writer_path_;

    // ── Misc ──────────────────────────────────────────────────────────────────
    bool auto_scroll_ = true;
};
