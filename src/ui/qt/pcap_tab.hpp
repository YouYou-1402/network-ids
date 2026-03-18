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
class IpsControlWidget;
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
    // ── Wireshark timerEvent ──────────────────────────────────────────────────
    // Wireshark dùng timerEvent() thay QTimer::timeout để điều tiết repaint
    // Lý do: timerEvent được Qt queue sau khi event loop rảnh
    //        → không block UI khi đang xử lý mouse/keyboard event
    //        → QTimer::timeout có thể fire ngay giữa paint event → flicker
    //
    // overlay_timer_id_  : 100ms — poll ring_buf + freeze/thaw
    // tail_timer_id_     : 200ms — auto-scroll nếu tail_at_end_
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

    PacketRingBuffer dummy_ring_buf_{100'000};

    QTableView*       packet_table_   = nullptr;
    PacketListModel*  packet_model_   = nullptr;
    PacketDetailTree* detail_tree_    = nullptr;
    HexView*          hex_view_       = nullptr;
    FilterBar*        filter_bar_     = nullptr;
    MetricsWidget*    metrics_widget_ = nullptr;
    TrafficChart*     traffic_chart_  = nullptr;
    AlertPanel*       alert_panel_    = nullptr;
    IpsControlWidget* ips_control_    = nullptr;

    std::unique_ptr<PcapReader> pcap_reader_;
    std::unique_ptr<PcapWriter> live_writer_;
    mutable std::mutex          live_writer_mutex_;
    QString                     live_writer_path_;

    bool auto_scroll_ = true;

    // ── Wireshark-style timer IDs ─────────────────────────────────────────────
    // overlay_timer_id_ : startTimer(100) — poll + freeze/thaw
    // tail_timer_id_    : startTimer(200) — auto-scroll
    // -1 = chưa start
    int overlay_timer_id_ = -1;
    int tail_timer_id_    = -1;

    // tail_at_end_: true khi user đang ở cuối list → auto-scroll
    // Wireshark: set true khi capture bắt đầu, false khi user scroll lên
    bool tail_at_end_ = true;

    // capture_in_progress_: true khi đang live capture
    // timerEvent dừng overlay timer khi false + pending rỗng
    std::atomic<bool> capture_in_progress_{false};

    // last_polled_seq_: seq cuối đã poll từ ring_buf
    // Chỉ đọc/ghi trong timerEvent (UI thread) → không cần mutex
    uint64_t last_polled_seq_ = 0;
};
