// ── pcap_tab.hpp ──────────────────────────────────────────────────────────────
#pragma once
#include <QWidget>
#include <QSplitter>
#include <QTableView>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QScrollBar>
#include <QToolBar>
#include <QTimer>
#include <QFileInfo>
#include <QDir>

#include <memory>
#include <atomic>
#include <mutex>
#include <vector>
#include <chrono>

#include "filter_bar.hpp"
#include "packet_list_model.hpp"
#include "packet_detail_tree.hpp"
#include "hex_view.hpp"
#include "../../pcap_io/pcap_reader.hpp"
#include "../../pcap_io/pcap_writer.hpp"
#include "../../pcap_io/packet_ring_buffer.hpp"

class PcapTab : public QWidget {
    Q_OBJECT

public:
    enum class Mode { OFFLINE, LIVE };

    // Ngưỡng tự động điều chỉnh render interval
    static constexpr int    RENDER_INTERVAL_NORMAL_MS  = 200;   // < 500 pps
    static constexpr int    RENDER_INTERVAL_FAST_MS    = 500;   // 500–2000 pps
    static constexpr int    RENDER_INTERVAL_TURBO_MS   = 1000;  // > 2000 pps
    static constexpr size_t MAX_ROWS_PER_FLUSH         = 300;   // rows/tick tối đa
    static constexpr size_t MAX_PENDING_BUFFER         = 10000; // pending tối đa
    static constexpr size_t DROP_TO_SIZE               = 5000;  // khi tràn, giữ lại

    explicit PcapTab(Mode mode, QWidget* parent = nullptr);
    ~PcapTab() override;

    // Offline
    void    loadFile(const QString& filepath);

    // Live — nhận batch từ UiBridge (1 lần lock thay vì N lần)
    void    appendLivePackets(std::vector<PacketRecord> records);

    // Compat: nhận từng packet (wrap thành batch)
    void    appendLivePacket(const PacketRecord& record);

    void    saveToFile(const QString& filepath);
    QString tabTitle()    const { return tab_title_; }
    int     visibleCount() const;

    // Wireshark-style: tạm dừng render (vẫn capture)
    void    setRenderPaused(bool paused);
    bool    isRenderPaused() const { return render_paused_; }

signals:
    void titleChanged  (QString title);
    void statusMessage (QString msg);

public slots:
    void onOpenClicked();
    void onSaveClicked();
    void onClearClicked();
    void onPacketSelected (const QModelIndex& index);
    void onFilterChanged  (DisplayFilter filter);
    void onLoadProgress   (uint64_t loaded, uint64_t total, double pct);

private slots:
    void onLiveTimer();
    void onPpsCheckTimer();   // đo PPS mỗi 1s → tự chỉnh render interval

private:
    void setupUI();
    void setupToolbar();
    void flushPendingToModel();
    void loadRawBytesForRecord(PacketRecord& record);
    void updateAdaptiveInterval(double pps);

    // ── Mode & state ──────────────────────────────────────────────────────────
    Mode              mode_;
    QString           tab_title_;
    QString           current_filepath_;
    std::atomic<bool> cancel_scan_    { false };
    bool              render_paused_  { false };
    bool              auto_scroll_    { true  };

    // ── Backend ───────────────────────────────────────────────────────────────
    PacketRingBuffer                  ring_buf_;
    std::unique_ptr<PacketListModel>  list_model_;
    std::unique_ptr<PcapReader>       reader_;
    std::unique_ptr<PcapWriter>       writer_;

    // ── Live mode ─────────────────────────────────────────────────────────────
    QTimer             live_timer_;       // flush pending → model
    QTimer             pps_check_timer_;  // đo PPS → điều chỉnh interval

    mutable std::mutex          live_mutex_;
    std::vector<PacketRecord>   live_pending_;

    // PPS tracking
    uint64_t pps_last_count_    { 0 };
    double   current_pps_       { 0.0 };

    // ── Widgets ───────────────────────────────────────────────────────────────
    QToolBar*         toolbar_      { nullptr };
    FilterBar*        filter_bar_   { nullptr };
    QProgressBar*     progress_bar_ { nullptr };
    QTableView*       packet_table_ { nullptr };
    PacketDetailTree* detail_tree_  { nullptr };
    HexView*          hex_view_     { nullptr };
    QLabel*           stats_label_  { nullptr };
    QLabel*           pps_label_    { nullptr };  // hiển thị PPS realtime
    QAction*          pause_act_    { nullptr };  // nút Pause render
};
