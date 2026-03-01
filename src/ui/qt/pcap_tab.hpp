// ── pcap_tab.hpp ──────────────────────────────────────────────────────────────
#pragma once
#include <QWidget>
#include <QSplitter>
#include <QTableView>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QStatusBar>
#include <QToolBar>
#include <QTimer>
#include <memory>
#include <atomic>

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
    // Mode: offline (load file) hoặc live (capture đang chạy)
    enum class Mode { OFFLINE, LIVE };

    explicit PcapTab(Mode mode, QWidget* parent = nullptr);
    ~PcapTab() override;

    // Offline: load từ file
    void loadFile(const QString& filepath);

    // Live: nhận packets từ engine
    void appendLivePacket(const PacketRecord& record);

    // Lưu packets hiện tại ra file
    void saveToFile(const QString& filepath);

    // Tên tab
    QString tabTitle() const { return tab_title_; }

    // Số packets đang hiển thị
    int visibleCount() const;

signals:
    void titleChanged(QString title);
    void statusMessage(QString msg);

public slots:
    void onPacketSelected(const QModelIndex& index);
    void onFilterChanged(DisplayFilter filter);
    void onSaveClicked();
    void onOpenClicked();
    void onClearClicked();
    void onLiveTimer();
    void onLoadProgress(uint64_t loaded, uint64_t total, double pct);

private:
    void setupUI();
    void setupToolbar();
    void loadRawBytesForRecord(PacketRecord& record);

    Mode                              mode_;
    QString                           tab_title_;
    QString                           current_filepath_;

    // Core data
    PacketRingBuffer                  ring_buf_;
    std::unique_ptr<PacketListModel>  list_model_;
    std::unique_ptr<PcapReader>       reader_;
    std::unique_ptr<PcapWriter>       writer_;

    // Widgets
    QToolBar*          toolbar_;
    FilterBar*         filter_bar_;
    QTableView*        packet_table_;
    PacketDetailTree*  detail_tree_;
    HexView*           hex_view_;
    QLabel*            stats_label_;
    QProgressBar*      progress_bar_;

    // Live capture timer
    QTimer             live_timer_;

    // Cancel flag cho scan thread
    std::atomic<bool>  cancel_scan_{false};

    // Pending live packets (thread-safe buffer)
    std::mutex                  live_mutex_;
    std::vector<PacketRecord>   live_pending_;
};
