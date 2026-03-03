#pragma once
#include <QAbstractTableModel>
#include <QColor>
#include <QFont>
#include <deque>
#include <mutex>
#include <vector>
#include <memory>
#include "../../pcap_io/packet_ring_buffer.hpp"
#include "filter_bar.hpp"

// ─── PacketListModel ──────────────────────────────────────────────────────────
class PacketListModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        COL_NO = 0, COL_TIME, COL_SRC_IP, COL_DST_IP,
        COL_PROTO, COL_LEN, COL_INFO, COL_THREAT,
        COL_COUNT
    };

    static constexpr int      MAX_DISPLAY_ROWS = 50000;
    static constexpr int      SCROLL_CHUNK     = 200;

    explicit PacketListModel(PacketRingBuffer& ring_buf,
                              QObject*          parent = nullptr);

    // QAbstractTableModel interface
    int      rowCount   (const QModelIndex& parent = {}) const override;
    int      columnCount(const QModelIndex& parent = {}) const override;
    QVariant headerData (int section, Qt::Orientation, int role) const override;
    QVariant data       (const QModelIndex&, int role) const override;

    // ── Mutators (main thread only) ───────────────────────────────────────────
    void appendRecords(const std::vector<PacketRecord>& batch);
    void applyFilter  (const DisplayFilter& filter);
    void clear        ();

    std::shared_ptr<PacketRecord> recordAt(int row) const;

private:
    // ✅ RowCache: tất cả display data đã pre-computed
    // data() chỉ đọc struct này — không lock, không alloc
    struct RowCache {
        uint64_t pkt_idx  = 0;
        uint32_t orig_len = 0;
        QString  time_str;
        QString  src;        // "1.2.3.4:1234"
        QString  dst;        // "5.6.7.8:80"
        QString  proto;      // "HTTP"
        QString  info;       // "[SYN] 1234→80 len=0"
        QString  threat;     // "" hoặc "DDOS_VOLUMETRIC"
        QColor   bg_color;
    };

    // ── Helpers — pure functions, không lock ──────────────────────────────────
    RowCache     buildRowCache   (const PacketRecord& r) const;
    bool         matchFilter     (uint64_t idx, const DisplayFilter& f) const;
    QString      computeProto    (const PacketRecord& r) const;
    QString      computeInfo     (const PacketRecord& r) const;
    QColor       computeRowColor (const PacketRecord& r) const;

    // ── Data ──────────────────────────────────────────────────────────────────
    PacketRingBuffer&    ring_buf_;
    DisplayFilter        current_filter_;
    double               base_timestamp_ = -1.0;

    // ✅ row_cache_ và filtered_indices_ chỉ được đọc/ghi từ main thread
    // → KHÔNG cần mutex trong data() / rowCount()
    std::deque<RowCache>   row_cache_;
    std::deque<uint64_t>   filtered_indices_;

    // mutex_ chỉ bảo vệ applyFilter/clear khi gọi từ background thread
    mutable std::mutex     mutex_;
};
