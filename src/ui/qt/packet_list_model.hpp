// src/ui/qt/packet_list_model.hpp
#pragma once
#include <QAbstractTableModel>
#include <QColor>
#include <QFont>
#include <deque>
#include <mutex>
#include <vector>
#include <memory>
#include "../../capture/io/packet_ring_buffer.hpp"
#include "filter_bar.hpp"

class PacketListModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        COL_NO = 0, COL_TIME, COL_SRC_IP, COL_DST_IP,
        COL_PROTO, COL_LEN, COL_INFO, COL_THREAT,
        COL_COUNT
    };

    static constexpr int MAX_DISPLAY_ROWS = 50000;
    static constexpr int SCROLL_CHUNK     = 200;

    explicit PacketListModel(PacketRingBuffer& ring_buf,
                              QObject*          parent = nullptr);

    // ── QAbstractTableModel interface ─────────────────────────────────────────
    int      rowCount   (const QModelIndex& parent = {}) const override;
    int      columnCount(const QModelIndex& parent = {}) const override;
    QVariant headerData (int section, Qt::Orientation, int role) const override;
    QVariant data       (const QModelIndex&, int role)           const override;

    // ── Mutators (main thread only) ───────────────────────────────────────────
    void appendRecords(const std::vector<PacketInfo>& batch);
    void applyFilter  (const DisplayFilter& filter);
    void clear        ();

    std::shared_ptr<PacketInfo> recordAt(int row) const;

private:
    // ── Pre-computed display cache ────────────────────────────────────────────
    struct RowCache {
        // frame_no = r.index + 1  (1-based, cố định suốt vòng đời packet)
        // Gán 1 lần khi buildRowCache, không bao giờ thay đổi dù filter/clear
        uint64_t frame_no  = 0;
        uint64_t pkt_idx   = 0;   // r.index — dùng cho recordAt()
        uint32_t orig_len  = 0;
        QString  time_str;
        QString  src;
        QString  dst;
        QString  proto;
        QString  info;
        QString  threat;
        QColor   bg_color;
    };

    // ── Pure helpers ──────────────────────────────────────────────────────────
    RowCache buildRowCache  (const PacketInfo& r)                        const;
    bool     matchRecord    (const PacketInfo& pkt,
                              const DisplayFilter& f)                      const;
    QString  computeProto   (const PacketInfo& r)                        const;
    QString  computeInfo    (const PacketInfo& r)                        const;
    QColor   computeRowColor(const PacketInfo& r)                        const;

    static bool evalOp (DisplayFilter::Op op, uint16_t lhs, uint16_t rhs);
    static bool applyOp(DisplayFilter::Op op, bool eq);

    // ── Data ──────────────────────────────────────────────────────────────────
    PacketRingBuffer&      ring_buf_;
    DisplayFilter          current_filter_;
    double                 base_timestamp_ = -1.0;

    std::deque<RowCache>   row_cache_;
    std::deque<uint64_t>   filtered_indices_;

    mutable std::mutex     mutex_;
};