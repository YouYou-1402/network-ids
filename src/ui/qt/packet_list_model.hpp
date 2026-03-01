#pragma once
#include <QAbstractTableModel>
#include <QColor>
#include <deque>
#include <vector>
#include <mutex>
#include <memory>
#include "../../pcap_io/packet_ring_buffer.hpp"
#include "filter_bar.hpp"

class PacketListModel : public QAbstractTableModel {
    Q_OBJECT

public:
    // ── Columns ───────────────────────────────────────────────────────────────
    enum Column {
        COL_NO = 0, COL_TIME, COL_SRC_IP, COL_DST_IP,
        COL_PROTO, COL_LEN, COL_INFO, COL_THREAT,
        COL_COUNT
    };

    // ── Wireshark-style limits ─────────────────────────────────────────────────
    static constexpr int MAX_DISPLAY_ROWS = 200'000; // tối đa rows trong model
    static constexpr int SCROLL_CHUNK     = 1'000;   // batch insert tối đa/lần

    explicit PacketListModel(PacketRingBuffer& ring_buf,
                              QObject*          parent = nullptr);

    // QAbstractTableModel interface
    int      rowCount   (const QModelIndex& parent = {}) const override;
    int      columnCount(const QModelIndex& parent = {}) const override;
    QVariant data       (const QModelIndex& index,
                         int role = Qt::DisplayRole)     const override;
    QVariant headerData (int section, Qt::Orientation,
                         int role = Qt::DisplayRole)     const override;

    // ── Live capture API ──────────────────────────────────────────────────────
    void appendRecords(const std::vector<PacketRecord>& batch);

    // ── Filter / clear ────────────────────────────────────────────────────────
    void applyFilter(const DisplayFilter& filter);
    void clear();

    // ── Random access ─────────────────────────────────────────────────────────
    std::shared_ptr<PacketRecord> recordAt(int row) const;

private:
    QVariant    rowColor      (const PacketRecord& r) const;
    QString     protocolName  (const PacketRecord& r) const;
    QString     buildInfo     (const PacketRecord& r) const;
    bool        matchFilter   (uint64_t idx,
                               const DisplayFilter& f) const;

    PacketRingBuffer& ring_buf_;

    // ── Core: deque thay vector — O(1) pop_front khi evict ───────────────────
    // Chỉ lưu index (8 bytes/packet), không copy PacketRecord
    mutable std::mutex    mutex_;
    std::deque<uint64_t>  filtered_indices_;   // ← deque, không phải vector

    DisplayFilter         current_filter_;
    double                base_timestamp_ = -1.0; // relative time anchor
};
