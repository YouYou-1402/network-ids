// src/ui/qt/packet_list_model.hpp
#pragma once
#include "filter_bar.hpp"
#include "../../capture/io/packet_ring_buffer.hpp"
#include "../../core/packet_info.hpp"

#include <QAbstractTableModel>
#include <QColor>
#include <QString>
#include <QTimer>
#include <deque>
#include <vector>

class PacketListModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column {
        COL_NO = 0, COL_TIME, COL_SRC_IP, COL_DST_IP,
        COL_PROTO, COL_LEN, COL_INFO, COL_THREAT,
        COL_COUNT
    };

    static constexpr int    MAX_DISPLAY_ROWS  = 500'000;
    // Số rows tối đa gom vào 1 beginInsertRows/endInsertRows
    // Lớn hơn → ít Qt notify hơn → nhanh hơn khi load file lớn
    static constexpr size_t BATCH_FLUSH_SIZE  = 5'000;

    explicit PacketListModel(PacketRingBuffer& ring_buf,
                              QObject*          parent = nullptr);

    int      rowCount   (const QModelIndex& parent = {}) const override;
    int      columnCount(const QModelIndex& parent = {}) const override;
    QVariant headerData (int section, Qt::Orientation, int role) const override;
    QVariant data       (const QModelIndex& index, int role)     const override;

    // Thêm batch — gom vào pending_rows_, flush theo BATCH_FLUSH_SIZE
    void appendRecords(const std::vector<PacketInfo>& batch);

    // Flush toàn bộ pending_rows_ vào row_cache_ ngay lập tức
    // Gọi sau khi scanFileDirect() hoàn thành để hiển thị ngay
    void flushPending();

    void applyFilter  (const DisplayFilter& filter);
    void clear        ();

    bool getRecord    (int row, PacketInfo& out) const;
    void updateRawData(int row,
                       std::shared_ptr<std::vector<uint8_t>> raw_data);

private:
    struct RowCache {
        uint64_t frame_no   = 0;
        uint64_t pkt_idx    = 0;
        uint32_t orig_len   = 0;
        QColor   bg_color;
        QString  time_str;
        QString  src;
        QString  dst;
        QString  proto;
        QString  info;
        QString  threat;
        PacketInfo meta;
    };

    RowCache buildRowCache  (const PacketInfo& pkt) const;
    bool     matchRecord    (const PacketInfo& pkt,
                              const DisplayFilter& f) const;
    QString  computeProto   (const PacketInfo& pkt) const;
    QString  computeInfo    (const PacketInfo& pkt) const;
    QColor   computeRowColor(const PacketInfo& pkt) const;

    static QString ipv4Str(uint32_t ip_net);
    static QString ipv6Str(const std::array<uint8_t, 16>& ip6);
    static QString addrStr(const PacketInfo& pkt, bool is_src);

    static bool evalOp (DisplayFilter::Op op, uint16_t lhs, uint16_t rhs);
    static bool applyOp(DisplayFilter::Op op, bool eq);

    // Gom rows chưa flush — tránh beginInsertRows per-packet
    void insertBatch(std::vector<RowCache>& batch);

    PacketRingBuffer&    ring_buf_;
    std::deque<RowCache> row_cache_;
    std::deque<uint64_t> pkt_indices_;

    // pending_rows_: buffer gom trước khi insertBatch()
    std::vector<RowCache> pending_rows_;

    DisplayFilter        current_filter_;
    double               base_ts_ = -1.0;
};
