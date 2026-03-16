#pragma once
#include "filter_bar.hpp"
#include "../../capture/io/packet_ring_buffer.hpp"
#include "../../core/packet_info.hpp"

#include <QAbstractTableModel>
#include <QColor>
#include <QString>
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

    static constexpr int MAX_DISPLAY_ROWS = 500'000;

    explicit PacketListModel(PacketRingBuffer& ring_buf,
                              QObject*          parent = nullptr);

    int      rowCount   (const QModelIndex& parent = {}) const override;
    int      columnCount(const QModelIndex& parent = {}) const override;
    QVariant headerData (int section, Qt::Orientation, int role) const override;
    QVariant data       (const QModelIndex& index, int role)     const override;

    void appendRecords(const std::vector<PacketInfo>& batch);
    void applyFilter  (const DisplayFilter& filter);
    void clear        ();

    // Trả về metadata packet tại row
    // raw_data = nullptr — caller tự lazy-load nếu cần
    bool getRecord(int row, PacketInfo& out) const;

    // Cập nhật raw_data sau khi lazy-load (cache lại để click tiếp không đọc disk)
    void updateRawData(int row,
                       std::shared_ptr<std::vector<uint8_t>> raw_data);

private:
    // RowCache chỉ lưu metadata — KHÔNG giữ raw_data
    struct RowCache {
        uint64_t frame_no   = 0;
        uint64_t pkt_idx    = 0;   // ring_buf index (dùng cho applyFilter)
        uint32_t orig_len   = 0;
        QColor   bg_color;
        QString  time_str;
        QString  src;
        QString  dst;
        QString  proto;
        QString  info;
        QString  threat;

        // Metadata đầy đủ để getRecord() không cần đọc ring_buf
        // raw_data = nullptr (lazy-load khi click)
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

    PacketRingBuffer&    ring_buf_;
    std::deque<RowCache> row_cache_;
    std::deque<uint64_t> pkt_indices_;
    DisplayFilter        current_filter_;
    double               base_ts_ = -1.0;
};
