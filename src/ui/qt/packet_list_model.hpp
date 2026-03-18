// src/ui/qt/packet_list_model.hpp
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

    static constexpr int    MAX_DISPLAY_ROWS = 500'000;
    static constexpr size_t BATCH_FLUSH_SIZE = 5'000;

    explicit PacketListModel(PacketRingBuffer& ring_buf,
                              QObject*          parent = nullptr);

    int      rowCount   (const QModelIndex& parent = {}) const override;
    int      columnCount(const QModelIndex& parent = {}) const override;
    QVariant headerData (int section, Qt::Orientation, int role) const override;
    QVariant data       (const QModelIndex& index, int role)     const override;

    // ── Wireshark freeze/thaw ─────────────────────────────────────────────────
    // freeze(): tạm dừng mọi beginInsertRows/endInsertRows
    //           packet vẫn vào pending_rows_ bình thường
    //           keep_current: giữ lại QModelIndex đang chọn (dùng khi filter)
    // thaw() : flush toàn bộ pending_rows_ → 1 lần beginInsertRows duy nhất
    //           → Qt chỉ repaint 1 lần thay vì N lần
    // Trả về true nếu state thực sự thay đổi
    bool freeze(bool keep_current = false);
    bool thaw  (bool restore_selection = false);

    bool isFrozen() const { return frozen_; }

    // ── Append / flush ────────────────────────────────────────────────────────
    // appendRecords: gom vào pending_rows_
    //   - nếu frozen_  → KHÔNG flush, chờ thaw()
    //   - nếu !frozen_ → flush theo BATCH_FLUSH_SIZE (LIVE mode)
    void appendRecords(const std::vector<PacketInfo>& batch);
    void flushPending ();

    void applyFilter  (const DisplayFilter& filter);
    void clear        ();

    bool getRecord    (int row, PacketInfo& out) const;
    void updateRawData(int row,
                       std::shared_ptr<std::vector<uint8_t>> raw_data);

    // ── Wireshark overlay ─────────────────────────────────────────────────────
    // Wireshark dùng 2 overlay timer:
    //   near_overlay: repaint ~100ms sau insert (rows vừa thêm)
    //   far_overlay : repaint ~500ms sau insert (rows cũ cần recolor)
    // Ta đơn giản hóa: 1 dirty flag, PcapTab::timerEvent() check và repaint
    bool isDirty() const { return dirty_; }
    void clearDirty()    { dirty_ = false; }

    // Frozen QModelIndex để restore sau thaw
    QModelIndex frozenCurrentRow() const { return frozen_current_row_; }

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

    void insertBatch(std::vector<RowCache>& batch);

    PacketRingBuffer&    ring_buf_;
    std::deque<RowCache> row_cache_;
    std::deque<uint64_t> pkt_indices_;
    std::vector<RowCache> pending_rows_;

    DisplayFilter current_filter_;
    double        base_ts_ = -1.0;

    // ── Freeze state ──────────────────────────────────────────────────────────
    bool        frozen_             = false;
    bool        dirty_              = false;
    QModelIndex frozen_current_row_;
};
