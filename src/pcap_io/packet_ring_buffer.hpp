#pragma once
#include "../common/packet_info.hpp"
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>

// ─── PacketRecord: metadata nhẹ, không giữ raw bytes ─────────────────────────
// Khi cần raw bytes → đọc lại từ file qua offset
struct PacketRecord {
    uint64_t  index       = 0;      // Số thứ tự toàn cục
    double    timestamp   = 0.0;    // Unix time (seconds)
    uint32_t  cap_len     = 0;      // Bytes thực sự capture
    uint32_t  orig_len    = 0;      // Bytes gốc trên wire

    // Parsed fields (nhẹ — không cần raw bytes)
    uint32_t  src_ip      = 0;
    uint32_t  dst_ip      = 0;
    uint16_t  src_port    = 0;
    uint16_t  dst_port    = 0;
    uint8_t   protocol    = 0;
    uint8_t   tcp_flags   = 0;
    uint16_t  eth_type    = 0;

    // Payload info
    uint32_t  payload_len = 0;

    // Threat info (từ IPS engine)
    std::string threat_type;   // "" = normal
    std::string action;        // "PASS" / "DROP" / "ALERT"

    // Pointer đến raw bytes (nullptr nếu đã evict)
    // Dùng shared_ptr để nhiều widget cùng giữ
    std::shared_ptr<std::vector<uint8_t>> raw_data;

    // File offset (dùng khi lazy-load từ pcap file)
    int64_t   file_offset = -1;  // -1 = live capture (không có file)
};

// ─── Ring Buffer cố định — tránh tràn RAM ────────────────────────────────────
// Khi đầy → overwrite record cũ nhất
// Giải phóng raw_data của record bị overwrite
class PacketRingBuffer {
public:
    // max_packets: số packet tối đa giữ trong RAM
    // keep_raw_last_n: chỉ giữ raw bytes của N packet gần nhất
    explicit PacketRingBuffer(size_t max_packets    = 100000,
                               size_t keep_raw_last_n = 1000);

    // Thêm packet mới — thread-safe
    void push(PacketRecord record);

    // Lấy snapshot để hiển thị (copy metadata, không copy raw)
    // Trả về vector các records từ index [from, to)
    std::vector<PacketRecord> getRange(size_t from, size_t to) const;

    // Lấy một record theo index tuyệt đối
    // Trả về nullptr nếu đã bị overwrite
    std::shared_ptr<PacketRecord> getByIndex(uint64_t index) const;

    // Tổng số packets đã nhận (kể cả đã overwrite)
    uint64_t totalReceived() const { return total_received_; }

    // Số packets hiện đang trong buffer
    size_t   size()          const;

    // Index của packet cũ nhất còn trong buffer
    uint64_t oldestIndex()   const;

    // Index của packet mới nhất
    uint64_t newestIndex()   const;

    // Xóa toàn bộ buffer
    void clear();

    // Giải phóng raw bytes của tất cả records (tiết kiệm RAM)
    void evictAllRawData();

    // Callback khi packet bị overwrite (để UI cập nhật)
    using EvictCallback = std::function<void(uint64_t evicted_index)>;
    void setEvictCallback(EvictCallback cb) { evict_cb_ = std::move(cb); }

private:
    void evictRawIfNeeded();

    std::vector<PacketRecord>   buffer_;
    size_t                      head_     = 0;   // Vị trí write tiếp theo
    std::atomic<uint64_t>       total_received_{0};
    size_t                      max_packets_;
    size_t                      keep_raw_last_n_;
    mutable std::mutex          mutex_;
    EvictCallback               evict_cb_;
};
