// src/capture/io/packet_ring_buffer.hpp
#pragma once
#include "../../core/packet_info.hpp"
#include <vector>
#include <mutex>
#include <functional>
#include <optional>
#include <cstdint>
#include <algorithm>

// ─── PacketRingBuffer ─────────────────────────────────────────────────────────
//
//  Thread-safety model:
//    - 1 writer  (capture thread) : push()
//    - 1+ reader (Qt main thread) : pollNew(), pollRange(), withRecord()
//    - Tất cả operations đều giữ mutex_ → safe, đơn giản, không race
//
//  Memory model:
//    - buffer_ giữ tối đa max_packets_ slot
//    - raw_data chỉ tồn tại cho keep_raw_last_n_ packet gần nhất
//    - Packet cũ hơn vẫn còn metadata nhưng raw_data = nullptr
//
//  Index model:
//    - write_seq_  : số packet đã push (tăng dần, không reset)
//    - oldest_seq_ : index nhỏ nhất còn valid trong buffer
//    - slot        : write_seq_ % max_packets_
//
//  push() trả về index đã gán cho packet
// ─────────────────────────────────────────────────────────────────────────────
class PacketRingBuffer {
public:
    explicit PacketRingBuffer(size_t max_packets     = 200'000,
                               size_t keep_raw_last_n = 20'000);

    // ── Writer API (capture thread) ───────────────────────────────────────────
    // Trả về index đã gán cho pkt
    uint64_t push(PacketInfo pkt);

    // ── Reader API (Qt main thread) ───────────────────────────────────────────

    // Poll tất cả packet mới kể từ last_seq
    // last_seq được cập nhật tự động → gọi lại sẽ không trùng
    std::vector<PacketInfo> pollNew(uint64_t& last_seq) const;

    // Poll đúng `count` packet bắt đầu từ `from`
    // KHÔNG thay đổi bất kỳ state nào — caller tự quản lý con trỏ
    // Trả về số lượng thực tế lấy được (có thể < count nếu buffer chưa đủ)
    std::vector<PacketInfo> pollRange(uint64_t from, uint64_t count) const;

    // Zero-copy read — fn(const PacketInfo&) được gọi trong lock
    // Trả về false nếu index không còn trong buffer
    template<typename Fn>
    bool withRecord(uint64_t index, Fn&& fn) const {
        std::lock_guard<std::mutex> lk(mutex_);
        if (!isValidLocked(index)) return false;
        fn(buffer_[index % max_packets_]);
        return true;
    }

    template<typename Fn>
    bool updateRecord(uint64_t index, Fn&& fn) {
        std::lock_guard<std::mutex> lk(mutex_);
        if (!isValidLocked(index)) return false;
        fn(buffer_[index % max_packets_]);
        return true;
    }

    // Copy 1 packet theo index — dùng khi cần giữ lâu (detail view)
    std::optional<PacketInfo> getByIndex(uint64_t index) const;

    // ── Stats ─────────────────────────────────────────────────────────────────
    uint64_t totalPushed() const;
    uint64_t oldestIndex() const;
    uint64_t newestIndex() const;
    size_t   capacity()    const { return max_packets_; }

    // ── Maintenance ───────────────────────────────────────────────────────────
    void clear();
    void evictAllRawData();

    // Callback khi slot bị overwrite (ring đầy)
    using EvictCb = std::function<void(uint64_t evicted_index)>;
    void setEvictCallback(EvictCb cb) { evict_cb_ = std::move(cb); }

private:
    bool isValidLocked(uint64_t index) const {
        if (index >= write_seq_)  return false;
        if (index < oldest_seq_)  return false;
        return buffer_[index % max_packets_].index == index;
    }

    size_t                  max_packets_;
    size_t                  keep_raw_last_n_;

    mutable std::mutex      mutex_;
    std::vector<PacketInfo> buffer_;

    uint64_t                write_seq_  = 0;
    uint64_t                oldest_seq_ = 0;

    EvictCb                 evict_cb_;
};
