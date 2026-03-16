#pragma once
#include "../../core/packet_info.hpp"
#include <vector>
#include <mutex>
#include <functional>
#include <optional>
#include <cstdint>

// ─── PacketRingBuffer ─────────────────────────────────────────────────────────
//
//  Sau refactor: ring_buf CHỈ phục vụ Detection/ML
//  → size nhỏ (~10k), không cần keep_raw_last_n
//  → raw_data trong mỗi slot: detection dùng xong thì drop
//  → UI KHÔNG đọc raw_data từ đây nữa (lazy-load từ disk)
//
//  PacketListModel vẫn giữ tham chiếu ring_buf_ nhưng chỉ dùng
//  pollRange() để lấy metadata khi applyFilter()
// ─────────────────────────────────────────────────────────────────────────────
class PacketRingBuffer {
public:
    explicit PacketRingBuffer(size_t max_packets = 1000'000);

    // ── Writer (capture thread) ───────────────────────────────────────────────
    uint64_t push(PacketInfo pkt);

    // ── Reader ────────────────────────────────────────────────────────────────
    std::vector<PacketInfo> pollNew  (uint64_t& last_seq)              const;
    std::vector<PacketInfo> pollRange(uint64_t from, uint64_t count)   const;

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

    std::optional<PacketInfo> getByIndex(uint64_t index) const;

    uint64_t totalPushed() const;
    uint64_t oldestIndex() const;
    uint64_t newestIndex() const;
    size_t   capacity()    const { return max_packets_; }

    void clear();

    using EvictCb = std::function<void(uint64_t)>;
    void setEvictCallback(EvictCb cb) { evict_cb_ = std::move(cb); }

private:
    bool isValidLocked(uint64_t index) const {
        if (index >= write_seq_)  return false;
        if (index < oldest_seq_)  return false;
        return buffer_[index % max_packets_].index == index;
    }

    size_t                  max_packets_;
    mutable std::mutex      mutex_;
    std::vector<PacketInfo> buffer_;
    uint64_t                write_seq_  = 0;
    uint64_t                oldest_seq_ = 0;
    EvictCb                 evict_cb_;
};
