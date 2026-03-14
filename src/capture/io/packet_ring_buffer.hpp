// src/capture/io/packet_ring_buffer.hpp
#pragma once
#include "../../core/packet_info.hpp"
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <algorithm>

class PacketRingBuffer {
public:
    explicit PacketRingBuffer(size_t max_packets     = 100'000,
                              size_t keep_raw_last_n = 10'000);

    // ── Write ─────────────────────────────────────────────────────────────────
    // index được gán tự động bên trong push()
    // caller KHÔNG cần set pkt.index trước
    void push(PacketInfo pkt);

    // ── Read ──────────────────────────────────────────────────────────────────
    std::vector<PacketInfo>     getRange  (size_t   from,
                                           size_t   to)    const;
    std::shared_ptr<PacketInfo> getByIndex(uint64_t index) const;

    // ── Zero-copy read với callback ───────────────────────────────────────────
    // Fn = void(const PacketInfo&)
    // Trả về false nếu index không còn trong buffer
    template<typename Fn>
    bool withRecord(uint64_t index, Fn&& fn) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const uint64_t total  = total_received_.load();
        if (index >= total) return false;
        const uint64_t oldest = (total > max_packets_)
                                ? total - max_packets_ : 0;
        if (index < oldest) return false;
        const size_t slot = index % max_packets_;
        if (buffer_[slot].index != index) return false;
        fn(buffer_[slot]);
        return true;
    }

    // ── Snapshot: lấy range [from, to) ───────────────────────────────────────
    // Clamp tự động về [oldest, total)
    std::vector<PacketInfo> getSnapshot(uint64_t from, uint64_t to) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<PacketInfo> result;
        const uint64_t total  = total_received_.load();
        const uint64_t oldest = (total > max_packets_)
                                ? total - max_packets_ : 0;
        const uint64_t start  = std::max(from,  oldest);
        const uint64_t end    = std::min(to,     total);
        if (start >= end) return result;
        result.reserve(end - start);
        for (uint64_t i = start; i < end; ++i) {
            const size_t slot = i % max_packets_;
            if (buffer_[slot].index == i)
                result.push_back(buffer_[slot]);
        }
        return result;
    }

    // ── Stats ─────────────────────────────────────────────────────────────────
    uint64_t totalReceived() const { return total_received_.load(); }
    size_t   size()          const;
    uint64_t oldestIndex()   const;
    uint64_t newestIndex()   const;

    // ── Maintenance ───────────────────────────────────────────────────────────
    void clear();

    // Giải phóng raw_data của toàn bộ packet trong buffer
    // Dùng khi cần giảm RAM, packet vẫn còn metadata
    void evictAllRawData();

    // ── Evict callback ────────────────────────────────────────────────────────
    // Gọi khi một slot bị overwrite (ring buffer đầy)
    using EvictCallback = std::function<void(uint64_t evicted_index)>;
    void setEvictCallback(EvictCallback cb) { evict_cb_ = std::move(cb); }

private:
    void evictOldRaw(uint64_t new_total);

    size_t                   max_packets_;
    size_t                   keep_raw_last_n_;
    mutable std::mutex       mutex_;
    std::vector<PacketInfo>  buffer_;
    std::atomic<uint64_t>    total_received_{0};
    EvictCallback            evict_cb_;
};
