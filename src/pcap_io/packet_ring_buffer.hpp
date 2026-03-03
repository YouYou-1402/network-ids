#pragma once
#include "../common/packet_info.hpp"
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>

// ─── PacketRecord ─────────────────────────────────────────────────────────────
struct PacketRecord {
    uint64_t  index       = 0;
    double    timestamp   = 0.0;
    uint32_t  cap_len     = 0;
    uint32_t  orig_len    = 0;

    uint32_t  src_ip      = 0;
    uint32_t  dst_ip      = 0;
    uint16_t  src_port    = 0;
    uint16_t  dst_port    = 0;
    uint8_t   protocol    = 0;
    uint8_t   tcp_flags   = 0;
    uint16_t  eth_type    = 0;

    uint32_t  payload_len = 0;

    std::string threat_type;
    std::string action;

    std::shared_ptr<std::vector<uint8_t>> raw_data;
    int64_t   file_offset = -1;
};

// ─── PacketRingBuffer ─────────────────────────────────────────────────────────
class PacketRingBuffer {
public:
    explicit PacketRingBuffer(size_t max_packets     = 100000,
                               size_t keep_raw_last_n = 1000);

    void     push(PacketRecord record);

    // Lấy range [from, to) — copy metadata, không copy raw_data
    std::vector<PacketRecord> getRange(size_t from, size_t to) const;

    // Lấy shared_ptr<PacketRecord> — dùng cho lazy raw-byte load
    std::shared_ptr<PacketRecord> getByIndex(uint64_t index) const;

    // ✅ MỚI: callback-based access — không alloc, không copy
    // Trả về false nếu index đã bị evict
    // f() được gọi TRONG lock — chỉ dùng cho read nhanh
    template<typename Fn>
    bool withRecord(uint64_t index, Fn&& f) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const uint64_t total  = total_received_.load();
        if (index >= total) return false;
        const uint64_t oldest = (total > max_packets_)
                                ? total - max_packets_ : 0;
        if (index < oldest) return false;
        const size_t slot = index % max_packets_;
        if (buffer_[slot].index != index) return false;
        f(buffer_[slot]);
        return true;
    }

    uint64_t totalReceived() const { return total_received_.load(); }
    size_t   size()          const;
    uint64_t oldestIndex()   const;
    uint64_t newestIndex()   const;
    void     clear();
    void     evictAllRawData();

    using EvictCallback = std::function<void(uint64_t evicted_index)>;
    void setEvictCallback(EvictCallback cb) { evict_cb_ = std::move(cb); }

private:
    std::vector<PacketRecord>   buffer_;
    size_t                      head_     = 0;
    std::atomic<uint64_t>       total_received_{0};
    size_t                      max_packets_;
    size_t                      keep_raw_last_n_;
    mutable std::mutex          mutex_;
    EvictCallback               evict_cb_;
};
