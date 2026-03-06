// src/pcap_io/packet_ring_buffer.hpp
#pragma once
#include "../common/packet_info.hpp"
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

// ─── PacketRecord ─────────────────────────────────────────────────────────────
struct PacketRecord {
    // ── Index & timing ────────────────────────────────────────────────────────
    uint64_t  index     = 0;
    double    timestamp = 0.0;

    // ── Frame sizes ───────────────────────────────────────────────────────────
    uint32_t  cap_len   = 0;
    uint32_t  orig_len  = 0;

    // ── Layer 2 ───────────────────────────────────────────────────────────────
    uint16_t  eth_type  = 0;   // ✅ 0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6

    // ── Layer 3 ───────────────────────────────────────────────────────────────
    uint32_t  src_ip    = 0;   // network byte order
    uint32_t  dst_ip    = 0;   // network byte order
    std::array<uint8_t, 16> src_ip6{};   // all-zero = không có
    std::array<uint8_t, 16> dst_ip6{};   // all-zero = không có
    uint8_t   protocol  = 0;
    uint8_t   ttl       = 0;

    // ── Layer 4 ───────────────────────────────────────────────────────────────
    uint16_t  src_port  = 0;
    uint16_t  dst_port  = 0;
    uint8_t   tcp_flags = 0;
    uint32_t  seq_num   = 0;
    uint32_t  ack_num   = 0;
    uint16_t  win_size  = 0;

    // ── Payload ───────────────────────────────────────────────────────────────
    uint32_t  payload_len    = 0;
    uint32_t  payload_offset = 0;

    // ── IDS result ────────────────────────────────────────────────────────────
    std::string threat_type;
    std::string action;

    // ── Raw bytes (evictable) ─────────────────────────────────────────────────
    std::shared_ptr<std::vector<uint8_t>> raw_data;

    // ── File offset (offline pcap) ────────────────────────────────────────────
    int64_t file_offset = -1;
};

// ─── PacketRingBuffer ─────────────────────────────────────────────────────────
class PacketRingBuffer {
public:
    explicit PacketRingBuffer(size_t max_packets     = 100'000,
                               size_t keep_raw_last_n = 1'000);

    // ── Write ─────────────────────────────────────────────────────────────────
    void push(PacketRecord record);

    // ── Read ──────────────────────────────────────────────────────────────────
    std::vector<PacketRecord>     getRange  (size_t   from,
                                             size_t   to)    const;
    std::shared_ptr<PacketRecord> getByIndex(uint64_t index) const;

    // ── Lock-free read với callback (tránh copy) ──────────────────────────────
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

    // ── Stats ─────────────────────────────────────────────────────────────────
    uint64_t totalReceived() const { return total_received_.load(); }
    size_t   size()          const;
    uint64_t oldestIndex()   const;
    uint64_t newestIndex()   const;

    // ── Maintenance ───────────────────────────────────────────────────────────
    void clear();
    void evictAllRawData();

    // ── Evict callback ────────────────────────────────────────────────────────
    using EvictCallback = std::function<void(uint64_t evicted_index)>;
    void setEvictCallback(EvictCallback cb) { evict_cb_ = std::move(cb); }

private:
    size_t                    max_packets_;
    size_t                    keep_raw_last_n_;
    mutable std::mutex        mutex_;
    std::vector<PacketRecord> buffer_;
    std::atomic<uint64_t>     total_received_{0};
    uint64_t                  head_{0};
    EvictCallback             evict_cb_;
};
