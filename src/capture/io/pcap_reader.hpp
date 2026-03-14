// src/capture/io/pcap_reader.hpp
#pragma once
#include "packet_ring_buffer.hpp"
#include <string>
#include <functional>
#include <atomic>
#include <memory>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

// ─── PcapFileStats ────────────────────────────────────────────────────────────
struct PcapFileStats {
    std::string filepath;
    uint64_t    total_packets = 0;
    uint64_t    total_bytes   = 0;
    double      first_ts      = 0.0;
    double      last_ts       = 0.0;
    double      duration_sec  = 0.0;
    uint32_t    snaplen       = 0;
    int         linktype      = 0;
    std::string linktype_name;
};

using ProgressCallback = std::function<void(uint64_t loaded,
                                             uint64_t total,
                                             double   percent)>;

// ─── PcapReader ───────────────────────────────────────────────────────────────
class PcapReader {
public:
    PcapReader()  = default;
    ~PcapReader();

    // ── Scan nhanh (chỉ metadata, không load raw bytes) ───────────────────────
    bool scanFile(const std::string&  filepath,
                  PacketRingBuffer&   ring_buf,
                  ProgressCallback    on_progress = nullptr,
                  std::atomic<bool>*  cancel_flag = nullptr);

    // ── Lazy load raw bytes cho một packet ────────────────────────────────────
    // Dùng mmap đang mở nếu cùng file, fallback fread nếu khác
    bool loadRawBytes(PacketInfo&        record,
                      const std::string& filepath);

    // ── Lazy load raw bytes cho một range packets ─────────────────────────────
    // Dùng khi user scroll đến vùng cần xem hex dump
    bool loadRawRange(std::vector<PacketInfo>& records,
                      const std::string&       filepath);

    // Lấy stats (gọi sau scanFile)
    const PcapFileStats& stats() const { return stats_; }

    // Hủy scan đang chạy
    void cancel() { if (cancel_flag_) *cancel_flag_ = true; }

private:
    // Pre-scan đếm tổng số packets (chỉ đọc headers, O(n) nhưng rất nhanh)
    uint64_t prescanPacketCount(const uint8_t* data,
                                size_t         file_size,
                                bool           swap_bytes) const;

    // Parse L3/L4 headers từ raw bytes (IPv4 + IPv6)
    void parseHeaders(PacketInfo&    record,
                      const uint8_t* data,
                      uint32_t       len,
                      int            linktype);

    PcapFileStats      stats_;
    std::atomic<bool>* cancel_flag_ = nullptr;

    // mmap state — giữ mở để lazy-load raw bytes
    int    mmap_fd_   = -1;
    void*  mmap_ptr_  = MAP_FAILED;
    size_t mmap_size_ = 0;

    void closeMmap();
};
