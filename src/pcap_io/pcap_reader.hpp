#pragma once
#include "packet_ring_buffer.hpp"
#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <memory>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

// Thống kê file pcap
struct PcapFileStats {
    std::string filepath;
    uint64_t    total_packets  = 0;
    uint64_t    total_bytes    = 0;
    double      first_ts       = 0.0;
    double      last_ts        = 0.0;
    double      duration_sec   = 0.0;
    uint32_t    snaplen        = 0;
    int         linktype       = 0;
    std::string linktype_name;
};

using ProgressCallback = std::function<void(uint64_t loaded,
                                             uint64_t total,
                                             double   percent)>;

class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader();

    // ── Scan nhanh file (chỉ đọc headers, không load raw bytes) ──────────────
    // Trả về stats + danh sách PacketRecord (không có raw_data)
    // Dùng mmap để tránh copy vào userspace
    bool scanFile(const std::string&         filepath,
                  PacketRingBuffer&           ring_buf,
                  ProgressCallback            on_progress = nullptr,
                  std::atomic<bool>*          cancel_flag = nullptr);

    // ── Load raw bytes cho một packet cụ thể (lazy load) ─────────────────────
    // Đọc từ file theo file_offset đã lưu trong PacketRecord
    bool loadRawBytes(PacketRecord&       record,
                      const std::string&  filepath);

    // ── Load một range packets với raw bytes ──────────────────────────────────
    // Dùng khi user scroll đến vùng cần xem hex dump
    bool loadRawRange(std::vector<PacketRecord>& records,
                      const std::string&          filepath);

    // Lấy stats của file (gọi sau scanFile)
    const PcapFileStats& stats() const { return stats_; }

    // Hủy scan đang chạy
    void cancel() { if (cancel_flag_) *cancel_flag_ = true; }

private:
    // Parse packet header tại offset trong mmap
    bool parsePacketAt(const uint8_t*  mmap_data,
                       size_t          file_size,
                       size_t          offset,
                       bool            swap_bytes,
                       PacketRecord&   out_record);

    // Parse L3/L4 headers từ raw bytes
    void parseHeaders(PacketRecord&      record,
                      const uint8_t*     data,
                      uint32_t           len,
                      int                linktype);

    PcapFileStats         stats_;
    std::atomic<bool>*    cancel_flag_ = nullptr;

    // mmap state
    int       mmap_fd_   = -1;
    void*     mmap_ptr_  = MAP_FAILED;
    size_t    mmap_size_ = 0;

    void closeMmap();
};
