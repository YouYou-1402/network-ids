// src/capture/io/pcap_reader.hpp
#pragma once
#include "packet_ring_buffer.hpp"
#include <string>
#include <functional>
#include <atomic>
#include <memory>
#include <vector>
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

    // ── Scan nhanh vào ring_buf (LIVE mode / compat) ──────────────────────────
    bool scanFile(const std::string&  filepath,
                  PacketRingBuffer&   ring_buf,
                  ProgressCallback    on_progress = nullptr,
                  std::atomic<bool>*  cancel_flag = nullptr);

    // ── Scan trực tiếp ra vector — OFFLINE mode, bỏ qua ring_buf overhead ─────
    // Trả về vector metadata (raw_data = nullptr), mmap giữ mở cho lazy-load
    // Nhanh hơn scanFile(ring_buf) vì không lock mutex từng packet
    bool scanFileDirect(const std::string&             filepath,
                        std::vector<PacketInfo>&        out_packets,
                        ProgressCallback                on_progress = nullptr,
                        std::atomic<bool>*              cancel_flag = nullptr);

    // ── Lazy load raw bytes ───────────────────────────────────────────────────
    bool loadRawBytes (PacketInfo&              record,
                       const std::string&       filepath);
    bool loadRawRange (std::vector<PacketInfo>& records,
                       const std::string&       filepath);

    const PcapFileStats& stats() const { return stats_; }

    void cancel() { if (cancel_flag_) *cancel_flag_ = true; }

private:
    uint64_t prescanPacketCount(const uint8_t* data,
                                size_t         file_size,
                                bool           swap_bytes) const;

    void parseHeaders(PacketInfo&    record,
                      const uint8_t* data,
                      uint32_t       len,
                      int            linktype);

    // ── Shared scan core — dùng bởi cả scanFile và scanFileDirect ────────────
    // on_packet: callback nhận từng PacketInfo đã parse (metadata only)
    bool scanCore(const std::string&                        filepath,
                  std::function<void(PacketInfo&&)>         on_packet,
                  ProgressCallback                          on_progress,
                  std::atomic<bool>*                        cancel_flag);

    PcapFileStats      stats_;
    std::atomic<bool>* cancel_flag_ = nullptr;

    int    mmap_fd_   = -1;
    void*  mmap_ptr_  = MAP_FAILED;
    size_t mmap_size_ = 0;

    void closeMmap();
};
