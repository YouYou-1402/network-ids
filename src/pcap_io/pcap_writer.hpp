#pragma once
#include "../common/packet_info.hpp"
#include "packet_ring_buffer.hpp"
#include <string>
#include <mutex>
#include <pcap.h>
#include <atomic>

// Ghi packets ra file pcap trong khi capture
// Thread-safe — nhiều worker threads có thể gọi đồng thời
class PcapWriter {
public:
    PcapWriter() = default;
    ~PcapWriter();

    // Mở file để ghi
    // snaplen: max bytes per packet (65535 = full)
    bool open(const std::string& filepath,
              int                snaplen   = 65535,
              int                linktype  = DLT_EN10MB);

    // Ghi một packet (thread-safe)
    bool writePacket(const uint8_t*        data,
                     uint32_t              cap_len,
                     uint32_t              orig_len,
                     const struct timeval& ts);

    // Overload tiện lợi từ PacketRecord
    bool writePacket(const PacketRecord& record);

    void close();
    bool isOpen() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return dumper_ != nullptr;
    }

    // Trả về byte offset của packet SẮP ghi (gọi TRƯỚC writePacket)
    // pcap format: [24 bytes global header] + N * [16 bytes pkt header + cap_len bytes data]
    int64_t currentOffset() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<int64_t>(PCAP_GLOBAL_HEADER_SIZE + bytes_written_);
    }

    uint64_t packetsWritten() const { return packets_written_; }
    uint64_t bytesWritten()   const { return bytes_written_;   }

    std::string filepath() const { return filepath_; }

private:
    static constexpr uint64_t PCAP_GLOBAL_HEADER_SIZE = 24; // magic+ver+zone+sig+snap+link
    static constexpr uint64_t PCAP_PACKET_HEADER_SIZE = 16; // ts_sec+ts_usec+caplen+len

    pcap_t*        handle_  = nullptr;
    pcap_dumper_t* dumper_  = nullptr;
    mutable std::mutex     mutex_;
    std::string    filepath_;

    std::atomic<uint64_t> packets_written_{0};
    std::atomic<uint64_t> bytes_written_  {0}; // tổng bytes đã ghi (KHÔNG kể global header)
                                                // mỗi packet += PCAP_PACKET_HEADER_SIZE + cap_len
};
