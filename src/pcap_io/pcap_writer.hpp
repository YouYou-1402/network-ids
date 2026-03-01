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
    bool writePacket(const uint8_t*            data,
                     uint32_t                  cap_len,
                     uint32_t                  orig_len,
                     const struct timeval&     ts);

    // Overload tiện lợi từ PacketRecord
    bool writePacket(const PacketRecord& record);

    void close();
    bool isOpen()  const { return dumper_ != nullptr; }

    uint64_t packetsWritten() const { return packets_written_; }
    uint64_t bytesWritten()   const { return bytes_written_;   }

    std::string filepath() const { return filepath_; }

private:
    pcap_t*           handle_   = nullptr;
    pcap_dumper_t*    dumper_   = nullptr;
    std::mutex        mutex_;
    std::string       filepath_;
    std::atomic<uint64_t> packets_written_{0};
    std::atomic<uint64_t> bytes_written_  {0};
};
