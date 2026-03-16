// src/capture/io/pcap_writer.hpp
#pragma once
#include "../../core/packet_info.hpp"
#include "packet_ring_buffer.hpp"
#include <string>
#include <mutex>
#include <pcap.h>

// Ghi packets ra file pcap trong khi capture
// Thread-safe — nhiều worker threads có thể gọi đồng thời
//
// FIX: writePacket() trả về int64_t data_offset thay vì bool
//      data_offset = vị trí DATA trong file (sau PcapPacketHeader 16 bytes)
//      → đây là giá trị đúng để gán vào pkt.file_offset cho lazy-load
class PcapWriter {
public:
    PcapWriter()  = default;
    ~PcapWriter();

    // Mở file để ghi
    bool open(const std::string& filepath,
              int                snaplen  = 65535,
              int                linktype = DLT_EN10MB);

    // Ghi một packet — trả về data_offset (vị trí DATA sau PcapPacketHeader)
    // Trả về -1 nếu thất bại
    // data_offset này phải được gán vào pkt.file_offset để lazy-load đúng
    int64_t writePacket(const uint8_t*        data,
                        uint32_t              cap_len,
                        uint32_t              orig_len,
                        const struct timeval& ts);

    // Overload tiện lợi từ PacketInfo
    int64_t writePacket(const PacketInfo& record);

    // Flush buffer xuống disk — gọi trước khi lazy-load đọc file
    void flush();

    void close();

    bool isOpen() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return dumper_ != nullptr;
    }

    // Trả về byte offset hiện tại (sau packet cuối cùng đã ghi)
    // Dùng để debug / stats — KHÔNG dùng làm file_offset cho lazy-load
    int64_t currentOffset() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<int64_t>(PCAP_GLOBAL_HEADER_SIZE + bytes_written_);
    }

    uint64_t packetsWritten() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return packets_written_;
    }
    uint64_t bytesWritten() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return bytes_written_;
    }

    std::string filepath() const { return filepath_; }

private:
    static constexpr uint64_t PCAP_GLOBAL_HEADER_SIZE = 24;
    static constexpr uint64_t PCAP_PACKET_HEADER_SIZE = 16;

    pcap_t*        handle_  = nullptr;
    pcap_dumper_t* dumper_  = nullptr;

    mutable std::mutex mutex_;

    std::string filepath_;
    uint64_t    packets_written_ = 0;
    uint64_t    bytes_written_   = 0;
};
