#pragma once
#include <vector>
#include <cstdint>
#include <sys/time.h>
#include <string> 

// TCP Flag bitmasks
namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

// Struct chứa thông tin một gói tin đã parse
struct PacketInfo {
    // Raw data
    std::vector<uint8_t> raw_data;
    struct timeval       timestamp;

    // Network layer (L3)
    uint32_t src_ip   = 0;
    uint32_t dst_ip   = 0;
    uint8_t  protocol = 0;   // IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1
    uint8_t  ttl      = 0;

    // Transport layer (L4)
    uint16_t src_port  = 0;
    uint16_t dst_port  = 0;
    uint8_t  tcp_flags = 0;  // Bitmask từ TCPFlags namespace
    uint32_t seq_num   = 0;
    uint32_t ack_num   = 0;
    uint16_t win_size  = 0;  // TCP window size

    // Payload
    uint32_t pkt_len      = 0;
    uint32_t payload_len  = 0;
    uint32_t payload_offset = 0; // Offset vào raw_data

    // Helper: lấy pointer đến payload
    const uint8_t* payload() const {
        if (payload_len == 0) return nullptr;
        return raw_data.data() + payload_offset;
    }

    // Helper: tạo flow key từ 5-tuple
    // Format: "srcIP:srcPort-dstIP:dstPort-proto"
    std::string flowKey() const;

    // Helper: kiểm tra flag
    bool hasSYN() const { return tcp_flags & TCPFlags::SYN; }
    bool hasACK() const { return tcp_flags & TCPFlags::ACK; }
    bool hasRST() const { return tcp_flags & TCPFlags::RST; }
    bool hasFIN() const { return tcp_flags & TCPFlags::FIN; }

    // Helper: timestamp dạng double (seconds)
    double timestampSeconds() const {
        return timestamp.tv_sec + timestamp.tv_usec / 1e6;
    }
};
