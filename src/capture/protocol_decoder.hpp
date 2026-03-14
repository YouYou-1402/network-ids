// src/capture/protocol_decoder.hpp
#pragma once
#include "io/packet_ring_buffer.hpp"
#include <pcap.h>
#include <cstdint>

// FIX BUG 4: named constants thay cho magic numbers 0xFE / 0xFF
namespace SentinelProto {
    inline constexpr uint8_t ARP  = 0xFD;   // 0xFD không dùng bởi IANA
    inline constexpr uint8_t IPV6 = 0xFC;   // 0xFC không dùng bởi IANA
}

class ProtocolDecoder {
public:
    // Decode một packet từ libpcap callback
    // payload_offset trong kết quả tính từ đầu frame (= đầu raw_data)
    static PacketInfo decode(const struct pcap_pkthdr* header,
                             const uint8_t*            data);

private:
    // FIX BUG 3: truyền thêm frame_base để tính payload_offset chính xác
    static void decodeIPv4(const uint8_t* data,
                           uint32_t       len,
                           uint32_t       l3_offset,   // offset của data so với frame
                           PacketInfo&    pkt);

    static void decodeTCP (const uint8_t* data,
                           uint32_t       len,
                           uint32_t       l4_offset,   // offset của data so với frame
                           PacketInfo&    pkt);

    static void decodeUDP (const uint8_t* data,
                           uint32_t       len,
                           uint32_t       l4_offset,
                           PacketInfo&    pkt);

    static void decodeICMP(const uint8_t* data,
                           uint32_t       len,
                           uint32_t       l4_offset,
                           PacketInfo&    pkt);
};
