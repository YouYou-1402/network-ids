// src/capture/protocol_decoder.hpp
#pragma once
#include "../pcap_io/packet_ring_buffer.hpp"
#include <pcap.h>
#include <cstdint>

class ProtocolDecoder {
public:
    // Decode 1 packet từ pcap → PacketRecord đã populate đầy đủ
    static PacketRecord decode(const struct pcap_pkthdr* header,
                               const uint8_t*            data);

private:
    static void decodeIPv4(const uint8_t* data, uint32_t len,
                           PacketRecord& rec);
    static void decodeTCP (const uint8_t* data, uint32_t len,
                           PacketRecord& rec);
    static void decodeUDP (const uint8_t* data, uint32_t len,
                           PacketRecord& rec);
    static void decodeICMP(const uint8_t* data, uint32_t len,
                           PacketRecord& rec);
};
