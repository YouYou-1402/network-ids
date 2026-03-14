// src/core/packet_info.hpp
#pragma once
#include <vector>
#include <array>
#include <memory>
#include <string>
#include <cstdint>
#include <sys/time.h>

//  TCP Flag bitmasks  
namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

//   EtherType constants  
namespace EtherType {
    constexpr uint16_t IPv4 = 0x0800;
    constexpr uint16_t ARP  = 0x0806;
    constexpr uint16_t VLAN = 0x8100;
    constexpr uint16_t IPv6 = 0x86DD;
}

//   PacketInfo 
struct PacketInfo {

    //   Ring buffer metadata  
    uint64_t  index       = 0;       
    uint64_t  capture_seq = 0;      

    struct timeval timestamp {};     
    double    timestamp_d   = 0.0;  // = tv_sec + tv_usec/1e6

    //   Frame sizes     
    uint32_t  cap_len   = 0;         // bytes thực sự captured
    uint32_t  orig_len  = 0;         // bytes trên dây 

    //   Layer 2       
    uint16_t  eth_type  = 0;

    //   Layer 3       
    uint32_t  src_ip    = 0;
    uint32_t  dst_ip    = 0;
    std::array<uint8_t, 16> src_ip6 {};
    std::array<uint8_t, 16> dst_ip6 {};
    uint8_t   protocol  = 0;
    uint8_t   ttl       = 0;
    uint8_t   hop_limit = 0;         // IPv6

    //   Layer 4       
    uint16_t  src_port  = 0;
    uint16_t  dst_port  = 0;
    uint8_t   tcp_flags = 0;
    uint32_t  seq_num   = 0;
    uint32_t  ack_num   = 0;
    uint16_t  win_size  = 0;

    //   Payload       
    uint32_t  payload_len    = 0;
    uint32_t  payload_offset = 0;

    //   IDS result      

    std::string threat_type;
    std::string action;

    //   File offset (offline pcap)                
    int64_t   file_offset = -1;

    std::shared_ptr<std::vector<uint8_t>> raw_data;


    const uint8_t* payload() const {
        if (!raw_data || payload_len == 0
            || payload_offset >= raw_data->size())
            return nullptr;
        return raw_data->data() + payload_offset;
    }

    std::string flowKey() const;

    // TCP flag helpers
    bool hasSYN() const { return tcp_flags & TCPFlags::SYN; }
    bool hasACK() const { return tcp_flags & TCPFlags::ACK; }
    bool hasRST() const { return tcp_flags & TCPFlags::RST; }
    bool hasFIN() const { return tcp_flags & TCPFlags::FIN; }
    bool hasPSH() const { return tcp_flags & TCPFlags::PSH; }
    bool hasURG() const { return tcp_flags & TCPFlags::URG; }

    // EtherType helpers
    bool isIPv4() const { return eth_type == EtherType::IPv4; }
    bool isARP()  const { return eth_type == EtherType::ARP;  }
    bool isIPv6() const { return eth_type == EtherType::IPv6; }

    // Timestamp helpers
    double timestampSeconds() const { return timestamp_d; }
};
