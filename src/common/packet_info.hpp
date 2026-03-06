// src/common/packet_info.hpp
#pragma once
#include <vector>
#include <array>
#include <cstdint>
#include <sys/time.h>
#include <string>

// ─── TCP Flag bitmasks ────────────────────────────────────────────────────────
namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

// ─── EtherType constants ──────────────────────────────────────────────────────
namespace EtherType {
    constexpr uint16_t IPv4 = 0x0800;
    constexpr uint16_t ARP  = 0x0806;
    constexpr uint16_t VLAN = 0x8100;
    constexpr uint16_t IPv6 = 0x86DD;
}

// ─── PacketInfo ───────────────────────────────────────────────────────────────
struct PacketInfo {
    // ── Raw data ──────────────────────────────────────────────────────────────
    std::vector<uint8_t> raw_data;
    struct timeval       timestamp {};

    // ── Link layer (L2) ───────────────────────────────────────────────────────
    uint16_t eth_type = 0;   // 0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6

    // ── Network layer (L3) ────────────────────────────────────────────────────
    uint32_t src_ip   = 0;   // network byte order
    uint32_t dst_ip   = 0;   // network byte order
    uint8_t  protocol = 0;   // IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1
    uint8_t  ttl      = 0;
    std::array<uint8_t, 16> src_ip6{};
    std::array<uint8_t, 16> dst_ip6{};
    uint8_t  hop_limit = 0; 

    // ── Transport layer (L4) ──────────────────────────────────────────────────
    uint16_t src_port  = 0;
    uint16_t dst_port  = 0;
    uint8_t  tcp_flags = 0;
    uint32_t seq_num   = 0;
    uint32_t ack_num   = 0;
    uint16_t win_size  = 0;

    // ── Payload ───────────────────────────────────────────────────────────────
    uint32_t pkt_len        = 0;
    uint32_t payload_len    = 0;
    uint32_t payload_offset = 0;

    // ── Helpers ───────────────────────────────────────────────────────────────
    const uint8_t* payload() const {
        if (payload_len == 0 || payload_offset >= raw_data.size())
            return nullptr;
        return raw_data.data() + payload_offset;
    }

    std::string flowKey() const;

    bool hasSYN() const { return tcp_flags & TCPFlags::SYN; }
    bool hasACK() const { return tcp_flags & TCPFlags::ACK; }
    bool hasRST() const { return tcp_flags & TCPFlags::RST; }
    bool hasFIN() const { return tcp_flags & TCPFlags::FIN; }
    bool hasPSH() const { return tcp_flags & TCPFlags::PSH; }
    bool hasURG() const { return tcp_flags & TCPFlags::URG; }

    bool isIPv4() const { return eth_type == EtherType::IPv4; }
    bool isARP()  const { return eth_type == EtherType::ARP;  }
    bool isIPv6() const { return eth_type == EtherType::IPv6; }

    double timestampSeconds() const {
        return timestamp.tv_sec + timestamp.tv_usec / 1e6;
    }
};
