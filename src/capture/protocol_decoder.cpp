// src/capture/protocol_decoder.cpp
#include "protocol_decoder.hpp"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <cstring>
#include <atomic>

// ─── Constants ───────────────────────────────────────────────────────────────
static std::atomic<uint64_t> g_capture_seq  = 0;
static constexpr uint32_t    ETH_HDR_LEN    = 14;
static constexpr uint32_t    VLAN_HDR_LEN   = 4;

// ─── decode ──────────────────────────────────────────────────────────────────
PacketInfo ProtocolDecoder::decode(const struct pcap_pkthdr* header,
                                   const uint8_t*            data) {
    PacketInfo pkt;

    // FIX BUG 1: gán đúng struct timeval + double cache
    pkt.timestamp.tv_sec  = header->ts.tv_sec;
    pkt.timestamp.tv_usec = header->ts.tv_usec;
    pkt.timestamp_d       = static_cast<double>(header->ts.tv_sec)
                          + static_cast<double>(header->ts.tv_usec) / 1e6;

    pkt.cap_len     = header->caplen;
    pkt.orig_len    = header->len;
    pkt.capture_seq = g_capture_seq.fetch_add(1, std::memory_order_relaxed);
    pkt.raw_data    = std::make_shared<std::vector<uint8_t>>(
                          data, data + header->caplen);

    if (header->caplen < ETH_HDR_LEN) return pkt;

    // ── Ethernet header ───────────────────────────────────────────────────────
    const auto* eth    = reinterpret_cast<const struct ether_header*>(data);
    uint16_t    eth_type  = ntohs(eth->ether_type);
    uint32_t    ip_offset = ETH_HDR_LEN;

    // 802.1Q VLAN tag
    if (eth_type == 0x8100) {
        if (header->caplen < ETH_HDR_LEN + VLAN_HDR_LEN) return pkt;
        eth_type  = ntohs(*reinterpret_cast<const uint16_t*>(
                              data + ETH_HDR_LEN + 2));
        ip_offset = ETH_HDR_LEN + VLAN_HDR_LEN;
    }

    pkt.eth_type = eth_type;

    // ── Dispatch theo EtherType ───────────────────────────────────────────────
    switch (eth_type) {
        case ETHERTYPE_IP:   // 0x0800
            decodeIPv4(data + ip_offset,
                       header->caplen - ip_offset,
                       ip_offset,        // FIX BUG 3: truyền offset
                       pkt);
            break;

        case ETHERTYPE_ARP:  // 0x0806
            // FIX BUG 4: dùng named constant thay magic number
            pkt.protocol = SentinelProto::ARP;
            break;

        case 0x86DD:         // IPv6
            // FIX BUG 4: dùng named constant thay magic number
            pkt.protocol = SentinelProto::IPV6;
            break;

        default:
            break;
    }

    return pkt;
}

// ─── decodeIPv4 ──────────────────────────────────────────────────────────────
void ProtocolDecoder::decodeIPv4(const uint8_t* data,
                                  uint32_t       len,
                                  uint32_t       l3_offset,
                                  PacketInfo&    pkt) {
    if (len < sizeof(struct ip)) return;

    const auto* ip = reinterpret_cast<const struct ip*>(data);
    if (ip->ip_v != 4) return;

    // FIX BUG 2: giữ network byte order — KHÔNG ntohl()
    // Nhất quán với pcap_reader.cpp và packet_capture.cpp
    pkt.src_ip   = ip->ip_src.s_addr;
    pkt.dst_ip   = ip->ip_dst.s_addr;
    pkt.protocol = ip->ip_p;
    pkt.ttl      = ip->ip_ttl;

    const uint32_t ip_hdr_len = ip->ip_hl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > len) return;

    const uint8_t* l4        = data + ip_hdr_len;
    const uint32_t l4_len    = len  - ip_hdr_len;
    const uint32_t l4_offset = l3_offset + ip_hdr_len;  // FIX BUG 3

    switch (ip->ip_p) {
        case IPPROTO_TCP:  decodeTCP (l4, l4_len, l4_offset, pkt); break;
        case IPPROTO_UDP:  decodeUDP (l4, l4_len, l4_offset, pkt); break;
        case IPPROTO_ICMP: decodeICMP(l4, l4_len, l4_offset, pkt); break;
        default: break;
    }
}

// ─── decodeTCP ───────────────────────────────────────────────────────────────
void ProtocolDecoder::decodeTCP(const uint8_t* data,
                                 uint32_t       len,
                                 uint32_t       l4_offset,
                                 PacketInfo&    pkt) {
    if (len < sizeof(struct tcphdr)) return;

    const auto* tcp = reinterpret_cast<const struct tcphdr*>(data);

    pkt.src_port  = ntohs(tcp->th_sport);
    pkt.dst_port  = ntohs(tcp->th_dport);
    pkt.tcp_flags = tcp->th_flags;
    pkt.seq_num   = ntohl(tcp->th_seq);
    pkt.ack_num   = ntohl(tcp->th_ack);
    pkt.win_size  = ntohs(tcp->th_win);

    const uint32_t tcp_hdr_len = tcp->th_off * 4;
    if (tcp_hdr_len < 20 || tcp_hdr_len > len) return;

    // FIX BUG 3: payload_offset tính từ đầu frame (= đầu raw_data)
    pkt.payload_offset = l4_offset + tcp_hdr_len;
    pkt.payload_len    = len - tcp_hdr_len;
}

// ─── decodeUDP ───────────────────────────────────────────────────────────────
void ProtocolDecoder::decodeUDP(const uint8_t* data,
                                 uint32_t       len,
                                 uint32_t       l4_offset,
                                 PacketInfo&    pkt) {
    if (len < sizeof(struct udphdr)) return;

    const auto* udp = reinterpret_cast<const struct udphdr*>(data);

    pkt.src_port = ntohs(udp->uh_sport);
    pkt.dst_port = ntohs(udp->uh_dport);

    // FIX BUG 3: payload_offset tính từ đầu frame
    pkt.payload_offset = l4_offset + static_cast<uint32_t>(sizeof(struct udphdr));
    pkt.payload_len    = (ntohs(udp->uh_ulen) > 8)
                         ? ntohs(udp->uh_ulen) - 8 : 0;
}

// ─── decodeICMP ──────────────────────────────────────────────────────────────
void ProtocolDecoder::decodeICMP(const uint8_t* data,
                                  uint32_t       len,
                                  uint32_t       l4_offset,
                                  PacketInfo&    pkt) {
    if (len < 4) return;

    // ICMP không có port — dùng type/code để flow table có thể group
    pkt.src_port = data[0];   // ICMP type
    pkt.dst_port = data[1];   // ICMP code

    // FIX BUG 3: payload_offset trỏ đúng vào ICMP header trong raw_data
    pkt.payload_offset = l4_offset;
    pkt.payload_len    = len;
}
