// src/capture/protocol_decoder.cpp
#include "protocol_decoder.hpp"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <cstring>

// ─── Constants ───────────────────────────────────────────────────────────────
static constexpr uint32_t ETH_HDR_LEN  = 14;
static constexpr uint32_t VLAN_HDR_LEN = 4;   // 802.1Q tag

// ─── Main entry point ────────────────────────────────────────────────────────
PacketRecord ProtocolDecoder::decode(const struct pcap_pkthdr* header,
                                      const uint8_t*            data) {
    PacketRecord rec;
    rec.timestamp = header->ts.tv_sec + header->ts.tv_usec / 1e6;
    rec.cap_len   = header->caplen;
    rec.orig_len  = header->len;

    // Lưu raw_data để detail tree có thể hiển thị
    rec.raw_data  = std::make_shared<std::vector<uint8_t>>(
                        data, data + header->caplen);

    if (header->caplen < ETH_HDR_LEN) return rec;  // quá ngắn

    // ── Ethernet header ───────────────────────────────────────────────────────
    const auto* eth = reinterpret_cast<const struct ether_header*>(data);
    uint16_t    eth_type   = ntohs(eth->ether_type);
    uint32_t    ip_offset  = ETH_HDR_LEN;

    // Handle 802.1Q VLAN tag
    if (eth_type == 0x8100) {
        if (header->caplen < ETH_HDR_LEN + VLAN_HDR_LEN) return rec;
        eth_type  = ntohs(*reinterpret_cast<const uint16_t*>(
                              data + ETH_HDR_LEN + 2));
        ip_offset = ETH_HDR_LEN + VLAN_HDR_LEN;
    }

    rec.eth_type = eth_type;

    // ── Dispatch theo EtherType ───────────────────────────────────────────────
    switch (eth_type) {
        case ETHERTYPE_IP:   // 0x0800
            decodeIPv4(data + ip_offset,
                       header->caplen - ip_offset,
                       rec);
            break;

        case ETHERTYPE_ARP:  // 0x0806
            // ARP không có IP src/dst theo nghĩa thông thường
            // Giữ src_ip=0, dst_ip=0 nhưng đánh dấu protocol
            rec.protocol = 0xFE;  // sentinel: ARP
            break;

        case 0x86DD:         // IPv6 — để sau
            rec.protocol = 0xFF;  // sentinel: IPv6
            break;

        default:
            // Unknown EtherType — giữ nguyên zeros
            // UI sẽ hiển thị eth_type hex thay vì crash
            break;
    }

    return rec;
}

// ─── IPv4 decode ─────────────────────────────────────────────────────────────
void ProtocolDecoder::decodeIPv4(const uint8_t* data,
                                  uint32_t       len,
                                  PacketRecord&  rec) {
    if (len < sizeof(struct ip)) return;

    const auto* ip = reinterpret_cast<const struct ip*>(data);

    // Validate IP version
    if (ip->ip_v != 4) return;

    rec.src_ip   = ntohl(ip->ip_src.s_addr);
    rec.dst_ip   = ntohl(ip->ip_dst.s_addr);
    rec.protocol = ip->ip_p;

    uint32_t ip_hdr_len = ip->ip_hl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > len) return;  // malformed

    const uint8_t* l4   = data + ip_hdr_len;
    uint32_t       l4len = len  - ip_hdr_len;

    switch (ip->ip_p) {
        case IPPROTO_TCP:  decodeTCP (l4, l4len, rec); break;
        case IPPROTO_UDP:  decodeUDP (l4, l4len, rec); break;
        case IPPROTO_ICMP: decodeICMP(l4, l4len, rec); break;
        default: break;
    }
}

// ─── TCP decode ──────────────────────────────────────────────────────────────
void ProtocolDecoder::decodeTCP(const uint8_t* data,
                                 uint32_t       len,
                                 PacketRecord&  rec) {
    if (len < sizeof(struct tcphdr)) return;

    const auto* tcp = reinterpret_cast<const struct tcphdr*>(data);

    rec.src_port  = ntohs(tcp->th_sport);
    rec.dst_port  = ntohs(tcp->th_dport);
    rec.tcp_flags = tcp->th_flags;

    uint32_t tcp_hdr_len = tcp->th_off * 4;
    if (tcp_hdr_len < 20 || tcp_hdr_len > len) return;

    rec.payload_len = len - tcp_hdr_len;
}

// ─── UDP decode ──────────────────────────────────────────────────────────────
void ProtocolDecoder::decodeUDP(const uint8_t* data,
                                 uint32_t       len,
                                 PacketRecord&  rec) {
    if (len < sizeof(struct udphdr)) return;

    const auto* udp = reinterpret_cast<const struct udphdr*>(data);

    rec.src_port    = ntohs(udp->uh_sport);
    rec.dst_port    = ntohs(udp->uh_dport);
    rec.payload_len = (ntohs(udp->uh_ulen) > 8)
                      ? ntohs(udp->uh_ulen) - 8 : 0;
}

// ─── ICMP decode ─────────────────────────────────────────────────────────────
void ProtocolDecoder::decodeICMP(const uint8_t* data,
                                  uint32_t       len,
                                  PacketRecord&  rec) {
    if (len < 4) return;
    // ICMP không có port — dùng type/code làm src_port/dst_port
    // để flow table có thể group được
    rec.src_port = data[0];  // ICMP type
    rec.dst_port = data[1];  // ICMP code
}
