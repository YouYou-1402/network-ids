// src/pcap_io/packet_capture.cpp
#include "packet_capture.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>    
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <cstring>

// ─── Constructor / Destructor ─────────────────────────────────────────────────
PacketCapture::PacketCapture() = default;

PacketCapture::~PacketCapture() {
    stopCapture();
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

// ─── applyFilter ──────────────────────────────────────────────────────────────
bool PacketCapture::applyFilter(const std::string& bpf_filter) {
    if (bpf_filter.empty()) return true;

    struct bpf_program fp {};
    if (pcap_compile(handle_, &fp,
                     bpf_filter.c_str(), 1,
                     PCAP_NETMASK_UNKNOWN) < 0) {
        LOG_WARN("BPF compile failed: " + std::string(pcap_geterr(handle_)));
        return false;
    }

    if (pcap_setfilter(handle_, &fp) < 0) {
        LOG_WARN("BPF setfilter failed: " + std::string(pcap_geterr(handle_)));
        pcap_freecode(&fp);
        return false;
    }

    pcap_freecode(&fp);
    LOG_INFO("BPF filter applied: " + bpf_filter);
    return true;
}

// ─── openLive ─────────────────────────────────────────────────────────────────
bool PacketCapture::openLive(const std::string& interface,
                              const std::string& bpf_filter) {
    char errbuf[PCAP_ERRBUF_SIZE] {};

    handle_ = pcap_open_live(
        interface.c_str(),
        65535,
        1,       // promiscuous
        1000,    // timeout ms
        errbuf
    );

    if (!handle_) {
        LOG_ERROR("pcap_open_live failed: " + std::string(errbuf));
        return false;
    }

    if (pcap_datalink(handle_) != DLT_EN10MB) {
        LOG_WARN("Interface " + interface +
                 " is not Ethernet (DLT=" +
                 std::to_string(pcap_datalink(handle_)) + ")");
    }

    applyFilter(bpf_filter);
    LOG_INFO("Live capture opened on interface: " + interface);
    return true;
}

// ─── openOffline ──────────────────────────────────────────────────────────────
bool PacketCapture::openOffline(const std::string& pcap_file,
                                 const std::string& bpf_filter) {
    char errbuf[PCAP_ERRBUF_SIZE] {};

    handle_ = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (!handle_) {
        LOG_ERROR("pcap_open_offline failed: " + std::string(errbuf));
        return false;
    }

    applyFilter(bpf_filter);
    LOG_INFO("Offline capture opened: " + pcap_file);
    return true;
}

// ─── startCapture ─────────────────────────────────────────────────────────────
void PacketCapture::startCapture(PacketCallback callback) {
    if (!handle_) {
        LOG_ERROR("Cannot start capture: handle not open");
        return;
    }

    callback_ = std::move(callback);
    running_  = true;
    LOG_INFO("Capture started");

    pcap_loop(handle_, 0,
              PacketCapture::pcapCallback,
              reinterpret_cast<u_char*>(this));

    running_ = false;
    LOG_INFO("Capture stopped");
}

// ─── stopCapture ──────────────────────────────────────────────────────────────
void PacketCapture::stopCapture() {
    if (running_.load() && handle_) {
        pcap_breakloop(handle_);
        running_ = false;
    }
}

// ─── pcapCallback (static) ────────────────────────────────────────────────────
void PacketCapture::pcapCallback(u_char*                   user,
                                  const struct pcap_pkthdr* header,
                                  const u_char*             packet) {
    auto* self = reinterpret_cast<PacketCapture*>(user);
    if (!self->running_.load()) return;

    PacketInfo pkt = parsePacket(packet, header);

    METRICS.packets_captured.fetch_add(1, std::memory_order_relaxed);

    if (self->callback_)
        self->callback_(std::move(pkt));
}

// ─────────────────────────────────────────────────────────────────────────────
// parseTransport — parse TCP/UDP/ICMP chung cho cả IPv4 và IPv6
// ─────────────────────────────────────────────────────────────────────────────
static void parseTransport(PacketInfo&   pkt,
                            const u_char* ptr,
                            size_t        remaining,
                            const u_char* data_start) {
    switch (pkt.protocol) {

        // ── TCP ───────────────────────────────────────────────────────────────
        case IPPROTO_TCP: {
            if (remaining < sizeof(struct tcphdr)) return;
            const auto* tcp = reinterpret_cast<const struct tcphdr*>(ptr);

            const size_t tcp_hdr_len = tcp->th_off * 4;
            if (tcp_hdr_len < 20 || tcp_hdr_len > remaining) return;

            pkt.src_port  = ntohs(tcp->th_sport);
            pkt.dst_port  = ntohs(tcp->th_dport);
            pkt.tcp_flags = tcp->th_flags;
            pkt.seq_num   = ntohl(tcp->th_seq);
            pkt.ack_num   = ntohl(tcp->th_ack);
            pkt.win_size  = ntohs(tcp->th_win);

            pkt.payload_offset = static_cast<uint32_t>(
                ptr - data_start + tcp_hdr_len);
            pkt.payload_len = static_cast<uint32_t>(
                remaining - tcp_hdr_len);
            break;
        }

        // ── UDP ───────────────────────────────────────────────────────────────
        case IPPROTO_UDP: {
            if (remaining < sizeof(struct udphdr)) return;
            const auto* udp = reinterpret_cast<const struct udphdr*>(ptr);

            pkt.src_port       = ntohs(udp->uh_sport);
            pkt.dst_port       = ntohs(udp->uh_dport);
            pkt.payload_offset = static_cast<uint32_t>(
                ptr - data_start + sizeof(struct udphdr));
            pkt.payload_len    = (remaining > sizeof(struct udphdr))
                ? static_cast<uint32_t>(remaining - sizeof(struct udphdr))
                : 0;
            break;
        }

        // ── ICMP / ICMPv6 — ghi nhận, không parse sâu ────────────────────────
        case IPPROTO_ICMP:
        case 58: {   // IPPROTO_ICMPV6
            pkt.payload_offset = static_cast<uint32_t>(ptr - data_start);
            pkt.payload_len    = static_cast<uint32_t>(remaining);
            break;
        }

        default: break;
    }
}

// ─── parsePacket ──────────────────────────────────────────────────────────────
PacketInfo PacketCapture::parsePacket(const u_char*             data,
                                       const struct pcap_pkthdr* header) {
    PacketInfo pkt {};
    pkt.timestamp = header->ts;
    pkt.pkt_len   = header->len;
    pkt.cap_len   = header->caplen;
    pkt.raw_data.assign(data, data + header->caplen);

    const u_char* ptr       = data;
    size_t        remaining = header->caplen;

    // ── Ethernet Header (14 bytes) ────────────────────────────────────────────
    if (remaining < sizeof(struct ether_header)) return pkt;

    const auto* eth  = reinterpret_cast<const struct ether_header*>(ptr);
    uint16_t eth_type = ntohs(eth->ether_type);

    pkt.eth_type = eth_type;

    ptr       += sizeof(struct ether_header);
    remaining -= sizeof(struct ether_header);

    // ── VLAN 802.1Q (0x8100) ─────────────────────────────────────────────────
    if (eth_type == 0x8100) {
        if (remaining < 4) return pkt;
        eth_type     = ntohs(*reinterpret_cast<const uint16_t*>(ptr + 2));
        pkt.eth_type = eth_type;
        ptr       += 4;
        remaining -= 4;
    }

    // ── IPv4 (0x0800) ─────────────────────────────────────────────────────────
    if (eth_type == ETHERTYPE_IP) {
        if (remaining < sizeof(struct ip)) return pkt;

        const auto* ip_hdr = reinterpret_cast<const struct ip*>(ptr);
        if (ip_hdr->ip_v != 4) return pkt;

        const size_t ip_hdr_len = ip_hdr->ip_hl * 4;
        if (ip_hdr_len < 20 || ip_hdr_len > remaining) return pkt;

        pkt.src_ip   = ip_hdr->ip_src.s_addr;   // network byte order
        pkt.dst_ip   = ip_hdr->ip_dst.s_addr;   // network byte order
        pkt.protocol = ip_hdr->ip_p;
        pkt.ttl      = ip_hdr->ip_ttl;

        ptr       += ip_hdr_len;
        remaining -= ip_hdr_len;

        parseTransport(pkt, ptr, remaining, data);
        return pkt;
    }

    // ── IPv6 (0x86DD) ─────────────────────────────────────────────────────────
    if (eth_type == 0x86DD) {
        // IPv6 fixed header = 40 bytes
        constexpr size_t IP6_HDR_LEN = 40;
        if (remaining < IP6_HDR_LEN) return pkt;

        const auto* ip6 = reinterpret_cast<const struct ip6_hdr*>(ptr);

        // ✅ Copy 128-bit src/dst address
        std::memcpy(pkt.src_ip6.data(),
                    &ip6->ip6_src,
                    16);
        std::memcpy(pkt.dst_ip6.data(),
                    &ip6->ip6_dst,
                    16);

        pkt.protocol  = ip6->ip6_nxt;   // next header (TCP=6, UDP=17, ICMPv6=58)
        pkt.hop_limit = ip6->ip6_hlim;  // IPv6 hop limit (≈ TTL)
        pkt.ttl       = ip6->ip6_hlim;  // alias cho compatibility

        ptr       += IP6_HDR_LEN;
        remaining -= IP6_HDR_LEN;

        // ── IPv6 Extension Headers ────────────────────────────────────────────
        // Bỏ qua các extension header cho đến khi gặp TCP/UDP/ICMPv6
        // Các extension header: Hop-by-Hop(0), Routing(43),
        //                       Fragment(44), Dest Options(60)
        bool parsing_ext = true;
        while (parsing_ext && remaining >= 2) {
            switch (pkt.protocol) {
                case 0:    // Hop-by-Hop Options
                case 43:   // Routing
                case 60: { // Destination Options
                    // Byte 0: next header, Byte 1: length (units of 8 bytes, +1)
                    const uint8_t next_hdr = ptr[0];
                    const size_t  ext_len  = (ptr[1] + 1) * 8;
                    if (ext_len > remaining) { parsing_ext = false; break; }
                    pkt.protocol = next_hdr;
                    ptr       += ext_len;
                    remaining -= ext_len;
                    break;
                }
                case 44: { // Fragment — fixed 8 bytes
                    if (remaining < 8) { parsing_ext = false; break; }
                    pkt.protocol = ptr[0];
                    ptr       += 8;
                    remaining -= 8;
                    break;
                }
                default:
                    // TCP(6), UDP(17), ICMPv6(58), IGMP(2), etc.
                    parsing_ext = false;
                    break;
            }
        }

        parseTransport(pkt, ptr, remaining, data);
        return pkt;
    }

    // ── ARP / VLAN / khác — đã có eth_type, không parse sâu hơn ─────────────
    return pkt;
}
