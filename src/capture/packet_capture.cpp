#include "packet_capture.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"

// Linux network headers
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>

PacketCapture::PacketCapture() = default;

PacketCapture::~PacketCapture() {
    stopCapture();
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

// ─── Open Live Interface ───────────────────────────────────────────────────────
bool PacketCapture::openLive(const std::string& interface,
                              const std::string& bpf_filter) {
    char errbuf[PCAP_ERRBUF_SIZE];

    handle_ = pcap_open_live(
        interface.c_str(),
        65535,      // snaplen: bắt toàn bộ gói tin
        1,          // promiscuous mode
        1000,       // read timeout ms
        errbuf
    );

    if (!handle_) {
        LOG_ERROR("pcap_open_live failed: " + std::string(errbuf));
        return false;
    }

    // Áp dụng BPF filter
    if (!bpf_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle_, &fp,
                         bpf_filter.c_str(), 0,
                         PCAP_NETMASK_UNKNOWN) < 0) {
            LOG_WARN("BPF compile failed: "
                     + std::string(pcap_geterr(handle_)));
        } else {
            pcap_setfilter(handle_, &fp);
            pcap_freecode(&fp);
        }
    }

    LOG_INFO("Live capture opened on interface: " + interface);
    return true;
}

// ─── Open Offline PCAP File ───────────────────────────────────────────────────
bool PacketCapture::openOffline(const std::string& pcap_file,
                                 const std::string& bpf_filter) {
    char errbuf[PCAP_ERRBUF_SIZE];

    handle_ = pcap_open_offline(pcap_file.c_str(), errbuf);

    if (!handle_) {
        LOG_ERROR("pcap_open_offline failed: " + std::string(errbuf));
        return false;
    }

    if (!bpf_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle_, &fp,
                         bpf_filter.c_str(), 0,
                         PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(handle_, &fp);
            pcap_freecode(&fp);
        }
    }

    LOG_INFO("Offline capture opened: " + pcap_file);
    return true;
}

// ─── Start Capture ────────────────────────────────────────────────────────────
void PacketCapture::startCapture(PacketCallback callback) {
    if (!handle_) {
        LOG_ERROR("Cannot start capture: handle not open");
        return;
    }

    callback_ = std::move(callback);
    running_  = true;

    LOG_INFO("Capture started");

    // pcap_loop blocks until stopCapture() calls pcap_breakloop()
    pcap_loop(handle_, 0,
              PacketCapture::pcapCallback,
              reinterpret_cast<u_char*>(this));

    running_ = false;
    LOG_INFO("Capture stopped");
}

void PacketCapture::stopCapture() {
    if (running_ && handle_) {
        pcap_breakloop(handle_);
        running_ = false;
    }
}

// ─── libpcap Static Callback ──────────────────────────────────────────────────
void PacketCapture::pcapCallback(u_char*                  user,
                                  const struct pcap_pkthdr* header,
                                  const u_char*             packet) {
    auto* self = reinterpret_cast<PacketCapture*>(user);
    if (!self->running_) return;

    PacketInfo pkt = parsePacket(packet, header);
    if (self->callback_)
        self->callback_(std::move(pkt));
}

// ─── Parse Raw Packet ─────────────────────────────────────────────────────────
PacketInfo PacketCapture::parsePacket(const u_char*             data,
                                       const struct pcap_pkthdr* header) {
    PacketInfo pkt;
    pkt.timestamp = header->ts;
    pkt.pkt_len   = header->len;

    // Copy raw data
    pkt.raw_data.assign(data, data + header->caplen);

    const u_char* ptr = data;
    size_t        remaining = header->caplen;

    // ── Ethernet Header (14 bytes) ────────────────────────────────────────────
    if (remaining < sizeof(struct ether_header)) return pkt;
    auto* eth = reinterpret_cast<const struct ether_header*>(ptr);

    uint16_t eth_type = ntohs(eth->ether_type);
    if (eth_type != ETHERTYPE_IP) return pkt; // Chỉ xử lý IPv4

    ptr       += sizeof(struct ether_header);
    remaining -= sizeof(struct ether_header);

    // ── IP Header ─────────────────────────────────────────────────────────────
    if (remaining < sizeof(struct ip)) return pkt;
    auto* ip_hdr = reinterpret_cast<const struct ip*>(ptr);

    pkt.src_ip   = ip_hdr->ip_src.s_addr;
    pkt.dst_ip   = ip_hdr->ip_dst.s_addr;
    pkt.protocol = ip_hdr->ip_p;
    pkt.ttl      = ip_hdr->ip_ttl;

    size_t ip_hdr_len = ip_hdr->ip_hl * 4;
    ptr       += ip_hdr_len;
    remaining -= ip_hdr_len;

    // ── TCP Header ────────────────────────────────────────────────────────────
    if (pkt.protocol == IPPROTO_TCP) {
        if (remaining < sizeof(struct tcphdr)) return pkt;
        auto* tcp = reinterpret_cast<const struct tcphdr*>(ptr);

        pkt.src_port  = ntohs(tcp->th_sport);
        pkt.dst_port  = ntohs(tcp->th_dport);
        pkt.tcp_flags = tcp->th_flags;
        pkt.seq_num   = ntohl(tcp->th_seq);
        pkt.ack_num   = ntohl(tcp->th_ack);
        pkt.win_size  = ntohs(tcp->th_win);

        size_t tcp_hdr_len = tcp->th_off * 4;
        pkt.payload_offset = static_cast<uint32_t>(
            ptr - data + tcp_hdr_len);
        pkt.payload_len = (remaining > tcp_hdr_len)
                          ? static_cast<uint32_t>(remaining - tcp_hdr_len)
                          : 0;
    }
    // ── UDP Header ────────────────────────────────────────────────────────────
    else if (pkt.protocol == IPPROTO_UDP) {
        if (remaining < sizeof(struct udphdr)) return pkt;
        auto* udp = reinterpret_cast<const struct udphdr*>(ptr);

        pkt.src_port    = ntohs(udp->uh_sport);
        pkt.dst_port    = ntohs(udp->uh_dport);
        pkt.payload_offset = static_cast<uint32_t>(
            ptr - data + sizeof(struct udphdr));
        pkt.payload_len = (remaining > sizeof(struct udphdr))
                          ? static_cast<uint32_t>(
                              remaining - sizeof(struct udphdr))
                          : 0;
    }

    return pkt;
}
