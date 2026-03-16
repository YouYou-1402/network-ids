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
#include <atomic>

static std::atomic<uint64_t> g_capture_seq{0};

PacketCapture::PacketCapture()  = default;

PacketCapture::~PacketCapture() {
    stopCapture();
    waitForStop();
    if (handle_) { pcap_close(handle_); handle_ = nullptr; }
}

bool PacketCapture::applyFilter(const std::string& bpf_filter) {
    if (bpf_filter.empty()) return true;
    struct bpf_program fp{};
    if (pcap_compile(handle_, &fp, bpf_filter.c_str(), 1,
                     PCAP_NETMASK_UNKNOWN) < 0) {
        LOG_WARN("BPF compile: " + std::string(pcap_geterr(handle_)));
        return false;
    }
    if (pcap_setfilter(handle_, &fp) < 0) {
        LOG_WARN("BPF setfilter: " + std::string(pcap_geterr(handle_)));
        pcap_freecode(&fp);
        return false;
    }
    pcap_freecode(&fp);
    return true;
}

bool PacketCapture::openLive(const std::string& interface,
                              const std::string& bpf_filter) {
    char errbuf[PCAP_ERRBUF_SIZE]{};
    handle_ = pcap_create(interface.c_str(), errbuf);
    if (!handle_) { LOG_ERROR("pcap_create: " + std::string(errbuf)); return false; }

    pcap_set_snaplen    (handle_, 65535);
    pcap_set_promisc    (handle_, 1);
    pcap_set_timeout    (handle_, 1);
    pcap_set_buffer_size(handle_, 32 * 1024 * 1024);

    const int rc = pcap_activate(handle_);
    if (rc < 0) {
        LOG_ERROR("pcap_activate: " + std::string(pcap_geterr(handle_)));
        pcap_close(handle_); handle_ = nullptr;
        return false;
    }
    if (rc > 0)
        LOG_WARN("pcap_activate warning: " + std::string(pcap_geterr(handle_)));

    applyFilter(bpf_filter);
    LOG_INFO("Live capture: " + interface);
    return true;
}

bool PacketCapture::openOffline(const std::string& pcap_file,
                                 const std::string& bpf_filter) {
    char errbuf[PCAP_ERRBUF_SIZE]{};
    handle_ = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (!handle_) { LOG_ERROR("pcap_open_offline: " + std::string(errbuf)); return false; }
    applyFilter(bpf_filter);
    return true;
}

void PacketCapture::startCapture(RawPacketCallback callback) {
    if (!handle_) { LOG_ERROR("handle not open"); return; }
    if (running_.load()) { LOG_WARN("already running"); return; }
    callback_ = std::move(callback);
    running_  = true;
    capture_thread_ = std::thread(&PacketCapture::captureLoop, this);
}

void PacketCapture::captureLoop() {
    while (running_.load(std::memory_order_relaxed)) {
        const int n = pcap_dispatch(handle_, -1,
                                    PacketCapture::pcapCallback,
                                    reinterpret_cast<u_char*>(this));
        if (n == -1) { if (running_.load()) LOG_ERROR("pcap_dispatch error"); break; }
        if (n == -2) break;
    }
    running_ = false;
}

void PacketCapture::stopCapture() {
    if (!running_.load()) return;
    if (handle_) pcap_breakloop(handle_);
}

void PacketCapture::waitForStop() {
    if (capture_thread_.joinable()) capture_thread_.join();
}

void PacketCapture::logStats() const {
    if (!handle_) return;
    struct pcap_stat ps{};
    if (pcap_stats(handle_, &ps) == 0)
        LOG_INFO("pcap recv=" + std::to_string(ps.ps_recv)
               + " drop=" + std::to_string(ps.ps_drop));
}

// ─── pcapCallback ─────────────────────────────────────────────────────────────
// KHÔNG copy raw_data vào pkt — raw_bytes là con trỏ tạm của pcap
// Caller (main_window) quyết định có copy hay không
void PacketCapture::pcapCallback(u_char*                   user,
                                  const struct pcap_pkthdr* header,
                                  const u_char*             packet) {
    auto* self = reinterpret_cast<PacketCapture*>(user);
    if (!self->running_.load(std::memory_order_relaxed)) return;

    PacketInfo pkt;
    pkt.capture_seq = g_capture_seq.fetch_add(1, std::memory_order_relaxed);
    pkt.timestamp   = header->ts;
    pkt.timestamp_d = static_cast<double>(header->ts.tv_sec)
                    + static_cast<double>(header->ts.tv_usec) * 1e-6;
    pkt.orig_len    = header->len;
    pkt.cap_len     = header->caplen;

    // Parse headers từ raw pointer — KHÔNG gán pkt.raw_data
    parsePacket(pkt,
                reinterpret_cast<const uint8_t*>(packet),
                header->caplen);

    METRICS.packets_captured.fetch_add(1, std::memory_order_relaxed);

    if (self->callback_)
        self->callback_(std::move(pkt),
                        reinterpret_cast<const uint8_t*>(packet),
                        header->caplen);
}

// ─── parsePacket ─────────────────────────────────────────────────────────────
void PacketCapture::parsePacket(PacketInfo&    pkt,
                                 const uint8_t* data,
                                 uint32_t       cap_len) {
    const uint8_t* ptr       = data;
    size_t         remaining = cap_len;

    if (remaining < sizeof(struct ether_header)) return;
    const auto* eth = reinterpret_cast<const struct ether_header*>(ptr);
    uint16_t eth_type = ntohs(eth->ether_type);
    pkt.eth_type      = eth_type;
    ptr += sizeof(struct ether_header);
    remaining -= sizeof(struct ether_header);

    while ((eth_type == 0x8100 || eth_type == 0x88A8) && remaining >= 4) {
        eth_type     = ntohs(*reinterpret_cast<const uint16_t*>(ptr + 2));
        pkt.eth_type = eth_type;
        ptr += 4; remaining -= 4;
    }

    if (eth_type == ETHERTYPE_IP) {
        if (remaining < sizeof(struct ip)) return;
        const auto* iph = reinterpret_cast<const struct ip*>(ptr);
        if (iph->ip_v != 4) return;
        const size_t ihl = static_cast<size_t>(iph->ip_hl) * 4;
        if (ihl < 20 || ihl > remaining) return;
        pkt.src_ip   = iph->ip_src.s_addr;
        pkt.dst_ip   = iph->ip_dst.s_addr;
        pkt.protocol = iph->ip_p;
        pkt.ttl      = iph->ip_ttl;
        pkt.is_ipv6  = false;
        ptr += ihl; remaining -= ihl;
        parseTransport(pkt, ptr, remaining, data);
        return;
    }

    if (eth_type == ETHERTYPE_IPV6) {
        constexpr size_t IP6H = 40;
        if (remaining < IP6H) return;
        const auto* ip6 = reinterpret_cast<const struct ip6_hdr*>(ptr);
        std::memcpy(pkt.src_ip6.data(), &ip6->ip6_src, 16);
        std::memcpy(pkt.dst_ip6.data(), &ip6->ip6_dst, 16);
        pkt.protocol  = ip6->ip6_nxt;
        pkt.ttl       = ip6->ip6_hlim;
        pkt.is_ipv6   = true;
        ptr += IP6H; remaining -= IP6H;

        bool cont = true;
        while (cont && remaining >= 2) {
            switch (pkt.protocol) {
                case 0: case 43: case 60: {
                    const size_t ext = static_cast<size_t>(ptr[1] + 1) * 8;
                    if (ext > remaining) { cont = false; break; }
                    pkt.protocol = ptr[0]; ptr += ext; remaining -= ext; break;
                }
                case 44:
                    if (remaining < 8) { cont = false; break; }
                    pkt.protocol = ptr[0]; ptr += 8; remaining -= 8; break;
                case 50: case 51:
                    pkt.is_encrypted = true; cont = false; break;
                default: cont = false; break;
            }
        }
        parseTransport(pkt, ptr, remaining, data);
    }
}

// ─── parseTransport ──────────────────────────────────────────────────────────
void PacketCapture::parseTransport(PacketInfo&    pkt,
                                    const uint8_t* ptr,
                                    size_t         remaining,
                                    const uint8_t* frame_start) {
    switch (pkt.protocol) {
        case IPPROTO_TCP: {
            if (remaining < sizeof(struct tcphdr)) return;
            const auto* tcp = reinterpret_cast<const struct tcphdr*>(ptr);
            const size_t hlen = static_cast<size_t>(tcp->th_off) * 4;
            if (hlen < 20 || hlen > remaining) return;
            pkt.src_port       = ntohs(tcp->th_sport);
            pkt.dst_port       = ntohs(tcp->th_dport);
            pkt.tcp_flags      = tcp->th_flags;
            pkt.seq_num        = ntohl(tcp->th_seq);
            pkt.ack_num        = ntohl(tcp->th_ack);
            pkt.win_size       = ntohs(tcp->th_win);
            pkt.payload_offset = static_cast<uint32_t>(ptr - frame_start + hlen);
            pkt.payload_len    = static_cast<uint32_t>(remaining - hlen);
            break;
        }
        case IPPROTO_UDP: {
            if (remaining < sizeof(struct udphdr)) return;
            const auto* udp = reinterpret_cast<const struct udphdr*>(ptr);
            pkt.src_port       = ntohs(udp->uh_sport);
            pkt.dst_port       = ntohs(udp->uh_dport);
            pkt.payload_offset = static_cast<uint32_t>(
                ptr - frame_start + sizeof(struct udphdr));
            pkt.payload_len    = remaining > sizeof(struct udphdr)
                ? static_cast<uint32_t>(remaining - sizeof(struct udphdr)) : 0;
            break;
        }
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            pkt.payload_offset = static_cast<uint32_t>(ptr - frame_start);
            pkt.payload_len    = static_cast<uint32_t>(remaining);
            break;
        default: break;
    }
}
