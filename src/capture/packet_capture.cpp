// src/capture/packet_capture.cpp
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

// ─── Global capture sequence ──────────────────────────────────────────────────
// Tăng dần liên tục, không reset khi stop/start capture
// → frame_no = capture_seq + 1 luôn unique và tăng dần
static std::atomic<uint64_t> g_capture_seq{0};

// ─── Constructor / Destructor ─────────────────────────────────────────────────
PacketCapture::PacketCapture() = default;

PacketCapture::~PacketCapture() {
    stopCapture();
    waitForStop();
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

// ─── applyFilter ──────────────────────────────────────────────────────────────
bool PacketCapture::applyFilter(const std::string& bpf_filter) {
    if (bpf_filter.empty()) return true;
    struct bpf_program fp {};
    if (pcap_compile(handle_, &fp, bpf_filter.c_str(), 1,
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
    handle_ = pcap_create(interface.c_str(), errbuf);
    if (!handle_) {
        LOG_ERROR("pcap_create failed: " + std::string(errbuf));
        return false;
    }

    pcap_set_snaplen    (handle_, 65535);
    pcap_set_promisc    (handle_, 1);
    pcap_set_timeout    (handle_, 1);
    pcap_set_buffer_size(handle_, 32 * 1024 * 1024);

    const int rc = pcap_activate(handle_);
    if (rc < 0) {
        LOG_ERROR("pcap_activate: " + std::string(pcap_geterr(handle_)));
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    if (rc > 0)
        LOG_WARN("pcap_activate warning: " + std::string(pcap_geterr(handle_)));

    if (pcap_datalink(handle_) != DLT_EN10MB)
        LOG_WARN("Not Ethernet DLT=" + std::to_string(pcap_datalink(handle_)));

    applyFilter(bpf_filter);
    LOG_INFO("Live capture: " + interface + " buffer=32MB timeout=1ms");
    return true;
}

// ─── openOffline ──────────────────────────────────────────────────────────────
bool PacketCapture::openOffline(const std::string& pcap_file,
                                 const std::string& bpf_filter) {
    char errbuf[PCAP_ERRBUF_SIZE] {};
    handle_ = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (!handle_) {
        LOG_ERROR("pcap_open_offline: " + std::string(errbuf));
        return false;
    }
    applyFilter(bpf_filter);
    LOG_INFO("Offline: " + pcap_file);
    return true;
}

// ─── startCapture ─────────────────────────────────────────────────────────────
void PacketCapture::startCapture(PacketCallback callback) {
    if (!handle_) { LOG_ERROR("handle not open"); return; }
    if (running_.load()) { LOG_WARN("already running"); return; }
    callback_ = std::move(callback);
    running_  = true;
    capture_thread_ = std::thread(&PacketCapture::captureLoop, this);
    LOG_INFO("Capture thread started");
}

// ─── captureLoop ──────────────────────────────────────────────────────────────
void PacketCapture::captureLoop() {
    LOG_INFO("Capture loop running");
    auto last_stats = std::chrono::steady_clock::now();

    while (running_.load(std::memory_order_relaxed)) {
        const int n = pcap_dispatch(handle_, -1,
                                    PacketCapture::pcapCallback,
                                    reinterpret_cast<u_char*>(this));
        if (n == -1) {
            if (running_.load())
                LOG_ERROR("pcap_dispatch: " + std::string(pcap_geterr(handle_)));
            break;
        }
        if (n == -2) break;

        const auto now = std::chrono::steady_clock::now();
        if (now - last_stats >= std::chrono::seconds(30)) {
            logStats();
            last_stats = now;
        }
    }

    running_ = false;
    LOG_INFO("Capture loop exited");
}

// ─── stopCapture ──────────────────────────────────────────────────────────────
void PacketCapture::stopCapture() {
    if (!running_.load()) return;
    if (handle_) pcap_breakloop(handle_);
}

// ─── waitForStop ──────────────────────────────────────────────────────────────
void PacketCapture::waitForStop() {
    if (capture_thread_.joinable())
        capture_thread_.join();
    logStats();
}

// ─── logStats ─────────────────────────────────────────────────────────────────
void PacketCapture::logStats() const {
    if (!handle_) return;
    struct pcap_stat ps {};
    if (pcap_stats(handle_, &ps) == 0)
        LOG_INFO("pcap | recv=" + std::to_string(ps.ps_recv)
               + " drop=" + std::to_string(ps.ps_drop)
               + " ifdrop=" + std::to_string(ps.ps_ifdrop));
}

// ─── pcapCallback ─────────────────────────────────────────────────────────────
void PacketCapture::pcapCallback(u_char*                   user,
                                  const struct pcap_pkthdr* header,
                                  const u_char*             packet) {
    auto* self = reinterpret_cast<PacketCapture*>(user);
    if (!self->running_.load(std::memory_order_relaxed)) return;

    PacketInfo pkt;

    // ── 1. Sequence + Timestamp ───────────────────────────────────────────────
    // FIX BUG 4: gán capture_seq từ global atomic counter
    pkt.capture_seq = g_capture_seq.fetch_add(1, std::memory_order_relaxed);
    pkt.timestamp   = header->ts;
    pkt.timestamp_d = static_cast<double>(header->ts.tv_sec)
                    + static_cast<double>(header->ts.tv_usec) * 1e-6;
    pkt.orig_len    = header->len;
    pkt.cap_len     = header->caplen;

    // ── 2. Copy raw bytes ─────────────────────────────────────────────────────
    pkt.raw_data = std::make_shared<std::vector<uint8_t>>(
                       packet, packet + header->caplen);

    // ── 3. Parse headers ──────────────────────────────────────────────────────
    parsePacket(pkt);

    METRICS.packets_captured.fetch_add(1, std::memory_order_relaxed);

    if (self->callback_)
        self->callback_(std::move(pkt));
}

// ─── parsePacket ──────────────────────────────────────────────────────────────
void PacketCapture::parsePacket(PacketInfo& pkt) {
    if (!pkt.raw_data || pkt.raw_data->empty()) return;

    const u_char* data      = pkt.raw_data->data();
    const u_char* ptr       = data;
    size_t        remaining = pkt.cap_len;

    // ── Ethernet ──────────────────────────────────────────────────────────────
    if (remaining < sizeof(struct ether_header)) return;
    const auto* eth      = reinterpret_cast<const struct ether_header*>(ptr);
    uint16_t    eth_type = ntohs(eth->ether_type);
    pkt.eth_type         = eth_type;
    ptr       += sizeof(struct ether_header);
    remaining -= sizeof(struct ether_header);

    // ── VLAN 802.1Q / QinQ ────────────────────────────────────────────────────
    while ((eth_type == 0x8100 || eth_type == 0x88A8) && remaining >= 4) {
        eth_type     = ntohs(*reinterpret_cast<const uint16_t*>(ptr + 2));
        pkt.eth_type = eth_type;
        ptr += 4; remaining -= 4;
    }

    // ── IPv4 ──────────────────────────────────────────────────────────────────
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

    // ── IPv6 ──────────────────────────────────────────────────────────────────
    if (eth_type == ETHERTYPE_IPV6) {
        constexpr size_t IP6H = 40;
        if (remaining < IP6H) return;
        const auto* ip6 = reinterpret_cast<const struct ip6_hdr*>(ptr);
        std::memcpy(pkt.src_ip6.data(), &ip6->ip6_src, 16);
        std::memcpy(pkt.dst_ip6.data(), &ip6->ip6_dst, 16);
        pkt.protocol   = ip6->ip6_nxt;
        pkt.hop_limit  = ip6->ip6_hlim;
        pkt.ttl        = ip6->ip6_hlim;
        pkt.is_ipv6    = true;
        ptr += IP6H; remaining -= IP6H;

        bool cont = true;
        while (cont && remaining >= 2) {
            switch (pkt.protocol) {
                case 0: case 43: case 60: {
                    const size_t ext = static_cast<size_t>(ptr[1] + 1) * 8;
                    if (ext > remaining) { cont = false; break; }
                    pkt.protocol = ptr[0];
                    ptr += ext; remaining -= ext;
                    break;
                }
                case 44:
                    if (remaining < 8) { cont = false; break; }
                    pkt.protocol = ptr[0];
                    ptr += 8; remaining -= 8;
                    break;
                case 50: case 51:
                    pkt.is_encrypted = true;
                    cont = false;
                    break;
                default:
                    cont = false;
                    break;
            }
        }
        parseTransport(pkt, ptr, remaining, data);
        return;
    }
    // ARP, MPLS, ... — giữ eth_type, không parse L4
}

// ─── parseTransport ───────────────────────────────────────────────────────────
void PacketCapture::parseTransport(PacketInfo&   pkt,
                                    const u_char* ptr,
                                    size_t        remaining,
                                    const u_char* frame_start) {
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
        default:
            break;
    }
}
