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

    // ── Bước 1: create (chưa activate) ───────────────────────────────────────
    handle_ = pcap_create(interface.c_str(), errbuf);
    if (!handle_) {
        LOG_ERROR("pcap_create failed: " + std::string(errbuf));
        return false;
    }

    // ── Bước 2: set params TRƯỚC activate ────────────────────────────────────
    pcap_set_snaplen(handle_, 65535);
    pcap_set_promisc(handle_, 1);
    pcap_set_timeout(handle_, 10);                      // 10ms thay vì 1000ms
    pcap_set_buffer_size(handle_, 32 * 1024 * 1024);    // 32 MB kernel buffer

    // ── Bước 3: activate ─────────────────────────────────────────────────────
    const int rc = pcap_activate(handle_);
    if (rc < 0) {
        LOG_ERROR("pcap_activate failed: " + std::string(pcap_geterr(handle_)));
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    if (rc > 0) {
        // rc > 0 là warning, không phải lỗi (vẫn hoạt động)
        LOG_WARN("pcap_activate warning: " + std::string(pcap_geterr(handle_)));
    }

    // ── Bước 4: kiểm tra datalink ────────────────────────────────────────────
    if (pcap_datalink(handle_) != DLT_EN10MB) {
        LOG_WARN("Interface " + interface +
                 " is not Ethernet (DLT=" +
                 std::to_string(pcap_datalink(handle_)) + ")");
    }

    applyFilter(bpf_filter);
    LOG_INFO("Live capture opened on: " + interface +
             " | buffer=32MB | timeout=10ms");
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
    if (running_.load()) {
        LOG_WARN("Capture already running");
        return;
    }

    callback_ = std::move(callback);
    running_  = true;

    capture_thread_ = std::thread(&PacketCapture::captureLoop, this);
    LOG_INFO("Capture thread started");
}

void PacketCapture::logStats() const {
    if (!handle_) return;
    struct pcap_stat ps {};
    if (pcap_stats(handle_, &ps) == 0) {
        LOG_INFO("pcap stats | recv=" + std::to_string(ps.ps_recv)
                 + " | kernel_drop=" + std::to_string(ps.ps_drop)
                 + " | iface_drop="  + std::to_string(ps.ps_ifdrop));
    }
}

// ─── captureLoop (chạy trên capture_thread_) ─────────────────────────────────
void PacketCapture::captureLoop() {
    LOG_INFO("Capture loop running");

    // pcap_loop trả về khi:
    //   -2 → pcap_breakloop() được gọi
    //   -1 → lỗi
    //    0 → đọc hết file (offline mode)
    const int ret = pcap_loop(handle_, 0,
                              PacketCapture::pcapCallback,
                              reinterpret_cast<u_char*>(this));

    if (ret == -1)
        LOG_ERROR("pcap_loop error: " + std::string(pcap_geterr(handle_)));
    else if (ret == -2)
        LOG_INFO("pcap_loop stopped by breakloop");
    else
        LOG_INFO("pcap_loop finished (offline EOF)");

    running_ = false;
    LOG_INFO("Capture loop exited");
}

// ─── stopCapture ──────────────────────────────────────────────────────────────
void PacketCapture::stopCapture() {
    logStats();
    if (running_.load() && handle_) {
        pcap_breakloop(handle_);
        // running_ = false sẽ được set bởi captureLoop() sau khi pcap_loop trả về
    }
}

// ─── waitForStop ──────────────────────────────────────────────────────────────
void PacketCapture::waitForStop() {
    if (capture_thread_.joinable())
        capture_thread_.join();
}

// ─── pcapCallback (static) ────────────────────────────────────────────────────
void PacketCapture::pcapCallback(u_char*                   user,
                                  const struct pcap_pkthdr* header,
                                  const u_char*             packet) {
    auto* self = reinterpret_cast<PacketCapture*>(user);
    if (!self->running_.load()) return;
    PacketInfo pkt = PacketCapture::parsePacket(packet, header);

    METRICS.packets_captured.fetch_add(1, std::memory_order_relaxed);

    if (self->callback_)
        self->callback_(std::move(pkt));
}

static void parseTransport(PacketInfo&   pkt,
                            const u_char* ptr,
                            size_t        remaining,
                            const u_char* frame_start) {
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

            // payload_offset = bytes từ đầu frame đến đầu payload
            pkt.payload_offset = static_cast<uint32_t>(
                (ptr - frame_start) + tcp_hdr_len);
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
                (ptr - frame_start) + sizeof(struct udphdr));
            pkt.payload_len    = (remaining > sizeof(struct udphdr))
                ? static_cast<uint32_t>(remaining - sizeof(struct udphdr))
                : 0;
            break;
        }

        // ── ICMP / ICMPv6 ─────────────────────────────────────────────────────
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6: {
            pkt.payload_offset = static_cast<uint32_t>(ptr - frame_start);
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
    pkt.timestamp  = header->ts;
    pkt.timestamp_d = static_cast<double>(header->ts.tv_sec)
                    + static_cast<double>(header->ts.tv_usec) / 1e6;
    pkt.orig_len    = header->len;
    pkt.cap_len    = header->caplen;

    // FIX BUG 2: raw_data là shared_ptr<vector<uint8_t>>
    pkt.raw_data = std::make_shared<std::vector<uint8_t>>(
        data, data + header->caplen);

    const u_char* ptr       = data;
    size_t        remaining = header->caplen;

    // ── Ethernet Header (14 bytes) ────────────────────────────────────────────
    if (remaining < sizeof(struct ether_header)) return pkt;

    const auto* eth = reinterpret_cast<const struct ether_header*>(ptr);
    uint16_t eth_type = ntohs(eth->ether_type);
    pkt.eth_type = eth_type;

    ptr       += sizeof(struct ether_header);
    remaining -= sizeof(struct ether_header);

    // ── VLAN 802.1Q ───────────────────────────────────────────────────────────
    if (eth_type == 0x8100) {
        if (remaining < 4) return pkt;
        eth_type     = ntohs(*reinterpret_cast<const uint16_t*>(ptr + 2));
        pkt.eth_type = eth_type;
        ptr       += 4;
        remaining -= 4;
    }

    // ── IPv4 ──────────────────────────────────────────────────────────────────
    if (eth_type == ETHERTYPE_IP) {
        if (remaining < sizeof(struct ip)) return pkt;

        const auto* ip_hdr = reinterpret_cast<const struct ip*>(ptr);
        if (ip_hdr->ip_v != 4) return pkt;

        const size_t ip_hdr_len = ip_hdr->ip_hl * 4;
        if (ip_hdr_len < 20 || ip_hdr_len > remaining) return pkt;

        pkt.src_ip   = ip_hdr->ip_src.s_addr;
        pkt.dst_ip   = ip_hdr->ip_dst.s_addr;
        pkt.protocol = ip_hdr->ip_p;
        pkt.ttl      = ip_hdr->ip_ttl;

        ptr       += ip_hdr_len;
        remaining -= ip_hdr_len;

        parseTransport(pkt, ptr, remaining, data);
        return pkt;
    }

    // ── IPv6 ──────────────────────────────────────────────────────────────────
    if (eth_type == 0x86DD) {
        constexpr size_t IP6_HDR_LEN = 40;
        if (remaining < IP6_HDR_LEN) return pkt;

        const auto* ip6 = reinterpret_cast<const struct ip6_hdr*>(ptr);

        std::memcpy(pkt.src_ip6.data(), &ip6->ip6_src, 16);
        std::memcpy(pkt.dst_ip6.data(), &ip6->ip6_dst, 16);

        pkt.protocol  = ip6->ip6_nxt;
        pkt.hop_limit = ip6->ip6_hlim;
        pkt.ttl       = ip6->ip6_hlim;

        ptr       += IP6_HDR_LEN;
        remaining -= IP6_HDR_LEN;

        // ── IPv6 Extension Headers ────────────────────────────────────────────
        bool parsing_ext = true;
        while (parsing_ext && remaining >= 2) {
            switch (pkt.protocol) {
                case 0:    // Hop-by-Hop Options
                case 43:   // Routing
                case 60: { // Destination Options
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
                    parsing_ext = false;
                    break;
            }
        }

        parseTransport(pkt, ptr, remaining, data);
        return pkt;
    }

    // ── ARP / khác ────────────────────────────────────────────────────────────
    return pkt;
}
