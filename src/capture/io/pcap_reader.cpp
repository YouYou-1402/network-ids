// src/capture/io/pcap_reader.cpp
#include "pcap_reader.hpp"
#include "../../common/logger.hpp"
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <atomic>

// ─── Global sequence counter (shared với ProtocolDecoder) ─────────────────────
// Dùng atomic riêng để capture_seq tăng dần liên tục
// kể cả khi mix live + offline
static std::atomic<uint64_t> g_pcap_reader_seq{0};

// ─── pcap magic numbers ───────────────────────────────────────────────────────
static constexpr uint32_t PCAP_MAGIC_LE    = 0xa1b2c3d4;
static constexpr uint32_t PCAP_MAGIC_BE    = 0xd4c3b2a1;
static constexpr uint32_t PCAP_MAGIC_NS_LE = 0xa1b23c4d;
static constexpr uint32_t PCAP_MAGIC_NS_BE = 0x4d3cb2a1;

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

// ═════════════════════════════════════════════════════════════════════════════
// Lifecycle
// ═════════════════════════════════════════════════════════════════════════════

PcapReader::~PcapReader() { closeMmap(); }

void PcapReader::closeMmap() {
    if (mmap_ptr_ != MAP_FAILED) {
        munmap(mmap_ptr_, mmap_size_);
        mmap_ptr_  = MAP_FAILED;
        mmap_size_ = 0;
    }
    if (mmap_fd_ >= 0) {
        ::close(mmap_fd_);
        mmap_fd_ = -1;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// prescanPacketCount
// ═════════════════════════════════════════════════════════════════════════════
uint64_t PcapReader::prescanPacketCount(const uint8_t* data,
                                         size_t         file_size,
                                         bool           swap_bytes) const {
    auto swap32 = [&](uint32_t v) -> uint32_t {
        return swap_bytes ? __builtin_bswap32(v) : v;
    };

    uint64_t count  = 0;
    size_t   offset = sizeof(PcapGlobalHeader);

    while (offset + sizeof(PcapPacketHeader) <= file_size) {
        auto* ph      = reinterpret_cast<const PcapPacketHeader*>(data + offset);
        uint32_t ilen = swap32(ph->incl_len);
        if (ilen > 65535) break;
        offset += sizeof(PcapPacketHeader) + ilen;
        ++count;
    }
    return count;
}

// ═════════════════════════════════════════════════════════════════════════════
// scanFile
// ═════════════════════════════════════════════════════════════════════════════
bool PcapReader::scanFile(const std::string&  filepath,
                           PacketRingBuffer&   ring_buf,
                           ProgressCallback    on_progress,
                           std::atomic<bool>*  cancel_flag) {
    cancel_flag_ = cancel_flag;
    stats_       = PcapFileStats{};
    stats_.filepath = filepath;

    // ── mmap ──────────────────────────────────────────────────────────────────
    mmap_fd_ = ::open(filepath.c_str(), O_RDONLY);
    if (mmap_fd_ < 0) {
        LOG_ERROR("PcapReader: cannot open " + filepath);
        return false;
    }

    struct stat st{};
    if (fstat(mmap_fd_, &st) < 0) {
        LOG_ERROR("PcapReader: fstat failed");
        closeMmap();
        return false;
    }

    mmap_size_ = static_cast<size_t>(st.st_size);
    if (mmap_size_ < sizeof(PcapGlobalHeader)) {
        LOG_ERROR("PcapReader: file too small");
        closeMmap();
        return false;
    }

    mmap_ptr_ = mmap(nullptr, mmap_size_,
                     PROT_READ, MAP_PRIVATE,
                     mmap_fd_, 0);
    if (mmap_ptr_ == MAP_FAILED) {
        LOG_ERROR("PcapReader: mmap failed");
        closeMmap();
        return false;
    }
    madvise(mmap_ptr_, mmap_size_, MADV_SEQUENTIAL);

    const uint8_t* data = static_cast<const uint8_t*>(mmap_ptr_);

    // ── Parse global header ───────────────────────────────────────────────────
    auto* gh = reinterpret_cast<const PcapGlobalHeader*>(data);

    bool swap_bytes = false;
    bool ns_mode    = false;

    switch (gh->magic_number) {
        case PCAP_MAGIC_LE:    swap_bytes = false; ns_mode = false; break;
        case PCAP_MAGIC_BE:    swap_bytes = true;  ns_mode = false; break;
        case PCAP_MAGIC_NS_LE: swap_bytes = false; ns_mode = true;  break;
        case PCAP_MAGIC_NS_BE: swap_bytes = true;  ns_mode = true;  break;
        default:
            LOG_ERROR("PcapReader: invalid magic number");
            closeMmap();
            return false;
    }

    auto swap32 = [&](uint32_t v) -> uint32_t {
        return swap_bytes ? __builtin_bswap32(v) : v;
    };

    stats_.snaplen  = swap32(gh->snaplen);
    stats_.linktype = static_cast<int>(swap32(gh->network));

    const char* lt_name = pcap_datalink_val_to_name(stats_.linktype);
    stats_.linktype_name = lt_name ? lt_name : "UNKNOWN";

    LOG_INFO("PcapReader: scanning " + filepath
             + " linktype=" + stats_.linktype_name
             + " snaplen=" + std::to_string(stats_.snaplen));

    const uint64_t total_packets = on_progress
        ? prescanPacketCount(data, mmap_size_, swap_bytes)
        : 0;

    // ── Scan packets ──────────────────────────────────────────────────────────
    size_t   offset    = sizeof(PcapGlobalHeader);
    uint64_t pkt_count = 0;

    while (offset + sizeof(PcapPacketHeader) <= mmap_size_) {
        if (cancel_flag_ && *cancel_flag_) {
            LOG_INFO("PcapReader: scan cancelled at packet "
                     + std::to_string(pkt_count));
            break;
        }

        auto* ph = reinterpret_cast<const PcapPacketHeader*>(data + offset);

        uint32_t incl_len = swap32(ph->incl_len);
        uint32_t orig_len = swap32(ph->orig_len);
        uint32_t ts_sec   = swap32(ph->ts_sec);
        uint32_t ts_frac  = swap32(ph->ts_usec);

        if (incl_len > 65535) {
            LOG_WARN("PcapReader: corrupt incl_len=" + std::to_string(incl_len)
                     + " at offset=" + std::to_string(offset));
            break;
        }

        const size_t pkt_data_offset = offset + sizeof(PcapPacketHeader);
        if (pkt_data_offset + incl_len > mmap_size_) break;

        // ── Build PacketInfo ──────────────────────────────────────────────────
        PacketInfo record;
        record.cap_len     = incl_len;
        record.orig_len    = orig_len;
        record.file_offset = static_cast<int64_t>(pkt_data_offset);

        // ── FIX BUG 2: capture_seq tăng dần ──────────────────────────────────
        record.capture_seq = g_pcap_reader_seq.fetch_add(
                                 1, std::memory_order_relaxed);

        // Timestamp
        const double ts_frac_sec = ns_mode
            ? static_cast<double>(ts_frac) / 1e9
            : static_cast<double>(ts_frac) / 1e6;
        record.timestamp.tv_sec  = static_cast<time_t>(ts_sec);
        record.timestamp.tv_usec = ns_mode
            ? static_cast<suseconds_t>(ts_frac / 1000)
            : static_cast<suseconds_t>(ts_frac);
        record.timestamp_d = static_cast<double>(ts_sec) + ts_frac_sec;

        // ── FIX BUG 1: copy raw bytes ─────────────────────────────────────────
        // raw_data phải có trước parseHeaders để HexView hoạt động
        // và để payload() helper trả về đúng pointer
        const uint8_t* pkt_data = data + pkt_data_offset;
        record.raw_data = std::make_shared<std::vector<uint8_t>>(
                              pkt_data, pkt_data + incl_len);

        // Parse L3/L4 headers
        parseHeaders(record,
                     pkt_data,
                     incl_len,
                     stats_.linktype);

        // Stats
        stats_.total_packets++;
        stats_.total_bytes += incl_len;
        if (stats_.first_ts == 0.0) stats_.first_ts = record.timestamp_d;
        stats_.last_ts = record.timestamp_d;

        ring_buf.push(record);

        offset += sizeof(PcapPacketHeader) + incl_len;
        ++pkt_count;

        if (on_progress && (pkt_count % 10'000 == 0)) {
            const double pct = (total_packets > 0)
                ? static_cast<double>(pkt_count) / total_packets * 100.0
                : static_cast<double>(offset) / mmap_size_ * 100.0;
            on_progress(pkt_count, total_packets, std::min(pct, 100.0));
        }
    }

    if (on_progress)
        on_progress(pkt_count, total_packets, 100.0);

    stats_.duration_sec = stats_.last_ts - stats_.first_ts;

    LOG_INFO("PcapReader: scan complete — "
             + std::to_string(stats_.total_packets) + " packets, "
             + std::to_string(stats_.total_bytes / 1024 / 1024) + " MB, "
             + std::to_string(stats_.duration_sec) + "s");

    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// loadRawBytes
// ═════════════════════════════════════════════════════════════════════════════
bool PcapReader::loadRawBytes(PacketInfo&        record,
                               const std::string& filepath) {
    if (record.file_offset < 0) return false;
    if (record.raw_data)        return true;   // đã có

    if (mmap_ptr_ != MAP_FAILED) {
        const size_t end = static_cast<size_t>(record.file_offset)
                         + record.cap_len;
        if (end <= mmap_size_) {
            const uint8_t* src = static_cast<const uint8_t*>(mmap_ptr_)
                               + record.file_offset;
            record.raw_data = std::make_shared<std::vector<uint8_t>>(
                src, src + record.cap_len);
            return true;
        }
    }

    FILE* f = fopen(filepath.c_str(), "rb");
    if (!f) return false;
    fseek(f, record.file_offset, SEEK_SET);
    record.raw_data = std::make_shared<std::vector<uint8_t>>(record.cap_len);
    const bool ok = (fread(record.raw_data->data(), 1,
                           record.cap_len, f) == record.cap_len);
    fclose(f);
    if (!ok) record.raw_data.reset();
    return ok;
}

// ═════════════════════════════════════════════════════════════════════════════
// loadRawRange
// ═════════════════════════════════════════════════════════════════════════════
bool PcapReader::loadRawRange(std::vector<PacketInfo>& records,
                               const std::string&       filepath) {
    if (records.empty()) return true;
    bool all_ok = true;
    for (auto& pkt : records) {
        if (!loadRawBytes(pkt, filepath))
            all_ok = false;
    }
    return all_ok;
}

// ═════════════════════════════════════════════════════════════════════════════
// parseHeaders
// ═════════════════════════════════════════════════════════════════════════════
void PcapReader::parseHeaders(PacketInfo&    record,
                               const uint8_t* data,
                               uint32_t       len,
                               int            linktype) {
    size_t offset = 0;

    // ── Layer 2 ───────────────────────────────────────────────────────────────
    if (linktype == DLT_EN10MB) {
        if (len < sizeof(struct ether_header)) return;
        auto* eth = reinterpret_cast<const struct ether_header*>(data);
        record.eth_type = ntohs(eth->ether_type);
        offset += sizeof(struct ether_header);

        // VLAN 802.1Q / QinQ
        while ((record.eth_type == 0x8100 || record.eth_type == 0x88A8)
               && offset + 4 <= len) {
            record.eth_type = ntohs(
                *reinterpret_cast<const uint16_t*>(data + offset + 2));
            offset += 4;
        }
    }
    else if (linktype == DLT_LINUX_SLL) {
        // Linux cooked capture: 16 bytes header, eth_type tại offset 14
        if (len < 16) return;
        record.eth_type = ntohs(
            *reinterpret_cast<const uint16_t*>(data + 14));
        offset = 16;
    }
    else if (linktype == DLT_RAW) {
        if (len < 1) return;
        const uint8_t version = (data[0] >> 4) & 0xF;
        record.eth_type = (version == 6)
            ? static_cast<uint16_t>(0x86DD)
            : static_cast<uint16_t>(ETHERTYPE_IP);
        offset = 0;
    }
    else {
        // Linktype không hỗ trợ — không parse
        return;
    }

    // ── IPv4 ──────────────────────────────────────────────────────────────────
    if (record.eth_type == ETHERTYPE_IP) {
        if (offset + sizeof(struct ip) > len) return;
        auto* iph = reinterpret_cast<const struct ip*>(data + offset);
        if (iph->ip_v != 4) return;

        record.src_ip   = iph->ip_src.s_addr;   // network byte order
        record.dst_ip   = iph->ip_dst.s_addr;
        record.protocol = iph->ip_p;
        record.ttl      = iph->ip_ttl;
        record.is_ipv6  = false;                 // explicit

        const size_t ip_hdr_len = iph->ip_hl * 4;
        if (ip_hdr_len < 20 || ip_hdr_len > len - offset) return;
        offset += ip_hdr_len;
    }
    // ── IPv6 ──────────────────────────────────────────────────────────────────
    else if (record.eth_type == 0x86DD) {
        constexpr size_t IP6H = sizeof(struct ip6_hdr);   // 40 bytes
        if (offset + IP6H > len) return;
        auto* ip6 = reinterpret_cast<const struct ip6_hdr*>(data + offset);

        std::memcpy(record.src_ip6.data(), &ip6->ip6_src, 16);
        std::memcpy(record.dst_ip6.data(), &ip6->ip6_dst, 16);
        record.protocol  = ip6->ip6_nxt;
        record.hop_limit = ip6->ip6_hlim;
        record.ttl       = ip6->ip6_hlim;
        record.is_ipv6   = true;                          // ← FIX BUG 3

        offset += IP6H;

        // Extension headers — giống packet_capture.cpp
        bool cont = true;
        while (cont && offset + 2 <= len) {
            switch (record.protocol) {
                case 0: case 43: case 60: {
                    const size_t ext =
                        static_cast<size_t>(data[offset + 1] + 1) * 8;
                    if (offset + ext > len) { cont = false; break; }
                    record.protocol = data[offset];
                    offset += ext;
                    break;
                }
                case 44:
                    if (offset + 8 > len) { cont = false; break; }
                    record.protocol = data[offset];
                    offset += 8;
                    break;
                case 50: case 51:
                    record.is_encrypted = true;
                    cont = false;
                    break;
                default:
                    cont = false;
                    break;
            }
        }
    }
    else {
        return;   // ARP, VLAN bare, ... — không parse L4
    }

    // ── Layer 4 ───────────────────────────────────────────────────────────────
    if (record.protocol == IPPROTO_TCP) {
        if (offset + sizeof(struct tcphdr) > len) return;
        auto* tcp = reinterpret_cast<const struct tcphdr*>(data + offset);

        record.src_port  = ntohs(tcp->th_sport);
        record.dst_port  = ntohs(tcp->th_dport);
        record.tcp_flags = tcp->th_flags;
        record.seq_num   = ntohl(tcp->th_seq);
        record.ack_num   = ntohl(tcp->th_ack);
        record.win_size  = ntohs(tcp->th_win);

        const size_t tcp_hdr_len = tcp->th_off * 4;
        if (tcp_hdr_len < 20 || offset + tcp_hdr_len > len) return;

        record.payload_offset = static_cast<uint32_t>(offset + tcp_hdr_len);
        record.payload_len    = static_cast<uint32_t>(
                                    len - offset - tcp_hdr_len);
    }
    else if (record.protocol == IPPROTO_UDP) {
        if (offset + sizeof(struct udphdr) > len) return;
        auto* udp = reinterpret_cast<const struct udphdr*>(data + offset);

        record.src_port       = ntohs(udp->uh_sport);
        record.dst_port       = ntohs(udp->uh_dport);
        record.payload_offset = static_cast<uint32_t>(
                                    offset + sizeof(struct udphdr));
        record.payload_len    = (ntohs(udp->uh_ulen) > 8)
                                ? ntohs(udp->uh_ulen) - 8 : 0;
    }
    else if (record.protocol == IPPROTO_ICMP
          || record.protocol == IPPROTO_ICMPV6) {
        record.payload_offset = static_cast<uint32_t>(offset);
        record.payload_len    = static_cast<uint32_t>(
                                    len > offset ? len - offset : 0);
    }
}
