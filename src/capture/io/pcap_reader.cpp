//src/capture/io/pcap_reader.cpp
#include "pcap_reader.hpp"
#include "../../common/logger.hpp"
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <pcap/pcap.h>
// pcap file magic numbers
static constexpr uint32_t PCAP_MAGIC_LE    = 0xa1b2c3d4; // Little-endian
static constexpr uint32_t PCAP_MAGIC_BE    = 0xd4c3b2a1; // Big-endian
static constexpr uint32_t PCAP_MAGIC_NS_LE = 0xa1b23c4d; // Nanosecond LE
static constexpr uint32_t PCAP_MAGIC_NS_BE = 0x4d3cb2a1; // Nanosecond BE

// pcap global header (24 bytes)
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// pcap packet header (16 bytes)
struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;   // hoặc nanoseconds nếu magic là NS variant
    uint32_t incl_len;
    uint32_t orig_len;
};

PcapReader::~PcapReader() {
    closeMmap();
}

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

// ─── Scan file với mmap ───────────────────────────────────────────────────────
bool PcapReader::scanFile(const std::string&  filepath,
                           PacketRingBuffer&   ring_buf,
                           ProgressCallback    on_progress,
                           std::atomic<bool>*  cancel_flag) {
    cancel_flag_ = cancel_flag;
    stats_       = PcapFileStats{};
    stats_.filepath = filepath;

    // ── mmap file ─────────────────────────────────────────────────────────────
    mmap_fd_ = ::open(filepath.c_str(), O_RDONLY);
    if (mmap_fd_ < 0) {
        LOG_ERROR("PcapReader: cannot open " + filepath);
        return false;
    }

    struct stat st;
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

    // MAP_PRIVATE + MADV_SEQUENTIAL — OS sẽ prefetch tuần tự
    mmap_ptr_ = mmap(nullptr, mmap_size_,
                     PROT_READ, MAP_PRIVATE,
                     mmap_fd_, 0);
    if (mmap_ptr_ == MAP_FAILED) {
        LOG_ERROR("PcapReader: mmap failed");
        closeMmap();
        return false;
    }

    // Hint cho kernel: đọc tuần tự
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

    stats_.snaplen   = swap32(gh->snaplen);
    stats_.linktype  = static_cast<int>(swap32(gh->network));

    // Linktype name
    const char* lt_name = pcap_datalink_val_to_name(stats_.linktype);
    stats_.linktype_name = lt_name ? lt_name : "UNKNOWN";

    LOG_INFO("PcapReader: scanning " + filepath
             + " linktype=" + stats_.linktype_name
             + " snaplen=" + std::to_string(stats_.snaplen));

    // ── Scan packets ──────────────────────────────────────────────────────────
    size_t   offset = sizeof(PcapGlobalHeader);
    uint64_t pkt_count = 0;

    // Đếm trước tổng số packets để tính progress
    // (scan nhanh chỉ đọc headers)
    uint64_t total_estimate = mmap_size_ / 100; // Ước lượng

    while (offset + sizeof(PcapPacketHeader) <= mmap_size_) {
        // Kiểm tra cancel
        if (cancel_flag_ && *cancel_flag_) {
            LOG_INFO("PcapReader: scan cancelled at packet "
                     + std::to_string(pkt_count));
            break;
        }

        auto* ph = reinterpret_cast<const PcapPacketHeader*>(
            data + offset);

        uint32_t incl_len = swap32(ph->incl_len);
        uint32_t orig_len = swap32(ph->orig_len);
        uint32_t ts_sec   = swap32(ph->ts_sec);
        uint32_t ts_frac  = swap32(ph->ts_usec);

        // Sanity check
        if (incl_len > stats_.snaplen + 4 || incl_len > 65535) {
            LOG_WARN("PcapReader: invalid incl_len="
                     + std::to_string(incl_len)
                     + " at offset=" + std::to_string(offset));
            break;
        }

        size_t pkt_data_offset = offset + sizeof(PcapPacketHeader);
        if (pkt_data_offset + incl_len > mmap_size_) break;

        // Build PacketRecord (chỉ metadata)
        PacketRecord record;
        record.cap_len     = incl_len;
        record.orig_len    = orig_len;
        record.file_offset = static_cast<int64_t>(pkt_data_offset);

        // Timestamp
        double ts_frac_sec = ns_mode
            ? ts_frac / 1e9
            : ts_frac / 1e6;
        record.timestamp = ts_sec + ts_frac_sec;

        // Parse L3/L4 headers (từ mmap — zero-copy)
        parseHeaders(record,
                     data + pkt_data_offset,
                     incl_len,
                     stats_.linktype);

        // Cập nhật stats
        stats_.total_packets++;
        stats_.total_bytes += incl_len;
        if (stats_.first_ts == 0.0) stats_.first_ts = record.timestamp;
        stats_.last_ts = record.timestamp;

        // Push vào ring buffer (không có raw_data — lazy)
        ring_buf.push(record);

        offset += sizeof(PcapPacketHeader) + incl_len;
        pkt_count++;

        // Progress callback mỗi 10000 packets
        if (on_progress && (pkt_count % 10000 == 0)) {
            double pct = std::min(
                100.0,
                static_cast<double>(offset) / mmap_size_ * 100.0
            );
            on_progress(pkt_count, total_estimate, pct);
        }
    }

    stats_.duration_sec = stats_.last_ts - stats_.first_ts;

    LOG_INFO("PcapReader: scan complete — "
             + std::to_string(stats_.total_packets) + " packets, "
             + std::to_string(stats_.total_bytes / 1024 / 1024) + " MB, "
             + std::to_string(stats_.duration_sec) + "s");

    // Giữ mmap mở để lazy-load raw bytes sau
    // closeMmap() sẽ được gọi khi PcapReader bị hủy
    return true;
}

// ─── Lazy load raw bytes cho một packet ──────────────────────────────────────
bool PcapReader::loadRawBytes(PacketRecord&      record,
                               const std::string& filepath) {
    if (record.file_offset < 0) return false;
    if (record.raw_data)        return true;  // Đã load rồi

    // Dùng mmap đang mở (nếu cùng file)
    if (mmap_ptr_ != MAP_FAILED && mmap_size_ > 0) {
        size_t end = static_cast<size_t>(record.file_offset)
                   + record.cap_len;
        if (end <= mmap_size_) {
            const uint8_t* src = static_cast<const uint8_t*>(mmap_ptr_)
                               + record.file_offset;
            record.raw_data = std::make_shared<std::vector<uint8_t>>(
                src, src + record.cap_len);
            return true;
        }
    }

    // Fallback: đọc từ file trực tiếp
    FILE* f = fopen(filepath.c_str(), "rb");
    if (!f) return false;

    fseek(f, record.file_offset, SEEK_SET);
    record.raw_data = std::make_shared<std::vector<uint8_t>>(
        record.cap_len);
    bool ok = (fread(record.raw_data->data(), 1,
                     record.cap_len, f) == record.cap_len);
    fclose(f);

    if (!ok) record.raw_data.reset();
    return ok;
}

// ─── Parse L3/L4 headers ─────────────────────────────────────────────────────
void PcapReader::parseHeaders(PacketRecord&   record,
                               const uint8_t* data,
                               uint32_t       len,
                               int            linktype) {
    size_t offset = 0;

    // ── Ethernet ──────────────────────────────────────────────────────────────
    if (linktype == DLT_EN10MB) {
        if (len < sizeof(struct ether_header)) return;
        auto* eth = reinterpret_cast<const struct ether_header*>(data);
        record.eth_type = ntohs(eth->ether_type);
        offset += sizeof(struct ether_header);

        // VLAN tag (802.1Q)
        if (record.eth_type == 0x8100 && offset + 4 <= len) {
            record.eth_type = ntohs(
                *reinterpret_cast<const uint16_t*>(data + offset + 2));
            offset += 4;
        }

        if (record.eth_type != ETHERTYPE_IP) return;
    }
    // Linux cooked capture (SLL)
    else if (linktype == DLT_LINUX_SLL) {
        if (len < 16) return;
        record.eth_type = ntohs(
            *reinterpret_cast<const uint16_t*>(data + 14));
        offset += 16;
        if (record.eth_type != ETHERTYPE_IP) return;
    }
    // Raw IP
    else if (linktype == DLT_RAW) {
        record.eth_type = ETHERTYPE_IP;
    }

    // ── IPv4 ──────────────────────────────────────────────────────────────────
    if (offset + sizeof(struct ip) > len) return;
    auto* ip_hdr = reinterpret_cast<const struct ip*>(data + offset);

    record.src_ip   = ip_hdr->ip_src.s_addr;
    record.dst_ip   = ip_hdr->ip_dst.s_addr;
    record.protocol = ip_hdr->ip_p;

    size_t ip_hdr_len = ip_hdr->ip_hl * 4;
    offset += ip_hdr_len;

    // ── TCP ───────────────────────────────────────────────────────────────────
    if (record.protocol == IPPROTO_TCP) {
        if (offset + sizeof(struct tcphdr) > len) return;
        auto* tcp = reinterpret_cast<const struct tcphdr*>(data + offset);
        record.src_port  = ntohs(tcp->th_sport);
        record.dst_port  = ntohs(tcp->th_dport);
        record.tcp_flags = tcp->th_flags;
        size_t tcp_hdr_len = tcp->th_off * 4;
        record.payload_len = (len > offset + tcp_hdr_len)
                           ? len - offset - tcp_hdr_len : 0;
    }
    // ── UDP ───────────────────────────────────────────────────────────────────
    else if (record.protocol == IPPROTO_UDP) {
        if (offset + sizeof(struct udphdr) > len) return;
        auto* udp = reinterpret_cast<const struct udphdr*>(data + offset);
        record.src_port  = ntohs(udp->uh_sport);
        record.dst_port  = ntohs(udp->uh_dport);
        record.payload_len = (ntohs(udp->uh_ulen) > 8)
                           ? ntohs(udp->uh_ulen) - 8 : 0;
    }
}
