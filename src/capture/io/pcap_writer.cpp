// src/capture/io/pcap_writer.cpp
#include "pcap_writer.hpp"
#include "../../common/logger.hpp"
#include <cstring>

PcapWriter::~PcapWriter() {
    close();
}

// ═════════════════════════════════════════════════════════════════════════════
// open
// ═════════════════════════════════════════════════════════════════════════════
bool PcapWriter::open(const std::string& filepath,
                      int                snaplen,
                      int                linktype) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (dumper_) {
        LOG_WARN("PcapWriter: already open, close first");
        return false;
    }

    handle_ = pcap_open_dead(linktype, snaplen);
    if (!handle_) {
        LOG_ERROR("PcapWriter: pcap_open_dead failed");
        return false;
    }

    dumper_ = pcap_dump_open(handle_, filepath.c_str());
    if (!dumper_) {
        LOG_ERROR("PcapWriter: cannot open file: " + filepath
                  + " — " + std::string(pcap_geterr(handle_)));
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }

    filepath_        = filepath;
    packets_written_ = 0;
    bytes_written_   = 0;
    LOG_INFO("PcapWriter: opened " + filepath);
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// writePacket
// ═════════════════════════════════════════════════════════════════════════════
// Trả về data_offset = vị trí DATA trong file (bỏ qua PcapPacketHeader 16B)
// Đây là giá trị đúng để gán vào pkt.file_offset cho lazy-load
//
// Layout trong file:
//   [24B global header]
//   [16B PcapPacketHeader] ← bytes_written_ trước khi ghi header
//   [cap_len bytes DATA]   ← data_offset = PCAP_GLOBAL_HEADER_SIZE
//                                        + bytes_written_
//                                        + PCAP_PACKET_HEADER_SIZE
//   [16B PcapPacketHeader]
//   [cap_len bytes DATA]
//   ...
int64_t PcapWriter::writePacket(const uint8_t*        data,
                                 uint32_t              cap_len,
                                 uint32_t              orig_len,
                                 const struct timeval& ts) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!dumper_) return -1;

    // Tính data_offset TRƯỚC khi ghi
    // = global_header(24) + bytes_written_so_far + packet_header(16)
    const int64_t data_offset =
        static_cast<int64_t>(PCAP_GLOBAL_HEADER_SIZE)
        + static_cast<int64_t>(bytes_written_)
        + static_cast<int64_t>(PCAP_PACKET_HEADER_SIZE);

    struct pcap_pkthdr hdr;
    hdr.ts     = ts;
    hdr.caplen = cap_len;
    hdr.len    = orig_len;

    pcap_dump(reinterpret_cast<u_char*>(dumper_), &hdr, data);

    ++packets_written_;
    bytes_written_ += PCAP_PACKET_HEADER_SIZE + cap_len;

    return data_offset;
}

// ─── Overload từ PacketInfo ───────────────────────────────────────────────────
int64_t PcapWriter::writePacket(const PacketInfo& record) {
    if (!record.raw_data || record.raw_data->empty())
        return -1;

    return writePacket(
        record.raw_data->data(),
        record.cap_len,
        record.orig_len,
        record.timestamp
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// flush
// ═════════════════════════════════════════════════════════════════════════════
void PcapWriter::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (dumper_)
        pcap_dump_flush(dumper_);
}

// ═════════════════════════════════════════════════════════════════════════════
// close
// ═════════════════════════════════════════════════════════════════════════════
void PcapWriter::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (dumper_) {
        pcap_dump_flush(dumper_);
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
        LOG_INFO("PcapWriter: closed " + filepath_
                 + " (" + std::to_string(packets_written_) + " packets"
                 + ", " + std::to_string(bytes_written_)   + " bytes)");
    }
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}
