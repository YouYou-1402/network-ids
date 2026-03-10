// ── pcap_writer.cpp ───────────────────────────────────────────────────────────
#include "pcap_writer.hpp"
#include "../common/logger.hpp"
#include <cstring>

PcapWriter::~PcapWriter() {
    close();
}

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
    bytes_written_   = 0;   // reset khi mở file mới
    LOG_INFO("PcapWriter: opened " + filepath);
    return true;
}

bool PcapWriter::writePacket(const uint8_t*        data,
                              uint32_t              cap_len,
                              uint32_t              orig_len,
                              const struct timeval& ts) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!dumper_) return false;

    struct pcap_pkthdr hdr;
    hdr.ts     = ts;
    hdr.caplen = cap_len;
    hdr.len    = orig_len;

    pcap_dump(reinterpret_cast<u_char*>(dumper_), &hdr, data);

    packets_written_++;
    bytes_written_ += PCAP_PACKET_HEADER_SIZE + cap_len; // ✅ FIX: +16 bytes packet header
    return true;
}

bool PcapWriter::writePacket(const PacketRecord& record) {
    if (!record.raw_data || record.raw_data->empty())
        return false;

    struct timeval ts;
    ts.tv_sec  = static_cast<time_t>(record.timestamp);
    ts.tv_usec = static_cast<suseconds_t>(
        (record.timestamp - static_cast<double>(ts.tv_sec)) * 1e6);

    return writePacket(
        record.raw_data->data(),
        record.cap_len,
        record.orig_len,
        ts
    );
}

void PcapWriter::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (dumper_) {
        pcap_dump_flush(dumper_);
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
        LOG_INFO("PcapWriter: closed " + filepath_
                 + " (" + std::to_string(packets_written_) + " packets"
                 + ", " + std::to_string(bytes_written_) + " bytes)");
    }
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}
