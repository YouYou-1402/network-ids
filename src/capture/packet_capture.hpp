// src/pcap_io/packet_capture.hpp
#pragma once

#include "../common/packet_info.hpp"
#include <pcap.h>
#include <functional>
#include <string>
#include <atomic>

using PacketCallback = std::function<void(PacketInfo)>;

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();

    // Không cho copy
    PacketCapture(const PacketCapture&)            = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    /// Live capture từ network interface
    /// bpf_filter mặc định rỗng = bắt tất cả
    bool openLive(const std::string& interface,
                  const std::string& bpf_filter = "");

    /// Offline capture từ .pcap file
    bool openOffline(const std::string& pcap_file,
                     const std::string& bpf_filter = "");

    /// Bắt đầu capture (blocking) — gọi callback cho mỗi gói tin
    void startCapture(PacketCallback callback);

    /// Dừng capture (thread-safe)
    void stopCapture();

    bool isOpen()    const { return handle_  != nullptr; }
    bool isRunning() const { return running_.load(); }

private:
    // libpcap static callback
    static void pcapCallback(u_char*                   user,
                              const struct pcap_pkthdr* header,
                              const u_char*             packet);

    // Parse raw bytes → PacketInfo
    static PacketInfo parsePacket(const u_char*             data,
                                   const struct pcap_pkthdr* header);

    // Áp dụng BPF filter lên handle_ đang mở
    bool applyFilter(const std::string& bpf_filter);

    pcap_t*           handle_   = nullptr;
    PacketCallback    callback_;
    std::atomic<bool> running_  {false};
};
