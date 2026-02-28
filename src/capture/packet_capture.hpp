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

    // Live capture từ network interface
    bool openLive(const std::string& interface,
                  const std::string& bpf_filter = "tcp or udp");

    // Offline capture từ .pcap file (dùng trong lab)
    bool openOffline(const std::string& pcap_file,
                     const std::string& bpf_filter = "");

    // Bắt đầu capture, gọi callback cho mỗi gói tin
    void startCapture(PacketCallback callback);

    // Dừng capture
    void stopCapture();

    bool isOpen() const { return handle_ != nullptr; }

private:
    // libpcap callback (static)
    static void pcapCallback(u_char*                  user,
                             const struct pcap_pkthdr* header,
                             const u_char*             packet);

    // Parse raw bytes → PacketInfo
    static PacketInfo parsePacket(const u_char*             data,
                                  const struct pcap_pkthdr* header);

    pcap_t*          handle_   = nullptr;
    PacketCallback   callback_;
    std::atomic<bool> running_ {false};
};
