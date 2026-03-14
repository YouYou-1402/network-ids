// src/capture/packet_capture.hpp
#pragma once

#include "../core/packet_info.hpp"
#include <pcap.h>
#include <functional>
#include <string>
#include <atomic>
#include <thread>   // FIX BUG 3

using PacketCallback = std::function<void(PacketInfo)>;

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();

    PacketCapture(const PacketCapture&)            = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    /// Live capture từ network interface
    /// bpf_filter mặc định rỗng = bắt tất cả
    bool openLive(const std::string& interface,
                  const std::string& bpf_filter = "");

    /// Offline capture từ .pcap file
    bool openOffline(const std::string& pcap_file,
                     const std::string& bpf_filter = "");

    // FIX BUG 3: startCapture() không blocking — pcap_loop chạy trên thread riêng
    // Trả về ngay sau khi thread được spawn
    // Gọi stopCapture() + waitForStop() để dừng sạch
    void startCapture(PacketCallback callback);

    /// Dừng capture (thread-safe, non-blocking)
    void stopCapture();

    /// Chờ capture thread kết thúc (blocking)
    void waitForStop();

    void logStats() const;

    bool isOpen()    const { return handle_   != nullptr; }
    bool isRunning() const { return running_.load(); }

private:
    // libpcap static callback — được gọi từ pcap_loop trên capture_thread_
    static void pcapCallback(u_char*                   user,
                              const struct pcap_pkthdr* header,
                              const u_char*             packet);

    // Parse raw bytes → PacketInfo
    // payload_offset tính từ đầu frame (= đầu raw_data)
    static PacketInfo parsePacket(const u_char*             data,
                                   const struct pcap_pkthdr* header);

    // Áp dụng BPF filter lên handle_ đang mở
    bool applyFilter(const std::string& bpf_filter);

    // Thread body — chạy pcap_loop
    void captureLoop();

    pcap_t*           handle_          = nullptr;
    PacketCallback    callback_;
    std::atomic<bool> running_         {false};
    std::thread       capture_thread_;   // FIX BUG 3
};
