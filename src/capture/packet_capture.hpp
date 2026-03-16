// src/capture/packet_capture.hpp
#pragma once
#include "../core/packet_info.hpp"
#include <pcap.h>
#include <functional>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>

using PacketCallback = std::function<void(PacketInfo)>;

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();

    PacketCapture(const PacketCapture&)            = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    bool openLive   (const std::string& interface,
                     const std::string& bpf_filter = "");
    bool openOffline(const std::string& pcap_file,
                     const std::string& bpf_filter = "");

    void startCapture(PacketCallback callback);
    void stopCapture();
    void waitForStop();
    void logStats() const;

    bool isOpen()    const { return handle_ != nullptr; }
    bool isRunning() const { return running_.load(); }

    // Parse in-place từ raw_data — gọi sau pcapCallback
    // Public vì WorkerThread (detection) cũng cần gọi
    static void parsePacket   (PacketInfo& pkt);

private:
    static void pcapCallback  (u_char*                   user,
                                const struct pcap_pkthdr* header,
                                const u_char*             packet);

    static void parseTransport(PacketInfo&   pkt,
                                const u_char* ptr,
                                size_t        remaining,
                                const u_char* frame_start);

    bool applyFilter(const std::string& bpf_filter);
    void captureLoop();

    pcap_t*           handle_  = nullptr;
    PacketCallback    callback_;
    std::atomic<bool> running_ {false};
    std::thread       capture_thread_;
};
