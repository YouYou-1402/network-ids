#pragma once
#include "../core/packet_info.hpp"
#include <pcap.h>
#include <functional>
#include <string>
#include <atomic>
#include <thread>

using RawPacketCallback = std::function<void(PacketInfo        pkt,
                                              const uint8_t*    raw_bytes,
                                              uint32_t          raw_len)>;

using PacketCallback = RawPacketCallback;

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

    void startCapture(RawPacketCallback callback);
    void stopCapture();
    void waitForStop();
    void logStats() const;

    bool isOpen()    const { return handle_ != nullptr; }
    bool isRunning() const { return running_.load(); }

    // ── Parse API (public — WorkerThread dùng) ────────────────────────────────

    // Overload 1: WorkerThread — pkt đã có raw_data (copy từ callback)
    static void parsePacket(PacketInfo& pkt) {
        if (!pkt.raw_data || pkt.raw_data->empty()) return;
        parsePacket(pkt,
                    pkt.raw_data->data(),
                    static_cast<uint32_t>(pkt.raw_data->size()));
    }

    // Overload 2: pcapCallback — raw pointer tạm, không copy
    static void parsePacket(PacketInfo&    pkt,
                             const uint8_t* data,
                             uint32_t       cap_len);

private:
    static void pcapCallback  (u_char*                   user,
                                const struct pcap_pkthdr* header,
                                const u_char*             packet);

    static void parseTransport(PacketInfo&    pkt,
                                const uint8_t* ptr,
                                size_t         remaining,
                                const uint8_t* frame_start);

    bool applyFilter(const std::string& bpf_filter);
    void captureLoop();

    pcap_t*           handle_  = nullptr;
    RawPacketCallback callback_;
    std::atomic<bool> running_ {false};
    std::thread       capture_thread_;
};
