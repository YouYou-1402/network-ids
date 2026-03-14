// src/dêtction/worker_thread.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "../capture/io/packet_ring_buffer.hpp"
#include "flow_table.hpp"
#include "signature_engine.hpp"
#include "protocol_anomaly.hpp"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <functional>

// ─── AlertCallback ────────────────────────────────────────────────────────────
using AlertCallback = std::function<void(const DetectionEvent&)>;

// ─── PacketQueue ──────────────────────────────────────────────────────────────
class PacketQueue {
public:
    explicit PacketQueue(size_t max_size = 4096);

    bool   push(PacketInfo pkt);
    bool   pop (PacketInfo& pkt, int timeout_ms = 100);
    size_t size()  const;
    bool   empty() const;

private:
    std::queue<PacketInfo>  queue_;
    mutable std::mutex      mutex_;
    std::condition_variable cv_;
    size_t                  max_size_;
};

// ─── WorkerThread ─────────────────────────────────────────────────────────────
class WorkerThread {
public:
    WorkerThread(int              id,
                 FlowTable&       flow_table,
                 AlertCallback    on_alert,
                 PacketRingBuffer& ring_buf);
    ~WorkerThread();

    void start();
    void stop();
    bool isRunning() const { return running_.load(); }
    bool enqueue(PacketInfo pkt);
    int  id()      const { return id_; }

private:
    void run();
    void processPacket(PacketInfo& pkt);
    void handleDetection(const DetectionResult& result,
                         const PacketInfo&      pkt,
                         FlowState&             flow);


    int               id_;
    FlowTable&        flow_table_;
    AlertCallback     on_alert_;
    PacketRingBuffer& ring_buf_;
    PacketQueue       queue_;
    SignatureEngine        sig_engine_;
    ProtocolAnomalyEngine  anomaly_engine_;
    std::thread       thread_;
    std::atomic<bool> running_{false};
};
