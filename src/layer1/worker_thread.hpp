#pragma once
#include "../common/packet_info.hpp"
#include "../common/threat_types.hpp"
#include "flow_table.hpp"
#include "signature_engine.hpp"
#include "protocol_anomaly.hpp"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <functional>

// Callback type: được gọi khi phát hiện threat
using AlertCallback = std::function<void(const DetectionEvent&)>;

// Thread-safe packet queue
class PacketQueue {
public:
    explicit PacketQueue(size_t max_size = 4096);

    bool push(PacketInfo pkt);          // Non-blocking, false nếu đầy
    bool pop(PacketInfo& pkt,
             int timeout_ms = 100);     // Blocking với timeout

    size_t size() const;
    bool   empty() const;

private:
    std::queue<PacketInfo>  queue_;
    mutable std::mutex      mutex_;
    std::condition_variable cv_;
    size_t                  max_size_;
};

// Worker Thread: xử lý gói tin từ queue
class WorkerThread {
public:
    WorkerThread(int id, FlowTable& flow_table,
                 AlertCallback on_alert);
    ~WorkerThread();

    void start();
    void stop();
    bool isRunning() const { return running_; }

    // Nhận gói tin từ Dispatcher
    bool enqueue(PacketInfo pkt);

    int id() const { return id_; }

private:
    void run();
    void processPacket(PacketInfo& pkt);
    void handleDetection(const DetectionResult& result,
                         const PacketInfo&      pkt,
                         FlowState&             flow);

    int               id_;
    FlowTable&        flow_table_;
    AlertCallback     on_alert_;
    PacketQueue       queue_;
    SignatureEngine   sig_engine_;
    ProtocolAnomalyEngine anomaly_engine_;

    std::thread       thread_;
    std::atomic<bool> running_{false};
};
