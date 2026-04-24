//src/detection/worker_thread.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "../capture/io/packet_ring_buffer.hpp"
#include "../firewall/firewall_manager.hpp"
#include "../ml/data_queue.hpp"
#include "../ml/feature_extractor.hpp"
#include "flow_table.hpp"
#include "ip_tracker.hpp"
#include "signature_engine.hpp"
#include "protocol_anomaly.hpp"
#include "behavioral_engine.hpp"
#include "action_handler.hpp"
#include <vector>
#include <atomic>
#include <thread>
#include <functional>

using AlertCallback = std::function<void(const DetectionEvent&)>;

// =============================================================================
//  PacketQueue — SPSC lock-free ring buffer
// =============================================================================
class PacketQueue {
public:
    explicit PacketQueue(size_t max_size = 65536);

    bool   push(PacketInfo pkt);
    bool   pop (PacketInfo& pkt);
    size_t size()     const;
    bool   empty()    const;
    size_t capacity() const { return max_size_; }

private:
    size_t                  max_size_;
    size_t                  mask_;
    std::vector<PacketInfo> buf_;

    alignas(64) std::atomic<size_t> head_{0};
    char pad0_[64 - sizeof(std::atomic<size_t>)];
    alignas(64) std::atomic<size_t> tail_{0};
    char pad1_[64 - sizeof(std::atomic<size_t>)];
};

// =============================================================================
//  WorkerThread
//
//  Pipeline per packet:
//    1.  parsePacket()          — parse nếu chưa parse
//    2.  flow lookup            — getOrCreate FlowState
//    2b. update ML features     — fwd/bwd bytes, Welford's IAT  ← MỚI
//    3.  Firewall quickCheck    — WHITELIST=skip / BLACKLIST=drop
//    4.  Detection guard        — skip nếu detection_enabled=false
//    5.  SignatureEngine        — DDoS rate, Port Scan, Flag abuse, Payload
//    6.  ProtocolAnomalyEngine  — Slow DDoS (HTTP port)
//    7.  BehavioralEngine       — HTTP Flood, SYN no-handshake, Dist scan
//    8.  ActionHandler          — quyết định DROP/ALERT/PASS
//    9.  ring_buf_.updateRecord — ghi threat/action vào slot
//    10. on_alert_()            — callback → AlertManager
//    11. autoBlock(src_ip)      — kernel firewall
//    12. ML sampling            — push MLJob vào MLJobQueue (mỗi 10/50 pkts)
// =============================================================================
class WorkerThread {
public:
    WorkerThread(int               id,
                 FlowTable&        flow_table,
                 IpTracker&        ip_tracker,
                 AlertCallback     on_alert,
                 PacketRingBuffer& ring_buf,
                 MLJobQueue*       ml_job_queue = nullptr);
    ~WorkerThread();

    WorkerThread(const WorkerThread&)            = delete;
    WorkerThread& operator=(const WorkerThread&) = delete;

    void start();
    void stop();

    bool   enqueue     (PacketInfo pkt);
    bool   isRunning   () const { return running_.load(std::memory_order_relaxed); }
    int    id          () const { return id_; }
    size_t queueSize   () const { return queue_.size(); }
    size_t queueDropped() const { return queue_dropped_.load(std::memory_order_relaxed); }

    // Firewall integration — set trước khi gọi start()
    void setFirewallManager(FirewallManager* fw) { firewall_manager_ = fw; }
    FirewallManager* firewallManager() const     { return firewall_manager_; }

    // ML integration — set trước khi gọi start()
    void setMLJobQueue(MLJobQueue* q) { ml_job_queue_ = q; }
    MLJobQueue* mlJobQueue() const    { return ml_job_queue_; }

private:
    void run();
    void processPacket  (PacketInfo& pkt);
    void handleDetection(DetectionResult    result,
                         DetectionSource    source,
                         const PacketInfo&  pkt,
                         FlowState&         flow);

    bool shouldSampleForML(const FlowState& flow) const;
    void pushMLJob(const PacketInfo&  pkt,
                   const FlowState&   flow,
                   const std::string& flow_key);

    int               id_;
    FlowTable&        flow_table_;
    AlertCallback     on_alert_;
    PacketRingBuffer& ring_buf_;

    PacketQueue           queue_;
    SignatureEngine       sig_engine_;
    ProtocolAnomalyEngine anomaly_engine_;
    BehavioralEngine      behavioral_engine_;
    ActionHandler         action_handler_;
    FeatureExtractor      feature_extractor_;

    

    FirewallManager* firewall_manager_ = nullptr;
    MLJobQueue*      ml_job_queue_     = nullptr;

    std::thread           thread_;
    std::atomic<bool>     running_      {false};
    std::atomic<size_t>   queue_dropped_{0};
    FlowWindowCounter window_counter_;
};
