// src/detection/worker_thread.cpp
#include "worker_thread.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"
#include "../common/engine_config.hpp"
#include "../capture/packet_capture.hpp"

// ═══════════════════════════════════════════════════════════════════════════════
// PacketQueue
// ═══════════════════════════════════════════════════════════════════════════════

PacketQueue::PacketQueue(size_t max_size)
    : max_size_(max_size), mask_(max_size - 1)
{
    // Round up to power of 2
    if (max_size == 0 || (max_size & (max_size - 1)) != 0) {
        size_t p = 1;
        while (p < max_size) p <<= 1;
        max_size_ = p;
        mask_     = p - 1;
        LOG_WARN("PacketQueue: round up → " + std::to_string(p));
    }
    buf_.resize(max_size_);
}

bool PacketQueue::push(PacketInfo pkt) {
    const size_t h    = head_.load(std::memory_order_relaxed);
    const size_t next = (h + 1) & mask_;
    if (next == tail_.load(std::memory_order_acquire))
        return false;   // full
    buf_[h] = std::move(pkt);
    head_.store(next, std::memory_order_release);
    return true;
}

bool PacketQueue::pop(PacketInfo& pkt) {
    const size_t t = tail_.load(std::memory_order_relaxed);
    if (t == head_.load(std::memory_order_acquire))
        return false;   // empty
    pkt = std::move(buf_[t]);
    tail_.store((t + 1) & mask_, std::memory_order_release);
    return true;
}

size_t PacketQueue::size() const {
    const size_t h = head_.load(std::memory_order_acquire);
    const size_t t = tail_.load(std::memory_order_acquire);
    return (h - t) & mask_;
}

bool PacketQueue::empty() const {
    return head_.load(std::memory_order_acquire)
        == tail_.load(std::memory_order_acquire);
}

// ═══════════════════════════════════════════════════════════════════════════════
// WorkerThread
// ═══════════════════════════════════════════════════════════════════════════════

WorkerThread::WorkerThread(int               id,
                            FlowTable&        flow_table,
                            IpTracker&        ip_tracker,
                            AlertCallback     on_alert,
                            PacketRingBuffer& ring_buf)
    : id_               (id)
    , flow_table_       (flow_table)
    , on_alert_         (std::move(on_alert))
    , ring_buf_         (ring_buf)
    , queue_            (65536)
    , sig_engine_       (ip_tracker)
    , anomaly_engine_   (ip_tracker)
    , behavioral_engine_(ip_tracker)
{}

WorkerThread::~WorkerThread() { stop(); }

void WorkerThread::start() {
    running_ = true;
    thread_  = std::thread(&WorkerThread::run, this);
    LOG_INFO("WorkerThread " + std::to_string(id_) + " started");
}

void WorkerThread::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
    LOG_INFO("WorkerThread " + std::to_string(id_) + " stopped");
}

bool WorkerThread::enqueue(PacketInfo pkt) {
    if (queue_.push(std::move(pkt))) return true;
    queue_dropped_.fetch_add(1, std::memory_order_relaxed);
    METRICS.queue_drops.fetch_add(1, std::memory_order_relaxed);
    return false;
}

// ─── run ──────────────────────────────────────────────────────────────────────
void WorkerThread::run() {
    LOG_INFO("WorkerThread " + std::to_string(id_) + " running");

    constexpr int BATCH = 64;
    PacketInfo    batch[BATCH];
    int           idle_spins = 0;

    while (running_.load(std::memory_order_relaxed)) {
        int count = 0;
        while (count < BATCH && queue_.pop(batch[count]))
            ++count;

        if (count == 0) {
            ++idle_spins;
            if      (idle_spins < 16)  { /* spin */                                       }
            else if (idle_spins < 256) { std::this_thread::yield();                       }
            else {
                std::this_thread::sleep_for(std::chrono::microseconds(50));
                idle_spins = 128;   // reset về yield level
            }
            continue;
        }

        idle_spins = 0;
        for (int i = 0; i < count; ++i)
            processPacket(batch[i]);
    }
}

// ─── processPacket ────────────────────────────────────────────────────────────
void WorkerThread::processPacket(PacketInfo& pkt) {

    // ── 1. Parse nếu chưa parse ───────────────────────────────────────────────
    if (pkt.raw_data && pkt.eth_type == 0)
        PacketCapture::parsePacket(pkt);

    // ── 2. Flow lookup ────────────────────────────────────────────────────────
    const std::string key  = pkt.flowKey();
    FlowState*        flow = flow_table_.getOrCreate(key, pkt);

    if (!flow) {
        // FlowTable đầy → DROP
        METRICS.packets_dropped.fetch_add(1, std::memory_order_relaxed);
        ring_buf_.updateRecord(pkt.index, [](PacketInfo& slot) {
            slot.action = "DROP";
        });
        return;
    }

    // ── 3. Detection (chỉ khi enabled) ───────────────────────────────────────
    if (!ENGINE_CFG.detection_enabled.load(std::memory_order_relaxed)) {
        METRICS.packets_passed.fetch_add(1, std::memory_order_relaxed);
        ring_buf_.updateRecord(pkt.index, [](PacketInfo& slot) {
            slot.action = "PASS";
        });
        return;
    }

    // Layer 1a: Signature (DDoS rate, Port Scan, Flag abuse, Payload)
    DetectionResult result = sig_engine_.analyze(pkt, *flow);
    DetectionSource source = DetectionSource::LAYER1_SIGNATURE;

    // Layer 1b: Protocol Anomaly (Slow DDoS — HTTP port)
    if (result == DetectionResult::NORMAL) {
        result = anomaly_engine_.analyze(pkt, *flow);
        source = DetectionSource::LAYER1_PROTOCOL_ANOMALY;
    }

    // Layer 1c: Behavioral (HTTP Flood, SYN no-handshake, Dist scan)
    if (result == DetectionResult::NORMAL) {
        result = behavioral_engine_.analyze(pkt, *flow);
        source = DetectionSource::LAYER1_BEHAVIORAL;
    }

    // ── 4. Action ─────────────────────────────────────────────────────────────
    if (result != DetectionResult::NORMAL) {
        handleDetection(result, source, pkt, *flow);

        const std::string threat = threatToString(result);
        const std::string action = actionToString(action_handler_.decide(result));

        ring_buf_.updateRecord(pkt.index, [&](PacketInfo& slot) {
            slot.threat_type = threat;
            slot.action      = action;
        });
        return;
    }

    // ── 5. Normal ─────────────────────────────────────────────────────────────
    METRICS.packets_passed.fetch_add(1, std::memory_order_relaxed);
    ring_buf_.updateRecord(pkt.index, [](PacketInfo& slot) {
        slot.action = "PASS";
    });
}

// ─── handleDetection ──────────────────────────────────────────────────────────
void WorkerThread::handleDetection(DetectionResult    result,
                                    DetectionSource    source,
                                    const PacketInfo&  pkt,
                                    FlowState&         flow) {
    // Cập nhật metrics
    switch (result) {
        case DetectionResult::DDOS_VOLUMETRIC:
            METRICS.ddos_detected   .fetch_add(1, std::memory_order_relaxed);
            METRICS.packets_dropped .fetch_add(1, std::memory_order_relaxed);
            break;
        case DetectionResult::SLOW_DDOS:
            METRICS.slow_ddos_detected.fetch_add(1, std::memory_order_relaxed);
            METRICS.packets_alerted   .fetch_add(1, std::memory_order_relaxed);
            break;
        case DetectionResult::PORT_SCAN:
            METRICS.port_scan_detected.fetch_add(1, std::memory_order_relaxed);
            METRICS.packets_alerted   .fetch_add(1, std::memory_order_relaxed);
            break;
        default:
            METRICS.packets_alerted.fetch_add(1, std::memory_order_relaxed);
            break;
    }

    // Cập nhật flow state
    flow.is_malicious = true;
    flow.threat_type  = threatToString(result);

    // Tạo event và gọi callback
    const DetectionEvent ev = action_handler_.makeEvent(result, source, pkt);
    if (on_alert_) on_alert_(ev);
}
