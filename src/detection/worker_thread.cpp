// src/detection/worker_thread.cpp
#include "worker_thread.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"
#include "../common/engine_config.hpp"
#include <arpa/inet.h>

// ═══════════════════════════════════════════════════════════════════════════════
// PacketQueue
// ═══════════════════════════════════════════════════════════════════════════════

PacketQueue::PacketQueue(size_t max_size)
    : max_size_(max_size) {}

bool PacketQueue::push(PacketInfo pkt) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.size() >= max_size_) return false;
    queue_.push(std::move(pkt));
    cv_.notify_one();
    return true;
}

bool PacketQueue::pop(PacketInfo& pkt, int timeout_ms) {
    std::unique_lock<std::mutex> lock(mutex_);
    const bool got = cv_.wait_for(
        lock,
        std::chrono::milliseconds(timeout_ms),
        [this]{ return !queue_.empty(); });
    if (!got) return false;
    pkt = std::move(queue_.front());
    queue_.pop();
    return true;
}

size_t PacketQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

bool PacketQueue::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.empty();
}

// ═══════════════════════════════════════════════════════════════════════════════
// WorkerThread
// ═══════════════════════════════════════════════════════════════════════════════

WorkerThread::WorkerThread(int               id,
                           FlowTable&        flow_table,
                           AlertCallback     on_alert,
                           PacketRingBuffer& ring_buf)
    : id_(id)
    , flow_table_(flow_table)
    , on_alert_(std::move(on_alert))
    , ring_buf_(ring_buf)
    , queue_(65536)
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
    const bool ok = queue_.push(std::move(pkt));
    if (!ok) METRICS.queue_drops++;
    return ok;
}

// ─── run ──────────────────────────────────────────────────────────────────────
void WorkerThread::run() {
    LOG_INFO("WorkerThread " + std::to_string(id_) + " running");
    while (running_) {
        PacketInfo pkt;
        if (queue_.pop(pkt, 100))
            processPacket(pkt);
    }
}

// ─── processPacket ────────────────────────────────────────────────────────────
void WorkerThread::processPacket(PacketInfo& pkt) {

    const std::string key  = pkt.flowKey();
    FlowState*        flow = flow_table_.getOrCreate(key, pkt);

    if (!flow) {
        METRICS.packets_dropped++;
        pkt.action = "DROP";
        ring_buf_.push(pkt);
        return;
    }

    // ── Detection engine (bật/tắt runtime) ───────────────────────────────────
    if (ENGINE_CFG.detection_enabled.load(std::memory_order_relaxed)) {

        const auto sig_result = sig_engine_.analyze(pkt, *flow);
        if (sig_result != DetectionResult::NORMAL) {
            handleDetection(sig_result, pkt, *flow);
            pkt.threat_type = threatToString(sig_result);
            pkt.action      = (sig_result == DetectionResult::DDOS_VOLUMETRIC)
                              ? "DROP" : "ALERT";
            ring_buf_.push(pkt);
            return;
        }

        const auto anomaly_result = anomaly_engine_.analyze(pkt, *flow);
        if (anomaly_result != DetectionResult::NORMAL) {
            handleDetection(anomaly_result, pkt, *flow);
            pkt.threat_type = threatToString(anomaly_result);
            pkt.action      = "ALERT";
            ring_buf_.push(pkt);
            return;
        }
    }

    // ── Normal packet ─────────────────────────────────────────────────────────
    METRICS.packets_passed++;
    pkt.action = "PASS";
    ring_buf_.push(pkt);
}

// ─── handleDetection ──────────────────────────────────────────────────────────
void WorkerThread::handleDetection(const DetectionResult& result,
                                   const PacketInfo&      pkt,
                                   FlowState&             flow) {
    // Cập nhật metrics
    switch (result) {
        case DetectionResult::DDOS_VOLUMETRIC:
            METRICS.ddos_detected++;
            METRICS.packets_dropped++;
            break;
        case DetectionResult::SLOW_DDOS:
            METRICS.slow_ddos_detected++;
            METRICS.packets_alerted++;
            break;
        case DetectionResult::PORT_SCAN:
            METRICS.port_scan_detected++;
            METRICS.packets_alerted++;
            break;
        default:
            break;
    }

    // Đánh dấu flow độc hại
    flow.is_malicious = true;
    flow.threat_type  = threatToString(result);

    // Tạo event và callback
    DetectionEvent event;
    event.result    = result;
    event.action    = (result == DetectionResult::DDOS_VOLUMETRIC)
                      ? PacketAction::DROP : PacketAction::ALERT;
    event.source    = DetectionSource::LAYER1_SIGNATURE;
    event.detail    = threatToString(result) + " from flow " + pkt.flowKey();
    event.src_ip    = pkt.src_ip;
    event.dst_ip    = pkt.dst_ip;
    event.src_port  = pkt.src_port;
    event.dst_port  = pkt.dst_port;
    event.timestamp = pkt.timestampSeconds();

    if (on_alert_) on_alert_(event);
}
