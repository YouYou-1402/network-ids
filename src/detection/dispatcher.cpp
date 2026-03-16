// src/detection/dispatcher.cpp
#include "dispatcher.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"

// ── UI mode ───────────────────────────────────────────────────────────────────
Dispatcher::Dispatcher(int num_workers, PacketRingBuffer& ring_buf)
    : num_workers_   (num_workers)
    , dummy_ring_buf_(1)        // không dùng, size=1 tránh assert
    , ring_buf_      (ring_buf)
    , flow_table_    (100000)
{}

// ── CLI mode ──────────────────────────────────────────────────────────────────
Dispatcher::Dispatcher(int num_workers)
    : num_workers_   (num_workers)
    , dummy_ring_buf_(1)
    , ring_buf_      (dummy_ring_buf_)  // trỏ vào dummy
    , flow_table_    (100000)
{}

Dispatcher::~Dispatcher() { stop(); }

// ─── start ────────────────────────────────────────────────────────────────────
void Dispatcher::start(AlertCallback on_alert) {
    if (running_.exchange(true)) return;
    workers_.clear();
    workers_.reserve(num_workers_);

    for (int i = 0; i < num_workers_; ++i) {
        workers_.push_back(std::make_unique<WorkerThread>(
            i,
            flow_table_,
            ip_tracker_,
            on_alert,
            ring_buf_));
        workers_.back()->start();
    }

    LOG_INFO("Dispatcher started: " + std::to_string(num_workers_)
             + " workers, flow_table=100000, ip_tracker="
             + std::to_string(IpTracker::MAX_TRACKED_IP));
}

// ─── stop ─────────────────────────────────────────────────────────────────────
void Dispatcher::stop() {
    if (!running_.exchange(false)) return;
    for (auto& w : workers_) w->stop();
    workers_.clear();
    LOG_INFO("Dispatcher stopped");
}

// ─── dispatch ─────────────────────────────────────────────────────────────────
void Dispatcher::dispatch(PacketInfo pkt) {
    if (!running_.load(std::memory_order_relaxed)) return;

    // Hash trước để biết worker nào
    const uint32_t worker_idx = hashToWorker(pkt);

    // Push vào ring_buf → gán index (single push, đúng chỗ)
    pkt.index = ring_buf_.push(pkt);

    // Enqueue vào worker với pkt.index đã đúng
    if (!workers_[worker_idx]->enqueue(std::move(pkt))) {
        METRICS.queue_drops.fetch_add(1, std::memory_order_relaxed);
        LOG_WARN("Worker " + std::to_string(worker_idx)
                 + " queue full, packet dropped");
    }
}
// ─── cleanupFlows ─────────────────────────────────────────────────────────────
void Dispatcher::cleanupFlows(double idle_timeout_sec) {
    const size_t removed = flow_table_.cleanup(idle_timeout_sec);
    if (removed > 0)
        LOG_INFO("FlowTable cleanup: " + std::to_string(removed)
                 + " removed, active=" + std::to_string(flow_table_.size()));
}

// ─── cleanupIps ───────────────────────────────────────────────────────────────
void Dispatcher::cleanupIps(double idle_timeout_sec) {
    const size_t removed = ip_tracker_.cleanup(idle_timeout_sec);
    if (removed > 0)
        LOG_INFO("IpTracker cleanup: " + std::to_string(removed)
                 + " removed, active=" + std::to_string(ip_tracker_.size()));
}

// ─── hashToWorker ─────────────────────────────────────────────────────────────
uint32_t Dispatcher::hashToWorker(const PacketInfo& pkt) const {
    uint32_t h = 2166136261U;
    h ^= pkt.src_ip;    h *= 16777619U;
    h ^= pkt.dst_ip;    h *= 16777619U;
    h ^= pkt.src_port;  h *= 16777619U;
    h ^= pkt.dst_port;  h *= 16777619U;
    h ^= pkt.protocol;  h *= 16777619U;
    return h % static_cast<uint32_t>(num_workers_);
}
