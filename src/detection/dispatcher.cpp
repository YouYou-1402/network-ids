// src/detection/dispatcher.cpp
#include "dispatcher.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"

// ── UI mode ───────────────────────────────────────────────────────────────────
Dispatcher::Dispatcher(int               num_workers,
                       PacketRingBuffer& ring_buf,
                       MLJobQueue*       ml_job_queue)
    : num_workers_   (num_workers)
    , dummy_ring_buf_(1)
    , ring_buf_      (ring_buf)
    , flow_table_    (1000000)
    , ml_job_queue_  (ml_job_queue)
{}

// ── CLI mode ──────────────────────────────────────────────────────────────────
Dispatcher::Dispatcher(int num_workers, MLJobQueue* ml_job_queue)
    : num_workers_   (num_workers)
    , dummy_ring_buf_(1)
    , ring_buf_      (dummy_ring_buf_)
    , flow_table_    (1000000)
    , ml_job_queue_  (ml_job_queue)
{}

Dispatcher::~Dispatcher() { stop(); }

// ─── start ────────────────────────────────────────────────────────────────────
void Dispatcher::start(AlertCallback on_alert) {
    if (running_.exchange(true)) return;
    workers_.clear();
    workers_.reserve(num_workers_);

    for (int i = 0; i < num_workers_; ++i) {
        auto worker = std::make_unique<WorkerThread>(
            i,
            flow_table_,
            ip_tracker_,
            on_alert,
            ring_buf_,
            ml_job_queue_);   // ← inject MLJobQueue vào mỗi worker

        // Inject FirewallManager nếu có
        if (firewall_manager_)
            worker->setFirewallManager(firewall_manager_);

        worker->start();
        workers_.push_back(std::move(worker));
    }

    LOG_INFO("Dispatcher started: workers=" + std::to_string(num_workers_)
             + " flow_table=1000000"
             + " ip_tracker=" + std::to_string(IpTracker::MAX_TRACKED_IP)
             + (ml_job_queue_     ? " ML=ON"      : " ML=OFF")
             + (firewall_manager_ ? " firewall=ON" : " firewall=OFF"));
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

    const uint32_t worker_idx = hashToWorker(pkt);

    // Push vào ring_buf → gán index
    pkt.index = ring_buf_.push(pkt);

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
        LOG_INFO("FlowTable cleanup: removed=" + std::to_string(removed)
                 + " active=" + std::to_string(flow_table_.size()));
}

// ─── cleanupIps ───────────────────────────────────────────────────────────────
void Dispatcher::cleanupIps(double idle_timeout_sec) {
    const size_t removed = ip_tracker_.cleanup(idle_timeout_sec);
    if (removed > 0)
        LOG_INFO("IpTracker cleanup: removed=" + std::to_string(removed)
                 + " active=" + std::to_string(ip_tracker_.size()));
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
