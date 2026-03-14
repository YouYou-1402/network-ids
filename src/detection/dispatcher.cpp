// src/detection/dispatcher.cpp
#include "dispatcher.hpp"
#include "../common/logger.hpp"

// ─── Constructor ──────────────────────────────────────────────────────────────
Dispatcher::Dispatcher(int num_workers, PacketRingBuffer& ring_buf)
    : num_workers_(num_workers)
    , ring_buf_(ring_buf)
    , flow_table_(10000)
{}

Dispatcher::~Dispatcher() { stop(); }

// ─── start ────────────────────────────────────────────────────────────────────
void Dispatcher::start(AlertCallback on_alert) {
    running_ = true;
    workers_.clear();

    for (int i = 0; i < num_workers_; i++) {
        auto worker = std::make_unique<WorkerThread>(
            i,
            flow_table_,
            on_alert,
            ring_buf_);   
        worker->start();
        workers_.push_back(std::move(worker));
    }

    LOG_INFO("Dispatcher started with "
             + std::to_string(num_workers_) + " workers");
}

// ─── stop ─────────────────────────────────────────────────────────────────────
void Dispatcher::stop() {
    if (!running_) return;
    running_ = false;
    for (auto& w : workers_) w->stop();
    workers_.clear();
    LOG_INFO("Dispatcher stopped");
}

// ─── dispatch ─────────────────────────────────────────────────────────────────
void Dispatcher::dispatch(PacketInfo pkt) {
    if (!running_) return;
    const uint32_t idx = hashToWorker(pkt);
    workers_[idx]->enqueue(std::move(pkt));
}

// ─── cleanupFlows ─────────────────────────────────────────────────────────────
void Dispatcher::cleanupFlows(double idle_timeout_sec) {
    flow_table_.cleanup(idle_timeout_sec);
}

// ─── hashToWorker — 5-tuple hash đảm bảo cùng flow → cùng worker ─────────────
uint32_t Dispatcher::hashToWorker(const PacketInfo& pkt) const {
    uint32_t h = pkt.src_ip   * 2654435761U;
    h ^= pkt.dst_ip            * 2246822519U;
    h ^= pkt.dst_port          * 40503U;
    h ^= pkt.protocol          * 22695477U;
    return h % static_cast<uint32_t>(num_workers_);
}
