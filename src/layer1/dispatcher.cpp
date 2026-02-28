#include "dispatcher.hpp"
#include "../common/logger.hpp"

Dispatcher::Dispatcher(int num_workers)
    : num_workers_(num_workers)
    , flow_table_(10000) {}

Dispatcher::~Dispatcher() {
    stop();
}

void Dispatcher::start(AlertCallback on_alert) {
    running_ = true;
    workers_.clear();

    for (int i = 0; i < num_workers_; i++) {
        auto worker = std::make_unique<WorkerThread>(
            i, flow_table_, on_alert);
        worker->start();
        workers_.push_back(std::move(worker));
    }

    LOG_INFO("Dispatcher started with "
             + std::to_string(num_workers_) + " workers");
}

void Dispatcher::stop() {
    if (!running_) return;
    running_ = false;

    for (auto& w : workers_)
        w->stop();

    workers_.clear();
    LOG_INFO("Dispatcher stopped");
}

void Dispatcher::dispatch(PacketInfo pkt) {
    if (!running_) return;

    uint32_t worker_idx = hashToWorker(pkt);
    workers_[worker_idx]->enqueue(std::move(pkt));
}

void Dispatcher::cleanupFlows(double idle_timeout_sec) {
    flow_table_.cleanup(idle_timeout_sec);
}

// Hash 5-tuple → worker index
// Đảm bảo cùng flow luôn đến cùng worker
uint32_t Dispatcher::hashToWorker(const PacketInfo& pkt) const {
    uint32_t hash = pkt.src_ip;
    hash ^= pkt.dst_ip       * 2654435761U;
    hash ^= pkt.src_port     * 40503U;
    hash ^= pkt.dst_port     * 40503U;
    hash ^= pkt.protocol     * 2246822519U;
    return hash % static_cast<uint32_t>(num_workers_);
}
