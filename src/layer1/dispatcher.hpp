#pragma once
#include "worker_thread.hpp"
#include "../common/packet_info.hpp"
#include <vector>
#include <memory>
#include <atomic>

class Dispatcher {
public:
    explicit Dispatcher(int num_workers = 4);
    ~Dispatcher();

    void start(AlertCallback on_alert);
    void stop();

    // Nhận gói tin từ PacketCapture và route đến đúng worker
    void dispatch(PacketInfo pkt);

    // Cleanup flows định kỳ
    void cleanupFlows(double idle_timeout_sec = 300.0);

    void forEachFlow(std::function<void(FlowState&)> callback) {
    flow_table_.forEach(callback);
}

    size_t activeFlows() const { return flow_table_.size(); }

private:
    // Hash 5-tuple → worker index
    uint32_t hashToWorker(const PacketInfo& pkt) const;

    int                                    num_workers_;
    FlowTable                              flow_table_;
    std::vector<std::unique_ptr<WorkerThread>> workers_;
    std::atomic<bool>                      running_{false};
};
