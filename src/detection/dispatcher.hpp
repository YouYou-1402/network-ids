// src/detection/dispatcher.hpp
#pragma once
#include "worker_thread.hpp"
#include "../core/packet_info.hpp"
#include "../capture/io/packet_ring_buffer.hpp"
#include <vector>
#include <memory>
#include <atomic>
#include <functional>

class Dispatcher {
public:
    explicit Dispatcher(int num_workers = 4, PacketRingBuffer& ring_buf = *defaultRingBuf());
    ~Dispatcher();

    void start(AlertCallback on_alert);
    void stop();

    void dispatch(PacketInfo pkt);
    void cleanupFlows(double idle_timeout_sec = 300.0);

    void forEachFlow(std::function<void(FlowState&)> callback) {
        flow_table_.forEach(callback);
    }

    size_t activeFlows() const { return flow_table_.size(); }

private:
    uint32_t hashToWorker(const PacketInfo& pkt) const;

    static PacketRingBuffer* defaultRingBuf() {
        static PacketRingBuffer fallback;
        return &fallback;
    }

    int                                        num_workers_;
    PacketRingBuffer&                          ring_buf_;
    FlowTable                                  flow_table_;
    std::vector<std::unique_ptr<WorkerThread>> workers_;
    std::atomic<bool>                          running_{false};
};
