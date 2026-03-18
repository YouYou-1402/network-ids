    // src/detection/dispatcher.hpp
    #pragma once
    #include "worker_thread.hpp"
    #include "ip_tracker.hpp"
    #include "../core/packet_info.hpp"
    #include "../capture/io/packet_ring_buffer.hpp"
    #include <vector>
    #include <memory>
    #include <atomic>
    #include <functional>

    class Dispatcher {
    public:
        // ── UI mode: có ring_buf thật ─────────────────────────────────────────────
        Dispatcher(int num_workers, PacketRingBuffer& ring_buf);

        // ── CLI mode: không cần ring_buf ──────────────────────────────────────────
        explicit Dispatcher(int num_workers);

        ~Dispatcher();

        void start(AlertCallback on_alert);
        void stop();

        void dispatch(PacketInfo pkt);

        void cleanupFlows(double idle_timeout_sec = 300.0);
        void cleanupIps  (double idle_timeout_sec =  60.0);

        void forEachFlow(std::function<void(FlowState&)> callback) {
            flow_table_.forEach(callback);
        }

        size_t activeFlows() const { return flow_table_.size(); }
        size_t activeIps  () const { return ip_tracker_.size(); }

    private:
        uint32_t hashToWorker(const PacketInfo& pkt) const;

        int                                        num_workers_;
        PacketRingBuffer                           dummy_ring_buf_;  // CLI mode
        PacketRingBuffer&                          ring_buf_;
        FlowTable                                  flow_table_;
        IpTracker                                  ip_tracker_;
        std::vector<std::unique_ptr<WorkerThread>> workers_;
        std::atomic<bool>                          running_{false};
    };
