#pragma once
//  src/detection/flow_table.hpp
#include "flow_state.hpp"           // ← Clock, TimePoint, FlowState
#include "../core/packet_info.hpp"
#include <unordered_map>
#include <deque>
#include <mutex>
#include <memory>
#include <functional>
#include <utility>
#include <chrono>

class FlowWindowCounter {
public:
    FlowWindowCounter() : window_2s_start_(Clock::now()) {}
    void recordConnection(uint32_t dst_ip, uint16_t dst_port) {
        const auto   now     = Clock::now();
        const double elapsed = std::chrono::duration<double>(
            now - window_2s_start_).count();

        if (elapsed >= 2.0) {
            dst_ip_2s_.clear();
            dst_port_2s_.clear();
            window_2s_start_ = now;
        }

        dst_ip_2s_[dst_ip]++;
        dst_port_2s_[dst_port]++;

        if (ring100_.size() >= RING_SIZE)
            ring100_.pop_front();
        ring100_.emplace_back(dst_ip, dst_port);
    }


    uint32_t queryCount2s(uint32_t dst_ip) const {
        auto it = dst_ip_2s_.find(dst_ip);
        return (it != dst_ip_2s_.end()) ? it->second : 0u;
    }

    uint32_t querySrvCount2s(uint16_t dst_port) const {
        auto it = dst_port_2s_.find(dst_port);
        return (it != dst_port_2s_.end()) ? it->second : 0u;
    }

    uint32_t queryDstHostCount(uint32_t dst_ip) const {
        uint32_t n = 0;
        for (const auto& [ip, port] : ring100_)
            if (ip == dst_ip) ++n;
        return n;
    }

    uint32_t queryDstHostSrvCount(uint32_t dst_ip, uint16_t dst_port) const {
        uint32_t n = 0;
        for (const auto& [ip, port] : ring100_)
            if (ip == dst_ip && port == dst_port) ++n;
        return n;
    }

    void reset() {
        dst_ip_2s_.clear();
        dst_port_2s_.clear();
        ring100_.clear();
        window_2s_start_ = Clock::now();
    }

    size_t ringSize()     const { return ring100_.size();    }
    size_t window2sSize() const { return dst_ip_2s_.size();  }

private:
    static constexpr size_t RING_SIZE = 100;


    std::unordered_map<uint32_t, uint32_t> dst_ip_2s_;    
    std::unordered_map<uint16_t, uint32_t> dst_port_2s_; 
    TimePoint                              window_2s_start_;
    std::deque<std::pair<uint32_t, uint16_t>> ring100_; 
};

class FlowTable {
public:
    explicit FlowTable(size_t max_flows = 10000);

    FlowState* getOrCreate(const std::string& flow_key,const PacketInfo&  pkt);
    FlowState* get(const std::string& flow_key);

    void remove(const std::string& flow_key);
    size_t cleanup(double idle_timeout_sec = 300.0);
    size_t size() const;
    void forEach(std::function<void(FlowState&)> callback);

private:
    std::unordered_map<std::string, std::unique_ptr<FlowState>> table_;
    mutable std::mutex mutex_;
    size_t             max_flows_;
    std::unique_ptr<FlowState> createFlow(const std::string& key, const PacketInfo&  pkt);
};
