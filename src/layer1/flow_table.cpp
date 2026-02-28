#include "flow_table.hpp"
#include "../common/packet_info.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"

FlowTable::FlowTable(size_t max_flows)
    : max_flows_(max_flows) {}

FlowState* FlowTable::getOrCreate(const std::string& flow_key,
                                   const PacketInfo&  pkt) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Tìm flow đã tồn tại
    auto it = table_.find(flow_key);
    if (it != table_.end()) {
        it->second->last_seen = Clock::now();
        return it->second.get();
    }

    // Kiểm tra giới hạn
    if (table_.size() >= max_flows_) {
        LOG_WARN("FlowTable full (" + std::to_string(max_flows_)
                 + " flows). Dropping new flow: " + flow_key);
        METRICS.queue_drops++;
        return nullptr;
    }

    // Tạo flow mới
    auto state = createFlow(flow_key, pkt);
    FlowState* ptr = state.get();
    table_[flow_key] = std::move(state);

    METRICS.active_flows++;
    return ptr;
}

FlowState* FlowTable::get(const std::string& flow_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = table_.find(flow_key);
    return (it != table_.end()) ? it->second.get() : nullptr;
}

void FlowTable::remove(const std::string& flow_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (table_.erase(flow_key) > 0)
        METRICS.active_flows--;
}

size_t FlowTable::cleanup(double idle_timeout_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto   now     = Clock::now();
    size_t removed = 0;

    for (auto it = table_.begin(); it != table_.end(); ) {
        double idle = std::chrono::duration<double>(
            now - it->second->last_seen).count();

        if (idle > idle_timeout_sec) {
            it = table_.erase(it);
            removed++;
            METRICS.active_flows--;
        } else {
            ++it;
        }
    }

    if (removed > 0)
        LOG_INFO("FlowTable cleanup: removed " + std::to_string(removed)
                 + " idle flows. Active: " + std::to_string(table_.size()));
    return removed;
}

size_t FlowTable::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.size();
}

void FlowTable::forEach(std::function<void(FlowState&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [key, state] : table_)
        callback(*state);
}

std::unique_ptr<FlowState> FlowTable::createFlow(const std::string& key,
                                                  const PacketInfo&  pkt) {
    auto state          = std::make_unique<FlowState>();
    state->flow_key     = key;
    state->src_ip       = pkt.src_ip;
    state->dst_ip       = pkt.dst_ip;
    state->src_port     = pkt.src_port;
    state->dst_port     = pkt.dst_port;
    state->protocol     = pkt.protocol;
    state->first_seen   = Clock::now();
    state->last_seen    = state->first_seen;
    state->window_start = state->first_seen;
    return state;
}
