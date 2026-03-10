//src/detection/flow_state.hpp
#pragma once
#include "flow_state.hpp"
#include <unordered_map>
#include <mutex>
#include <memory>
#include <functional>
#include "../core/packet_info.hpp" 

class FlowTable {
public:
    explicit FlowTable(size_t max_flows = 10000);

    // Lấy hoặc tạo mới FlowState cho flow_key
    // Trả về nullptr nếu table đầy
    FlowState* getOrCreate(const std::string& flow_key,
                           const PacketInfo&  pkt);

    // Lấy FlowState đã tồn tại (nullptr nếu không có)
    FlowState* get(const std::string& flow_key);

    // Xóa một flow
    void remove(const std::string& flow_key);

    // Dọn dẹp flows cũ (gọi định kỳ)
    // idle_timeout_sec: xóa flow không có packet sau N giây
    size_t cleanup(double idle_timeout_sec = 300.0);

    // Số flows hiện tại
    size_t size() const;

    // Iterate qua tất cả flows (callback)
    void forEach(std::function<void(FlowState&)> callback);

private:
    std::unordered_map<std::string,
                       std::unique_ptr<FlowState>> table_;
    mutable std::mutex mutex_;
    size_t             max_flows_;

    // Tạo FlowState mới từ PacketInfo
    std::unique_ptr<FlowState> createFlow(const std::string& key,
                                          const PacketInfo&  pkt);
};
