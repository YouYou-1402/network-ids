#pragma once
// =============================================================================
//  src/detection/flow_table.hpp
//
//  Thay đổi so với phiên bản cũ:
//    [THÊM] FlowWindowCounter — sliding window counters cho NSL-KDD features
//    [GIỮ]  FlowTable — không thay đổi interface
//
//  Include order:
//    flow_table.hpp
//      → flow_state.hpp   (Clock, TimePoint, FlowState đã được define)
//      → packet_info.hpp
// =============================================================================

#include "flow_state.hpp"           // ← Clock, TimePoint, FlowState
#include "../core/packet_info.hpp"
#include <unordered_map>
#include <deque>
#include <mutex>
#include <memory>
#include <functional>
#include <utility>
#include <chrono>

// =============================================================================
//  FlowWindowCounter — đếm connections trong sliding window
//
//  Dùng để tính 4 NSL-KDD features:
//    [10] count              — connections đến cùng dst_ip trong 2 giây qua
//    [11] srv_count          — connections đến cùng dst_port trong 2 giây qua
//    [17] dst_host_count     — connections đến cùng dst_ip trong 100 conn qua
//    [18] dst_host_srv_count — connections đến cùng (dst_ip,dst_port) trong 100 conn qua
//
//  Thread safety:
//    KHÔNG thread-safe — chỉ dùng từ 1 WorkerThread duy nhất.
//    Mỗi WorkerThread có instance riêng → không cần mutex.
//
//  Memory:
//    2s window  : 2 unordered_map nhỏ, reset mỗi 2 giây
//    100-conn ring: deque tối đa 100 phần tử (pair<uint32_t, uint16_t>)
// =============================================================================
class FlowWindowCounter {
public:
    // Clock và TimePoint đã được define trong flow_state.hpp
    FlowWindowCounter() : window_2s_start_(Clock::now()) {}

    // =========================================================================
    //  recordConnection — ghi nhận 1 connection mới hoàn thành
    //
    //  Gọi trong WorkerThread::pushMLJob() TRƯỚC khi query.
    //  Lý do gọi trước: NSL-KDD tính "connections including current one"
    // =========================================================================
    void recordConnection(uint32_t dst_ip, uint16_t dst_port) {
        // ── 2-second window ───────────────────────────────────────────────────
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

        // ── 100-connection ring ───────────────────────────────────────────────
        if (ring100_.size() >= RING_SIZE)
            ring100_.pop_front();
        ring100_.emplace_back(dst_ip, dst_port);
    }

    // ── 2-second window queries ───────────────────────────────────────────────

    // count: số connections đến cùng dst_ip trong 2s
    uint32_t queryCount2s(uint32_t dst_ip) const {
        auto it = dst_ip_2s_.find(dst_ip);
        return (it != dst_ip_2s_.end()) ? it->second : 0u;
    }

    // srv_count: số connections đến cùng dst_port trong 2s
    uint32_t querySrvCount2s(uint16_t dst_port) const {
        auto it = dst_port_2s_.find(dst_port);
        return (it != dst_port_2s_.end()) ? it->second : 0u;
    }

    // ── 100-connection ring queries ───────────────────────────────────────────

    // dst_host_count: số connections đến cùng dst_ip trong ring
    uint32_t queryDstHostCount(uint32_t dst_ip) const {
        uint32_t n = 0;
        for (const auto& [ip, port] : ring100_)
            if (ip == dst_ip) ++n;
        return n;
    }

    // dst_host_srv_count: số connections đến cùng (dst_ip, dst_port) trong ring
    uint32_t queryDstHostSrvCount(uint32_t dst_ip, uint16_t dst_port) const {
        uint32_t n = 0;
        for (const auto& [ip, port] : ring100_)
            if (ip == dst_ip && port == dst_port) ++n;
        return n;
    }

    // Reset toàn bộ (dùng khi test)
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

    // 2-second window
    std::unordered_map<uint32_t, uint32_t> dst_ip_2s_;    // dst_ip   → count
    std::unordered_map<uint16_t, uint32_t> dst_port_2s_;  // dst_port → count
    TimePoint                              window_2s_start_;

    // 100-connection ring buffer
    std::deque<std::pair<uint32_t, uint16_t>> ring100_;   // (dst_ip, dst_port)
};

// =============================================================================
//  FlowTable — không thay đổi interface
// =============================================================================
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
