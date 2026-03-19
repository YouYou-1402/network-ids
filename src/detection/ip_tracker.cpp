// src/detection/ip_tracker.cpp
#include "ip_tracker.hpp"

bool IpTracker::withStats(uint32_t src_ip,
                           const std::function<void(IpStats&)>& fn) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = table_.find(src_ip);
    if (it == table_.end()) {
        if (table_.size() >= MAX_TRACKED_IP)
            return false;   // bảng đầy, bỏ qua
        auto [ins, ok] = table_.emplace(src_ip, IpStats{});
        ins->second.src_ip       = src_ip;
        ins->second.window_start = Clock::now();
        it = ins;
    }

    last_seen_[src_ip] = Clock::now();
    fn(it->second);   // chạy callback TRONG lock
    return true;
}

size_t IpTracker::cleanup(double idle_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = Clock::now();
    size_t removed = 0;
    for (auto it = table_.begin(); it != table_.end(); ) {
        auto ls = last_seen_.find(it->first);
        if (ls != last_seen_.end()) {
            const double idle = std::chrono::duration<double>(
                now - ls->second).count();
            if (idle > idle_sec) {
                last_seen_.erase(ls);
                it = table_.erase(it);
                ++removed;
                continue;
            }
        }
        ++it;
    }
    return removed;
}

size_t IpTracker::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.size();
}
