// src/detection/ip_tracker.cpp
#include "ip_tracker.hpp"
#include "../common/logger.hpp"

IpStats* IpTracker::getOrCreate(uint32_t src_ip) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = table_.find(src_ip);
    if (it != table_.end()) {
        last_seen_[src_ip] = Clock::now();

        // Reset window nếu hết hạn
        IpStats& stats = it->second;
        if (stats.windowElapsed() > WINDOW_SEC)
            stats.resetWindow();

        return &stats;
    }

    if (table_.size() >= MAX_TRACKED_IP) {
        LOG_WARN("IpTracker: table full (" 
                 + std::to_string(MAX_TRACKED_IP) + " IPs)");
        return nullptr;
    }

    IpStats& stats   = table_[src_ip];
    stats.src_ip     = src_ip;
    stats.window_start = Clock::now();
    last_seen_[src_ip] = stats.window_start;
    return &stats;
}

IpStats* IpTracker::get(uint32_t src_ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = table_.find(src_ip);
    return (it != table_.end()) ? &it->second : nullptr;
}

size_t IpTracker::cleanup(double idle_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto   now     = Clock::now();
    size_t removed = 0;

    for (auto it = table_.begin(); it != table_.end(); ) {
        auto ls = last_seen_.find(it->first);
        if (ls != last_seen_.end()) {
            double idle = std::chrono::duration<double>(
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

    if (removed > 0)
        LOG_INFO("IpTracker cleanup: removed " + std::to_string(removed)
                 + " IPs. Active: " + std::to_string(table_.size()));
    return removed;
}

size_t IpTracker::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.size();
}
