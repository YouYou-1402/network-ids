#pragma once
#include "feature_extractor.hpp"
#include "../common/threat_types.hpp"
#include <array>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <string>

// Job gửi từ Layer 1 → Layer 2
struct MLJob {
    FeatureVector  features;
    std::string    flow_key;    // Để feedback loop tìm lại flow
    uint32_t       src_ip;
    uint32_t       dst_ip;
    uint16_t       src_port;
    uint16_t       dst_port;
    double         timestamp;
};

// Ring buffer thread-safe
// Layer 1 (producers) → Layer 2 (consumer)
// Thiết kế: nhiều producer, một consumer
template<typename T, size_t Capacity>
class RingBuffer {
public:
    // Push không blocking — trả false nếu đầy
    bool push(T item) {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t next = (head + 1) % Capacity;

        if (next == tail_.load(std::memory_order_acquire))
            return false; // Buffer đầy

        buffer_[head] = std::move(item);
        head_.store(next, std::memory_order_release);
        cv_.notify_one();
        return true;
    }

    // Pop blocking với timeout
    std::optional<T> pop(int timeout_ms = 200) {
        std::unique_lock<std::mutex> lock(mutex_);

        bool ready = cv_.wait_for(
            lock,
            std::chrono::milliseconds(timeout_ms),
            [this] {
                return tail_.load(std::memory_order_relaxed)
                    != head_.load(std::memory_order_acquire);
            }
        );

        if (!ready) return std::nullopt;

        size_t tail = tail_.load(std::memory_order_relaxed);
        T item      = std::move(buffer_[tail]);
        tail_.store((tail + 1) % Capacity,
                    std::memory_order_release);
        return item;
    }

    size_t size() const {
        size_t h = head_.load(std::memory_order_acquire);
        size_t t = tail_.load(std::memory_order_acquire);
        return (h >= t) ? (h - t) : (Capacity - t + h);
    }

    bool empty() const { return size() == 0; }
    bool full()  const { return size() == Capacity - 1; }

private:
    std::array<T, Capacity>  buffer_;
    std::atomic<size_t>      head_{0};
    std::atomic<size_t>      tail_{0};
    std::mutex               mutex_;
    std::condition_variable  cv_;
};

// Alias cụ thể cho ML job queue
// Capacity 4096 đủ cho lab (5K–10K pps)
using MLJobQueue = RingBuffer<MLJob, 4096>;
