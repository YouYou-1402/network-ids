// src/capture/io/packet_ring_buffer.cpp
#include "packet_ring_buffer.hpp"
#include "../../common/logger.hpp"

// ─── Constructor ──────────────────────────────────────────────────────────────
PacketRingBuffer::PacketRingBuffer(size_t max_packets,
                                    size_t keep_raw_last_n)
    : max_packets_(max_packets)
    , keep_raw_last_n_(keep_raw_last_n)
{
    buffer_.resize(max_packets_);
    LOG_INFO("PacketRingBuffer: capacity=" + std::to_string(max_packets_)
             + " keep_raw=" + std::to_string(keep_raw_last_n_));
}

// ─── push ─────────────────────────────────────────────────────────────────────
void PacketRingBuffer::push(PacketInfo record) {
    std::lock_guard<std::mutex> lock(mutex_);

    const uint64_t idx = total_received_.fetch_add(1);
    record.index       = idx;
    const size_t slot  = idx % max_packets_;

    // Evict slot cũ nếu cần
    if (buffer_[slot].raw_data) {
        if (evict_cb_) evict_cb_(buffer_[slot].index);
        buffer_[slot].raw_data.reset();
    }

    // Evict raw_data của record cũ hơn keep_raw_last_n_
    if (idx >= keep_raw_last_n_) {
        const size_t old_slot = (idx - keep_raw_last_n_) % max_packets_;
        buffer_[old_slot].raw_data.reset();
    }

    buffer_[slot] = std::move(record);
}

// ─── getRange ─────────────────────────────────────────────────────────────────
std::vector<PacketInfo>
PacketRingBuffer::getRange(size_t from, size_t to) const {
    std::lock_guard<std::mutex> lock(mutex_);

    const uint64_t total = total_received_.load();
    if (total == 0) return {};

    const uint64_t oldest = (total > max_packets_) ? total - max_packets_ : 0;
    const uint64_t f      = std::max(static_cast<uint64_t>(from), oldest);
    const uint64_t t      = std::min(static_cast<uint64_t>(to),   total);
    if (f >= t) return {};

    std::vector<PacketInfo> result;
    result.reserve(static_cast<size_t>(t - f));
    for (uint64_t i = f; i < t; ++i) {
        const size_t slot = i % max_packets_;
        if (buffer_[slot].index == i)
            result.push_back(buffer_[slot]);
    }
    return result;
}

// ─── getByIndex ───────────────────────────────────────────────────────────────
std::shared_ptr<PacketInfo>
PacketRingBuffer::getByIndex(uint64_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);

    const uint64_t total = total_received_.load();
    if (index >= total) return nullptr;

    const uint64_t oldest = (total > max_packets_) ? total - max_packets_ : 0;
    if (index < oldest) return nullptr;

    const size_t slot = index % max_packets_;
    if (buffer_[slot].index != index) return nullptr;

    return std::make_shared<PacketInfo>(buffer_[slot]);
}

// ─── size ─────────────────────────────────────────────────────────────────────
size_t PacketRingBuffer::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t total = total_received_.load();
    return static_cast<size_t>(
        std::min(total, static_cast<uint64_t>(max_packets_)));
}

// ─── oldestIndex ──────────────────────────────────────────────────────────────
uint64_t PacketRingBuffer::oldestIndex() const {
    const uint64_t total = total_received_.load();
    return (total > max_packets_) ? total - max_packets_ : 0;
}

// ─── newestIndex ──────────────────────────────────────────────────────────────
uint64_t PacketRingBuffer::newestIndex() const {
    const uint64_t total = total_received_.load();
    return (total > 0) ? total - 1 : 0;
}

// ─── clear ────────────────────────────────────────────────────────────────────
void PacketRingBuffer::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& r : buffer_) r.raw_data.reset();
    buffer_.assign(max_packets_, PacketInfo{});
    total_received_ = 0;
}

// ─── evictAllRawData ──────────────────────────────────────────────────────────
void PacketRingBuffer::evictAllRawData() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& r : buffer_) r.raw_data.reset();
    LOG_INFO("PacketRingBuffer: evicted all raw data");
}
