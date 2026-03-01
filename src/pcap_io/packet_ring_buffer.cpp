#include "packet_ring_buffer.hpp"
#include "../common/logger.hpp"

PacketRingBuffer::PacketRingBuffer(size_t max_packets,
                                    size_t keep_raw_last_n)
    : max_packets_(max_packets)
    , keep_raw_last_n_(keep_raw_last_n)
{
    buffer_.resize(max_packets_);
    LOG_INFO("PacketRingBuffer: capacity=" + std::to_string(max_packets_)
             + " keep_raw=" + std::to_string(keep_raw_last_n_));
}

void PacketRingBuffer::push(PacketRecord record) {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t idx = total_received_.fetch_add(1);
    record.index = idx;

    size_t slot = idx % max_packets_;

    // Evict raw data của record sắp bị overwrite
    if (buffer_[slot].raw_data) {
        if (evict_cb_)
            evict_cb_(buffer_[slot].index);
        buffer_[slot].raw_data.reset();
    }

    // Evict raw data của records cũ hơn keep_raw_last_n_
    // Chỉ giữ raw bytes cho N records gần nhất
    if (idx >= keep_raw_last_n_) {
        size_t old_slot = (idx - keep_raw_last_n_) % max_packets_;
        buffer_[old_slot].raw_data.reset();
    }

    buffer_[slot] = std::move(record);
}

std::vector<PacketRecord> PacketRingBuffer::getRange(size_t from,
                                                      size_t to) const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t total = total_received_.load();
    if (total == 0) return {};

    // Clamp range
    uint64_t oldest = (total > max_packets_)
                      ? total - max_packets_ : 0;
    from = std::max(static_cast<uint64_t>(from), oldest);
    to   = std::min(static_cast<uint64_t>(to),   total);

    std::vector<PacketRecord> result;
    result.reserve(to - from);

    for (uint64_t i = from; i < to; i++) {
        size_t slot = i % max_packets_;
        if (buffer_[slot].index == i)
            result.push_back(buffer_[slot]);
    }
    return result;
}

std::shared_ptr<PacketRecord>
PacketRingBuffer::getByIndex(uint64_t index) const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t total = total_received_.load();
    if (index >= total) return nullptr;

    // Kiểm tra còn trong buffer không
    uint64_t oldest = (total > max_packets_)
                      ? total - max_packets_ : 0;
    if (index < oldest) return nullptr;

    size_t slot = index % max_packets_;
    if (buffer_[slot].index != index) return nullptr;

    return std::make_shared<PacketRecord>(buffer_[slot]);
}

size_t PacketRingBuffer::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t total = total_received_.load();
    return static_cast<size_t>(std::min(total,
                                static_cast<uint64_t>(max_packets_)));
}

uint64_t PacketRingBuffer::oldestIndex() const {
    uint64_t total = total_received_.load();
    return (total > max_packets_) ? total - max_packets_ : 0;
}

uint64_t PacketRingBuffer::newestIndex() const {
    uint64_t total = total_received_.load();
    return (total > 0) ? total - 1 : 0;
}

void PacketRingBuffer::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& r : buffer_)
        r.raw_data.reset();
    buffer_.assign(max_packets_, PacketRecord{});
    total_received_ = 0;
    head_ = 0;
}

void PacketRingBuffer::evictAllRawData() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& r : buffer_)
        r.raw_data.reset();
    LOG_INFO("PacketRingBuffer: evicted all raw data");
}
