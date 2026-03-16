#include "packet_ring_buffer.hpp"
#include "../../common/logger.hpp"
#include <algorithm>

PacketRingBuffer::PacketRingBuffer(size_t max_packets)
    : max_packets_(max_packets)
{
    buffer_.resize(max_packets_);
    LOG_INFO("PacketRingBuffer capacity=" + std::to_string(max_packets_)
             + " (detection only)");
}

uint64_t PacketRingBuffer::push(PacketInfo pkt) {
    std::lock_guard<std::mutex> lk(mutex_);
    const uint64_t idx  = write_seq_;
    const size_t   slot = idx % max_packets_;

    // Evict callback khi buffer đầy (>= thay vì >)
    if (write_seq_ >= max_packets_ && evict_cb_)
        evict_cb_(oldest_seq_);

    pkt.index     = idx;
    buffer_[slot] = std::move(pkt);

    ++write_seq_;

    // Cập nhật oldest_seq_ đúng: dùng >= thay vì >
    if (write_seq_ >= max_packets_)
        oldest_seq_ = write_seq_ - max_packets_;

    return idx;
}


std::vector<PacketInfo> PacketRingBuffer::pollNew(uint64_t& last_seq) const {
    std::lock_guard<std::mutex> lk(mutex_);
    if (last_seq >= write_seq_) return {};

    const uint64_t from = std::max(last_seq, oldest_seq_);
    const uint64_t to   = write_seq_;

    std::vector<PacketInfo> result;
    result.reserve(static_cast<size_t>(to - from));
    for (uint64_t i = from; i < to; ++i) {
        const size_t slot = i % max_packets_;
        if (buffer_[slot].index == i)
            result.push_back(buffer_[slot]);
    }
    last_seq = to;
    return result;
}

std::vector<PacketInfo> PacketRingBuffer::pollRange(uint64_t from,
                                                     uint64_t count) const {
    if (count == 0) return {};
    std::lock_guard<std::mutex> lk(mutex_);

    const uint64_t actual_from = std::max(from, oldest_seq_);
    const uint64_t actual_to   = std::min(from + count, write_seq_);
    if (actual_from >= actual_to) return {};

    std::vector<PacketInfo> result;
    result.reserve(static_cast<size_t>(actual_to - actual_from));
    for (uint64_t i = actual_from; i < actual_to; ++i) {
        const size_t slot = i % max_packets_;
        if (buffer_[slot].index == i)
            result.push_back(buffer_[slot]);
    }
    return result;
}

std::optional<PacketInfo> PacketRingBuffer::getByIndex(uint64_t index) const {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!isValidLocked(index)) return std::nullopt;
    return buffer_[index % max_packets_];
}

uint64_t PacketRingBuffer::totalPushed() const {
    std::lock_guard<std::mutex> lk(mutex_); return write_seq_;
}
uint64_t PacketRingBuffer::oldestIndex() const {
    std::lock_guard<std::mutex> lk(mutex_); return oldest_seq_;
}
uint64_t PacketRingBuffer::newestIndex() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return write_seq_ > 0 ? write_seq_ - 1 : 0;
}

void PacketRingBuffer::clear() {
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto& s : buffer_) s = PacketInfo{};
    write_seq_ = 0; oldest_seq_ = 0;
}
