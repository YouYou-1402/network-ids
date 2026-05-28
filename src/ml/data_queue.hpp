#pragma once
#include "../detection/flow_state.hpp"   
#include "../core/threat_types.hpp"
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <chrono>


enum class TcpState : uint8_t {
    OTH,    
    REJ,     
    RSTO,    
    RSTOS0, 
    RSTR,    
    S0,     
    S1,     
    S2,      
    S3,     
    SF,     
    SH,      
};

inline TcpState inferTcpState(uint32_t syn,  uint32_t ack,
                               uint32_t rst,  uint32_t fin,
                               bool     is_initiator) noexcept
{
    const bool has_syn = (syn > 0);
    const bool has_ack = (ack > 0);
    const bool has_rst = (rst > 0);
    const bool has_fin = (fin > 0);

    // SF: SYN + ACK + FIN, không RST → normal close
    if (has_syn && has_ack && has_fin && !has_rst) return TcpState::SF;
    // SH: SYN + FIN, không ACK → half-open close
    if (has_syn && has_fin && !has_ack)            return TcpState::SH;
    // RSTOS0: SYN + RST, không ACK → reset trước khi handshake
    if (has_syn && has_rst && !has_ack)            return TcpState::RSTOS0;
    // S0: chỉ SYN → half-open, chưa có ACK
    if (has_syn && !has_ack && !has_rst && !has_fin) return TcpState::S0;
    // REJ: RST từ server (không phải initiator) → connection rejected
    if (!has_syn && has_rst && !is_initiator)      return TcpState::REJ;
    // RSTO: RST từ initiator → reset bởi client
    if (has_rst && is_initiator)                   return TcpState::RSTO;
    // RSTR: RST từ server → reset bởi server
    if (has_rst && !is_initiator)                  return TcpState::RSTR;
    // S1: SYN + ACK, không FIN, không RST → handshake hoàn thành, chưa data
    if (has_syn && has_ack && !has_fin && !has_rst) return TcpState::S1;
    // FIX #5: Thêm S2 và S3 — hai state quan trọng trong NSL-KDD
    // bị thiếu trước đây, khiến nhiều flow bình thường rơi vào OTH.
    //
    // S2: ACK + FIN từ initiator, không SYN, không RST
    //     → data đang truyền, initiator bắt đầu đóng kết nối
    if (!has_syn && has_ack && has_fin && !has_rst && is_initiator)
        return TcpState::S2;
    // S3: ACK + FIN từ server (không phải initiator), không SYN, không RST
    //     → server bắt đầu đóng kết nối (half-close từ server)
    if (!has_syn && has_ack && has_fin && !has_rst && !is_initiator)
        return TcpState::S3;
    return TcpState::OTH;
}

struct FlowSnapshot {

    uint32_t src_ip   = 0;
    uint32_t dst_ip   = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 6;

    float    duration_sec = 0.0f;

    TcpState tcp_state = TcpState::OTH;
    uint64_t src_bytes = 0;
    uint64_t dst_bytes = 0;

    uint32_t wrong_fragment     = 0;
    uint32_t hot                = 0;
    bool     logged_in          = false;
    uint32_t num_compromised    = 0;
    uint32_t num_file_creations = 0;

    uint32_t count     = 0;
    uint32_t srv_count = 0;

    float serror_rate = 0.0f;
    float rerror_rate = 0.0f;
    float same_srv_rate      = 0.0f;
    float diff_srv_rate      = 0.0f;
    float srv_diff_host_rate = 0.0f;

    uint32_t dst_host_count     = 0;
    uint32_t dst_host_srv_count = 0;
    float dst_host_same_srv_rate      = 0.0f;
    float dst_host_diff_srv_rate      = 0.0f;
    float dst_host_same_src_port_rate = 0.0f;
    float dst_host_srv_diff_host_rate = 0.0f;

    static FlowSnapshot from(const FlowState& flow,
                              uint32_t         count              = 0,
                              uint32_t         srv_count          = 0,
                              uint32_t         dst_host_count     = 0,
                              uint32_t         dst_host_srv_count = 0) noexcept
    {
        FlowSnapshot s;

        s.src_ip       = flow.src_ip;
        s.dst_ip       = flow.dst_ip;
        s.src_port     = flow.src_port;
        s.dst_port     = flow.dst_port;
        s.protocol     = flow.protocol;
        s.duration_sec = static_cast<float>(flow.durationSeconds());
        s.src_bytes    = flow.fwd_bytes;
        s.dst_bytes    = flow.bwd_bytes;


        s.tcp_state = inferTcpState(flow.syn_count, flow.ack_count,
                                    flow.rst_count, flow.fin_count,
                                    flow.is_initiator);

        s.serror_rate = (flow.syn_count > 0)
            ? std::min(1.0f, static_cast<float>(flow.rst_count)
                             / static_cast<float>(flow.syn_count))
            : 0.0f;

        s.rerror_rate = (flow.total_packets > 0)
            ? std::min(1.0f, static_cast<float>(flow.rst_count)
                             / static_cast<float>(flow.total_packets))
            : 0.0f;


        s.count              = count;
        s.srv_count          = srv_count;
        s.dst_host_count     = dst_host_count;
        s.dst_host_srv_count = dst_host_srv_count;


        return s;
    }
};


struct MLJob {
    FlowSnapshot flow_snapshot;

    std::string  flow_key;
    uint32_t     src_ip    = 0;
    uint32_t     dst_ip    = 0;
    uint16_t     src_port  = 0;
    uint16_t     dst_port  = 0;
    double       timestamp = 0.0;
};

template<typename T>
class RingBuffer {
public:
    explicit RingBuffer(size_t capacity = 4096)
        : capacity_(capacity), buffer_(capacity)
    {}

    bool push(T item) {
        // FIX #1: Thêm mutex vào push() để an toàn với MPSC
        // Nhiều WorkerThread gọi push() đồng thời → cần lock để tránh
        // hai thread ghi vào cùng slot khi đọc head_ cùng lúc.
        std::lock_guard<std::mutex> lock(mutex_);
        size_t head = head_.load(std::memory_order_relaxed);
        size_t next = (head + 1) % capacity_;
        if (next == tail_.load(std::memory_order_relaxed))
            return false;
        buffer_[head] = std::move(item);
        head_.store(next, std::memory_order_relaxed);
        cv_.notify_one();
        return true;
    }

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
        tail_.store((tail + 1) % capacity_, std::memory_order_release);
        return item;
    }

    size_t size() const {
        size_t h = head_.load(std::memory_order_acquire);
        size_t t = tail_.load(std::memory_order_acquire);
        return (h >= t) ? (h - t) : (capacity_ - t + h);
    }

    bool empty() const { return size() == 0;             }
    bool full()  const { return size() == capacity_ - 1; }

private:
    size_t                  capacity_;
    std::vector<T>          buffer_;
    std::atomic<size_t>     head_{0};
    std::atomic<size_t>     tail_{0};
    std::mutex              mutex_;
    std::condition_variable cv_;
};

using MLJobQueue = RingBuffer<MLJob>;
