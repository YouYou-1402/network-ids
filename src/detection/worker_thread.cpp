// src/detection/worker_thread.cpp
#include "worker_thread.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"
#include "../common/engine_config.hpp"
#include "../capture/packet_capture.hpp"
#include <arpa/inet.h>
#include <cmath>

// =============================================================================
//  PacketQueue
// =============================================================================

PacketQueue::PacketQueue(size_t max_size)
    : max_size_(max_size), mask_(max_size - 1)
{
    if (max_size == 0 || (max_size & (max_size - 1)) != 0) {
        size_t p = 1;
        while (p < max_size) p <<= 1;
        max_size_ = p;
        mask_     = p - 1;
        LOG_WARN("PacketQueue: round up → " + std::to_string(p));
    }
    buf_.resize(max_size_);
}

bool PacketQueue::push(PacketInfo pkt) {
    const size_t h    = head_.load(std::memory_order_relaxed);
    const size_t next = (h + 1) & mask_;
    if (next == tail_.load(std::memory_order_acquire))
        return false;
    buf_[h] = std::move(pkt);
    head_.store(next, std::memory_order_release);
    return true;
}

bool PacketQueue::pop(PacketInfo& pkt) {
    const size_t t = tail_.load(std::memory_order_relaxed);
    if (t == head_.load(std::memory_order_acquire))
        return false;
    pkt = std::move(buf_[t]);
    tail_.store((t + 1) & mask_, std::memory_order_release);
    return true;
}

size_t PacketQueue::size() const {
    const size_t h = head_.load(std::memory_order_acquire);
    const size_t t = tail_.load(std::memory_order_acquire);
    return (h - t) & mask_;
}

bool PacketQueue::empty() const {
    return head_.load(std::memory_order_acquire)
        == tail_.load(std::memory_order_acquire);
}

// =============================================================================
//  WorkerThread
// =============================================================================

WorkerThread::WorkerThread(int               id,
                            FlowTable&        flow_table,
                            IpTracker&        ip_tracker,
                            AlertCallback     on_alert,
                            PacketRingBuffer& ring_buf,
                            MLJobQueue*       ml_job_queue)
    : id_               (id)
    , flow_table_       (flow_table)
    , on_alert_         (std::move(on_alert))
    , ring_buf_         (ring_buf)
    , queue_            (65536)
    , sig_engine_       (ip_tracker)
    , anomaly_engine_   (ip_tracker)
    , behavioral_engine_(ip_tracker)
    , ml_job_queue_     (ml_job_queue)
{}

WorkerThread::~WorkerThread() { stop(); }

void WorkerThread::start() {
    running_ = true;
    thread_  = std::thread(&WorkerThread::run, this);
    LOG_INFO("WorkerThread " + std::to_string(id_) + " started"
             + (firewall_manager_ ? " [firewall ON]" : " [firewall OFF]")
             + (ml_job_queue_     ? " [ML ON]"       : " [ML OFF]"));
}

void WorkerThread::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
    LOG_INFO("WorkerThread " + std::to_string(id_) + " stopped");
}

bool WorkerThread::enqueue(PacketInfo pkt) {
    if (queue_.push(std::move(pkt))) return true;
    queue_dropped_.fetch_add(1, std::memory_order_relaxed);
    METRICS.queue_drops.fetch_add(1, std::memory_order_relaxed);
    return false;
}

// =============================================================================
//  isPrivateIP
//
//  Kiểm tra IP có thuộc RFC1918 / loopback không.
//  Tham số ip_be: network byte order (big-endian) — giống pkt.src_ip/dst_ip.
//
//  RFC1918 ranges:
//    10.0.0.0/8        (0x0A000000)
//    172.16.0.0/12     (0xAC100000 – 0xAC1FFFFF)
//    192.168.0.0/16    (0xC0A80000)
//    127.0.0.0/8       (loopback — phòng trường hợp test local)
//
//  Dùng trong shouldSampleForML() để phân biệt:
//    Port scan vào nội bộ : dst_ip là RFC1918  → sample tại n=1
//    Client ra CDN/Internet: dst_ip là public  → KHÔNG sample tại n=1
//
//  Lý do cần hàm này (không dùng is_initiator hay src_port):
//    hping3 --rand-source -p 443 : is_initiator=TRUE, src_port>=1024, dst=RFC1918
//    Client → CDN:443            : is_initiator=TRUE, src_port>=1024, dst=PUBLIC
//    → Chỉ dst_ip phân biệt được hai trường hợp.
//
//  Inline vì:
//    - Chỉ dùng trong file này
//    - Gọi mỗi packet trong hot path
//    - Compiler có thể optimize thành 4 branch-free comparisons
// =============================================================================
static inline bool isPrivateIP(uint32_t ip_be) {
    const uint32_t ip = ntohl(ip_be);
    if ((ip & 0xFF000000u) == 0x0A000000u) return true;   // 10.0.0.0/8
    if ((ip & 0xFFF00000u) == 0xAC100000u) return true;   // 172.16.0.0/12
    if ((ip & 0xFFFF0000u) == 0xC0A80000u) return true;   // 192.168.0.0/16
    if ((ip & 0xFF000000u) == 0x7F000000u) return true;   // 127.0.0.0/8
    return false;
}

// =============================================================================
//  run
// =============================================================================
void WorkerThread::run() {
    LOG_INFO("WorkerThread " + std::to_string(id_) + " running");

    constexpr int BATCH = 64;
    PacketInfo    batch[BATCH];
    int           idle_spins = 0;

    while (running_.load(std::memory_order_relaxed)) {
        int count = 0;
        while (count < BATCH && queue_.pop(batch[count]))
            ++count;

        if (count == 0) {
            ++idle_spins;
            if      (idle_spins < 16)  { /* busy spin */                         }
            else if (idle_spins < 256) { std::this_thread::yield();              }
            else {
                std::this_thread::sleep_for(std::chrono::microseconds(50));
                idle_spins = 128;
            }
            continue;
        }

        idle_spins = 0;
        for (int i = 0; i < count; ++i)
            processPacket(batch[i]);
    }
}

// =============================================================================
//  processPacket
// =============================================================================
void WorkerThread::processPacket(PacketInfo& pkt) {

    // ── 1. Parse nếu chưa parse ───────────────────────────────────────────────
    if (pkt.raw_data && pkt.eth_type == 0)
        PacketCapture::parsePacket(pkt);

    // ── 2. Flow lookup ────────────────────────────────────────────────────────
    const std::string key  = pkt.flowKey();
    FlowState*        flow = flow_table_.getOrCreate(key, pkt);

    if (!flow) {
        METRICS.packets_dropped.fetch_add(1, std::memory_order_relaxed);
        ring_buf_.updateRecord(pkt.index, [](PacketInfo& slot) {
            slot.action = "DROP";
        });
        return;
    }

    // ── 2b. Update ML features ────────────────────────────────────────────────
    //
    // Thực hiện TRƯỚC mọi detection engine để features luôn up-to-date
    // khi pushMLJob() được gọi ở cuối pipeline.
    //
    // Hai nhóm feature được update tại đây:
    //   A) Per-direction bytes  : fwd_bytes / bwd_bytes
    //   B) Inter-Arrival Time   : iat_mean_ms / iat_m2  (Welford's algorithm)
    {
        // ── A. Per-direction bytes ─────────────────────────────────────────────
        // is_initiator được set 1 lần trong FlowTable::createFlow()
        // dựa trên SYN flag của packet đầu tiên:
        //   SYN (không ACK) → is_initiator = true  → hướng fwd
        //   Còn lại         → is_initiator = false → hướng bwd
        //
        // payload_len = IP total length - IP header - TCP/UDP header
        // = 0 với SYN/ACK/RST thuần (không có payload)
        if (flow->is_initiator)
            flow->fwd_bytes += pkt.payload_len;
        else
            flow->bwd_bytes += pkt.payload_len;

        // ── B. Welford's online algorithm cho Inter-Arrival Time ───────────────
        //
        // Điều kiện update:
        //   1. total_packets > 1       : cần ít nhất 2 packet để có IAT
        //   2. pkt.timestamp_d > 0     : timestamp hợp lệ
        //   3. prev_pkt_timestamp_d > 0: đã có packet trước
        //
        // Welford's one-pass (Knuth, TAOCP Vol.2):
        //   n      = total_packets  (đã được increment bởi getOrCreate)
        //   iat_ms = (cur_ts - prev_ts) * 1000
        //   delta  = iat_ms - mean_old
        //   mean  += delta / n
        //   delta2 = iat_ms - mean_new        ← dùng mean MỚI
        //   M2    += delta * delta2
        //
        //   Variance = M2 / (n - 1)           ← sample variance
        //   Std      = sqrt(M2 / (n - 1))
        //
        // Lý do dùng Welford's:
        //   - O(1) memory: không cần lưu toàn bộ IAT history
        //   - Numerically stable: tránh catastrophic cancellation
        //     của naive formula Var = E[X²] - E[X]²
        //     (xảy ra khi mean >> std, ví dụ IAT ~ 100ms ± 0.1ms)
        if (flow->total_packets > 1
            && pkt.timestamp_d            > 0.0
            && flow->prev_pkt_timestamp_d > 0.0)
        {
            const double iat_ms = (pkt.timestamp_d
                                   - flow->prev_pkt_timestamp_d) * 1000.0;

            // Chỉ update nếu IAT hợp lệ:
            //   iat_ms <= 0  : clock skew hoặc out-of-order packet → bỏ qua
            //   iat_ms > 60s : flow idle quá lâu → bỏ qua để không skew mean
            if (iat_ms > 0.0 && iat_ms < 60000.0) {
                const double n      = static_cast<double>(flow->total_packets);
                const double delta  = iat_ms - flow->iat_mean_ms;
                flow->iat_mean_ms  += delta / n;
                const double delta2 = iat_ms - flow->iat_mean_ms;
                flow->iat_m2       += delta * delta2;
            }
        }

        // Lưu timestamp hiện tại cho packet tiếp theo
        // Thực hiện SAU khi tính IAT (không phải trước)
        flow->prev_pkt_timestamp_d = pkt.timestamp_d;
    }
    // ── end 2b ────────────────────────────────────────────────────────────────

    // ── 3. Firewall quick check ───────────────────────────────────────────────
    if (firewall_manager_) {
        const auto check = firewall_manager_->quickCheck(pkt);

        if (check == FirewallManager::QuickCheck::WHITELIST) {
            METRICS.packets_passed.fetch_add(1, std::memory_order_relaxed);
            ring_buf_.updateRecord(pkt.index, [](PacketInfo& slot) {
                slot.action = "PASS(whitelist)";
            });
            return;
        }

        if (check == FirewallManager::QuickCheck::BLACKLIST) {
            // nftables/iptables đã DROP ở kernel
            // Packet này chỉ xuất hiện nếu capture trước firewall (mirror port)
            METRICS.packets_dropped.fetch_add(1, std::memory_order_relaxed);
            ring_buf_.updateRecord(pkt.index, [](PacketInfo& slot) {
                slot.action = "DROP(blacklist)";
            });
            return;
        }
        // QuickCheck::NONE → tiếp tục detection
    }

    // ── 4. Detection guard ────────────────────────────────────────────────────
    if (!ENGINE_CFG.detection_enabled.load(std::memory_order_relaxed)) {
        METRICS.packets_passed.fetch_add(1, std::memory_order_relaxed);
        ring_buf_.updateRecord(pkt.index, [](PacketInfo& slot) {
            slot.action = "PASS";
        });
        // Vẫn sample cho ML khi L1 disabled
        // → ML có thể phát hiện anomaly mà L1 bỏ qua
        if (ml_job_queue_
            && ENGINE_CFG.ml_enabled.load(std::memory_order_relaxed)
            && shouldSampleForML(*flow))
        {
            pushMLJob(pkt, *flow, key);
        }
        return;
    }

    // ── 5. Layer 1a — Signature Engine ───────────────────────────────────────
    DetectionResult result = sig_engine_.analyze(pkt, *flow);
    DetectionSource source = DetectionSource::LAYER1_SIGNATURE;

    // ── 6. Layer 1b — Protocol Anomaly (Slow DDoS) ───────────────────────────
    if (result == DetectionResult::NORMAL) {
        result = anomaly_engine_.analyze(pkt, *flow);
        source = DetectionSource::LAYER1_PROTOCOL_ANOMALY;
    }

    // ── 7. Layer 1c — Behavioral Engine ──────────────────────────────────────
    if (result == DetectionResult::NORMAL) {
        result = behavioral_engine_.analyze(pkt, *flow);
        source = DetectionSource::LAYER1_BEHAVIORAL;
    }

    // ── 8. Threat detected ────────────────────────────────────────────────────
    if (result != DetectionResult::NORMAL) {
        handleDetection(result, source, pkt, *flow);

        const std::string threat = threatToString(result);
        const std::string action = actionToString(action_handler_.decide(result));

        ring_buf_.updateRecord(pkt.index, [&](PacketInfo& slot) {
            slot.threat_type = threat;
            slot.action      = action;
        });

        // Vẫn sample cho ML sau khi L1 detect
        // → ML học được pattern của traffic độc hại (supervised signal)
        if (ml_job_queue_
            && ENGINE_CFG.ml_enabled.load(std::memory_order_relaxed)
            && shouldSampleForML(*flow))
        {
            pushMLJob(pkt, *flow, key);
        }
        return;
    }

    // ── 9. Normal ─────────────────────────────────────────────────────────────
    METRICS.packets_passed.fetch_add(1, std::memory_order_relaxed);
    ring_buf_.updateRecord(pkt.index, [](PacketInfo& slot) {
        slot.action = "PASS";
    });

    // ── 10. ML sampling — Layer 2 ─────────────────────────────────────────────
    // Push flow snapshot vào MLJobQueue để MLEngine phân tích bất đồng bộ
    // Chỉ push khi:
    //   a. MLJobQueue tồn tại
    //   b. ml_enabled = true
    //   c. Flow đủ "già" để có features ý nghĩa (shouldSampleForML)
    if (ml_job_queue_
        && ENGINE_CFG.ml_enabled.load(std::memory_order_relaxed)
        && shouldSampleForML(*flow))
    {
        pushMLJob(pkt, *flow, key);
    }
}

// =============================================================================
//  handleDetection
// =============================================================================
void WorkerThread::handleDetection(DetectionResult    result,
                                    DetectionSource    source,
                                    const PacketInfo&  pkt,
                                    FlowState&         flow) {
    // ── Metrics ───────────────────────────────────────────────────────────────
    switch (result) {
        case DetectionResult::DDOS_VOLUMETRIC:
            METRICS.ddos_detected   .fetch_add(1, std::memory_order_relaxed);
            METRICS.packets_dropped .fetch_add(1, std::memory_order_relaxed);
            break;
        case DetectionResult::SLOW_DDOS:
            METRICS.slow_ddos_detected.fetch_add(1, std::memory_order_relaxed);
            METRICS.packets_alerted   .fetch_add(1, std::memory_order_relaxed);
            break;
        case DetectionResult::PORT_SCAN:
            METRICS.port_scan_detected.fetch_add(1, std::memory_order_relaxed);
            METRICS.packets_alerted   .fetch_add(1, std::memory_order_relaxed);
            break;
        default:
            METRICS.packets_alerted.fetch_add(1, std::memory_order_relaxed);
            break;
    }

    // ── Auto-block vào kernel firewall ────────────────────────────────────────
    if (firewall_manager_) {
        struct in_addr addr;
        addr.s_addr = pkt.src_ip;
        const std::string src_ip_str = inet_ntoa(addr);
        const std::string reason     = threatToString(result) + " detected by L1";
        firewall_manager_->autoBlock(src_ip_str, pkt.protocol, 0, reason);
    }

    // ── Flow state ────────────────────────────────────────────────────────────
    flow.is_malicious = true;
    flow.threat_type  = threatToString(result);

    // ── Alert callback → AlertManager / UI ───────────────────────────────────
    const DetectionEvent ev = action_handler_.makeEvent(result, source, pkt);
    if (on_alert_) on_alert_(ev);
}

// =============================================================================
//  shouldSampleForML
//
//  Quyết định có push flow snapshot vào MLJobQueue hay không.
//
//  ── Vấn đề với code cũ ────────────────────────────────────────────────────
//
//  Case [A] cũ:
//    if (n==1 && syn>0 && ack==0 && fin==0) return true;
//
//  Trigger với CẢ HAI trường hợp:
//    (a) hping3 --rand-source -p 443
//        flow: RAND_IP:PORT → 192.168.100.95:443
//        dst_ip = 192.168.100.95  ← RFC1918 (internal victim)
//
//    (b) Client mở HTTPS đến CDN (YouTube, Microsoft, ...)
//        flow: 192.168.100.95:PORT → 142.250.197.130:443
//        dst_ip = 142.250.197.130  ← public IP (external CDN)
//
//  Tại n=1, FeatureVector gần như rỗng:
//    flow_duration ≈ 0  →  pkt_rate = normalize(∞) = max
//    fwd_bytes = 0 (SYN không có payload)
//    bwd_bytes = 0
//    syn=1, ack=0
//  → XGBoost: {syn=1, ack=0, pkt_rate=max, bytes=0} = PORT_SCAN (score=0.703)
//    Đây là decision boundary cứng của tree — không phải coincidence.
//
//  ── Tại sao không dùng is_initiator hay src_port ──────────────────────────
//
//  Cả hai trường hợp đều có:
//    is_initiator = TRUE  (cả 2 đều gửi SYN → createFlow() set TRUE)
//    src_port >= 1024     (ephemeral port)
//    scan_ports_seen.size() = 1  (hping3 --rand-source: mỗi src_ip random
//                                 chỉ gửi 1 SYN → size=1, giống CDN client)
//  → Không phân biệt được qua các field này.
//
//  ── Fix: isPrivateIP(dst_ip) ──────────────────────────────────────────────
//
//  Port scan vào nội bộ : dst_ip là RFC1918 → sample tại n=1 ✓
//  Client ra CDN        : dst_ip là public  → KHÔNG sample tại n=1
//                         → Chờ n=10 (case [B]) khi flow đã có đủ features
//
//  Tại n=10 với CDN flow:
//    flow đã hoàn thành ít nhất 1 RTT (SYN→SYN-ACK→ACK→DATA)
//    flow_duration > 0, fwd_bytes > 0, bwd_bytes > 0, ack_count > 0
//    → Features có nghĩa → XGBoost classify đúng (BENIGN)
//
//  ── Edge cases ────────────────────────────────────────────────────────────
//
//  [E1] Attacker trong mạng nội bộ scan ra ngoài:
//    src_ip = 192.168.x.x (compromised host), dst_ip = 1.2.3.4 (external)
//    → dst_ip không phải RFC1918 → case [A] không trigger
//    → NHƯNG: SignatureEngine::checkPortScan() vẫn chạy độc lập (L1)
//    → Case [B] tại n=10 vẫn sample cho ML
//    → Chấp nhận được: L1 đã cover, ML là layer bổ sung
//
//  [E2] Scan nội bộ đến nội bộ (lateral movement):
//    src_ip = 192.168.x.x, dst_ip = 192.168.y.y
//    → dst_ip là RFC1918 → case [A] trigger → sample tại n=1 ✓
//
//  [E3] hping3 --rand-source probe port lạ (không phải 443):
//    dst_ip = 192.168.100.95 (internal) → case [A] trigger ✓
//
//  [E4] CDN dùng IP private (không thực tế nhưng phòng ngừa):
//    Không tồn tại trong thực tế — CDN luôn dùng public IP.
//
//  ── Case [C]: SYN flood tích lũy ─────────────────────────────────────────
//
//  Guard isPrivateIP(dst_ip) tương tự case [A]:
//    CDN server có thể có syn_no_ack tạm thời cao trong TLS session resumption
//    → Nếu không guard, case [C] trigger với CDN flow → false positive
//    → Guard: chỉ sample khi dst là internal host
//
// =============================================================================
bool WorkerThread::shouldSampleForML(const FlowState& flow) const {
    const uint64_t n = flow.total_packets;

    // ── Case [A]: SYN-only flow ───────────────────────────────────────────────
    //
    // Bắt hping3 --rand-source: mỗi flow chỉ có đúng 1 SYN packet.
    // Nếu không sample tại n=1, flow sẽ expire trước khi đạt n=10
    // → bỏ sót hoàn toàn.
    //
    // Guard isPrivateIP(dst_ip):
    //   dst_ip là RFC1918 → scan vào internal host → sample ✓
    //   dst_ip là public  → outbound connection (CDN, API, ...) → skip
    //
    if (n == 1) {
        // Chỉ cho phép sample n=1 nếu là quét cổng nội bộ (dst là Private IP)
        if (isPrivateIP(flow.dst_ip)) {
            return (flow.syn_count > 0 && flow.ack_count == 0);
        }
        // Nếu là YouTube/Facebook (Public IP), tuyệt đối đợi đến n=10 
        // để các đặc trưng duration, byte_rate ổn định.
        return false; 
    }
    // ── Case [C]: SYN flood tích lũy ─────────────────────────────────────────
    //
    // Bắt hping3 với IP cố định: 1 flow tích lũy nhiều SYN liên tục.
    // syn_no_ack > 5: nhiều SYN gửi đi không nhận được ACK phản hồi.
    //
    // Guard isPrivateIP(dst_ip):
    //   CDN có thể có syn_no_ack tạm thời > 5 trong quá trình
    //   TLS session resumption / HTTP/2 multiplexing → false positive
    //   → Chỉ sample khi dst là internal host.
    //
    if (flow.syn_no_ack   >  5
        && n              %  5 == 0
        && isPrivateIP(flow.dst_ip))
    {
        return true;
    }

    // ── Case [B]: Sampling định kỳ ───────────────────────────────────────────
    //
    // Không cần guard isPrivateIP ở đây:
    //   - Tại n=10, flow đã có ít nhất 1 RTT hoàn chỉnh
    //   - flow_duration > 0, fwd_bytes > 0, bwd_bytes > 0, ack_count > 0
    //   - Features có nghĩa → XGBoost classify đúng cho cả internal và external
    //   - CDN flow tại n=10: ack_count > 0, bwd_bytes > 0
    //     → XGBoost không classify là PORT_SCAN
    //
    if (n == 10)                   return true;   // snapshot đầu tiên
    if (n <  200 && n % 50  == 0)  return true;   // mỗi 50 pkts (flow trẻ)
    if (n >= 200 && n % 200 == 0)  return true;   // mỗi 200 pkts (flow già)

    return false;
}

// =============================================================================
//  pushMLJob
// =============================================================================
void WorkerThread::pushMLJob(const PacketInfo&  pkt,
                              const FlowState&   flow,
                              const std::string& flow_key) {
    MLJob job;
    job.features  = feature_extractor_.extract(flow);
    job.flow_key  = flow_key;
    job.src_ip    = pkt.src_ip;
    job.dst_ip    = pkt.dst_ip;
    job.src_port  = pkt.src_port;
    job.dst_port  = pkt.dst_port;
    job.timestamp = pkt.timestamp_d;

    if (!ml_job_queue_->push(std::move(job))) {
        METRICS.queue_drops.fetch_add(1, std::memory_order_relaxed);
        LOG_DEBUG("MLJobQueue full, job dropped for flow: " + flow_key);
    }
}