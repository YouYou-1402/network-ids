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
{
    // FIX #2: Tính mask SAU khi round-up lên power-of-2.
    // Trước đây: max_size_ và mask_ được khởi tạo từ tham số gốc,
    // sau đó chỉ được cập nhật nếu không phải power-of-2.
    // Nếu max_size đã là power-of-2, mask_ = max_size - 1 đúng.
    // Nhưng nếu không, mask_ ban đầu sai và buf_.resize() dùng max_size_ mới
    // → mask_ và buf_.size() không khớp → out-of-bounds access.
    // Fix: luôn tính mask_ từ giá trị đã round-up.
    size_t p = 1;
    while (p < std::max(max_size, size_t(2))) p <<= 1;
    max_size_ = p;
    mask_     = p - 1;
    buf_.resize(p);
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
    , queue_            (4096*2)
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

    // ── 2b. Update ALL ML features ────────────────────────────────────────────
    //
    // [FIX-1] total_packets và total_bytes phải được increment tại đây.
    //   Trước đây FlowTable::createFlow() chỉ set total_packets=1 cho packet
    //   đầu tiên, các packet tiếp theo không được đếm → feature vô nghĩa.
    //
    // [FIX-2] Tất cả TCP flag counter và fwd/bwd packet counter phải được
    //   update tại đây — không phải trong SignatureEngine hay chỗ khác.
    //   Lý do: SignatureEngine có thể return sớm (detect DDOS_VOLUMETRIC),
    //   nhưng ML cần features đầy đủ bất kể L1 quyết định gì.
    //
    // [FIX-3] Welford's IAT: dùng total_packets SAU khi increment.
    //   n = total_packets (sau increment) = số packet hiện tại (bắt đầu từ 1).
    //   Welford's yêu cầu n = index của observation hiện tại.
    //   Trước đây dùng total_packets trước increment → n lệch 1 → mean sai.
    //
    // [FIX-4] dst_ports_seen: insert tại đây cho mọi SYN (no-ACK).
    //   Trước đây chỉ SignatureEngine::checkPortScan() mới insert.
    //   → unique_dst_ports = 0 với mọi flow không bị L1 detect
    //   → feature vô nghĩa với ML model
    {
        // [FIX-1] Packet / byte counters
        flow->total_packets++;
        flow->total_bytes += pkt.payload_len;

        if (flow->is_initiator) {
            flow->fwd_packets++;
            flow->fwd_bytes += pkt.payload_len;
        } else {
            flow->bwd_packets++;
            flow->bwd_bytes += pkt.payload_len;
        }

        // [FIX-2] TCP flag counters
        if (pkt.protocol == IPPROTO_TCP) {
            const bool has_syn = pkt.hasSYN();
            const bool has_ack = pkt.hasACK();
            const bool has_rst = pkt.hasRST();
            const bool has_fin = pkt.hasFIN();

            if (has_syn) {
                flow->syn_count++;
                if (!has_ack) {
                    // SYN không có ACK = half-open probe
                    flow->syn_no_ack++;

                    // [FIX-4] dst_ports_seen: track mọi SYN probe
                    // Không giới hạn chỉ khi SignatureEngine detect
                    // → unique_dst_ports có giá trị thực với mọi flow
                    flow->dst_ports_seen.insert(pkt.dst_port);
                }
            }
            if (has_ack) flow->ack_count++;
            if (has_rst) flow->rst_count++;
            if (has_fin) flow->fin_count++;
        }

        // [FIX-3] IAT — Welford's online algorithm
        //
        // Điều kiện update:
        //   total_packets >= 2  : cần ít nhất 2 packet để có IAT
        //   timestamp_d > 0     : packet có timestamp hợp lệ
        //   prev_pkt_timestamp_d > 0 : đã có packet trước
        //
        // n = total_packets SAU increment (đã fix):
        //   Packet 2: n=2, delta = iat - 0 = iat, mean = iat/2
        //   Packet 3: n=3, delta = iat - mean_prev, mean += delta/3
        //   → Welford's chuẩn: mean_n = mean_{n-1} + (x_n - mean_{n-1}) / n
        //
        // Guard iat_ms: [0.001, 60000] ms
        //   < 0.001ms: clock resolution artifact → bỏ qua
        //   > 60000ms: flow idle / clock jump → bỏ qua
        if (flow->total_packets >= 2
            && pkt.timestamp_d             > 0.0
            && flow->prev_pkt_timestamp_d  > 0.0)
        {
            const double iat_ms = (pkt.timestamp_d
                                   - flow->prev_pkt_timestamp_d) * 1000.0;
            if (iat_ms > 0.001 && iat_ms < 60000.0) {
                // [FIX-3] n = total_packets SAU increment
                const double n      = static_cast<double>(flow->total_packets);
                const double delta  = iat_ms - flow->iat_mean_ms;
                flow->iat_mean_ms  += delta / n;
                const double delta2 = iat_ms - flow->iat_mean_ms;
                flow->iat_m2       += delta * delta2;
            }
        }

        flow->prev_pkt_timestamp_d = pkt.timestamp_d;
        flow->last_seen            = Clock::now();
    }

    // ── 2c. Protocol Anomaly pre-hook — TRƯỚC tất cả detection engine ─────────
    //
    // Gọi anomaly_engine_.onSyn() tại đây để đảm bảo http_start luôn được
    // set khi nhận SYN, bất kể sig_engine_ có detect DDOS_VOLUMETRIC hay không.
    //
    // Vấn đề nếu không có bước này:
    //   Slowloris gửi 500 SYN → sig_engine_.checkFloodRate() detect
    //   DDOS_VOLUMETRIC tại packet thứ 10 → processPacket() return sớm
    //   → anomaly_engine_.analyze() không được gọi
    //   → flow.http_start không được set
    //   → Các packet keep-alive header sau đó:
    //       flow.http_start == TimePoint{} → checkSlowloris() return NORMAL
    //   → Slowloris không bao giờ bị detect bởi ProtocolAnomalyEngine
    //
    // Fix: tách onSyn() ra khỏi analyze(), gọi unconditionally tại đây
    // → http_start luôn được set ngay cả khi sig_engine_ return sớm
    if (pkt.protocol == IPPROTO_TCP)
        anomaly_engine_.onSyn(pkt, *flow);

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
            METRICS.packets_dropped.fetch_add(1, std::memory_order_relaxed);
            ring_buf_.updateRecord(pkt.index, [](PacketInfo& slot) {
                slot.action = "DROP(blacklist)";
            });
            return;
        }
    }

    // ── 4. Detection guard ────────────────────────────────────────────────────
    if (!ENGINE_CFG.detection_enabled.load(std::memory_order_relaxed)) {
        METRICS.packets_passed.fetch_add(1, std::memory_order_relaxed);
        ring_buf_.updateRecord(pkt.index, [](PacketInfo& slot) {
            slot.action = "PASS";
        });
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
    //
    // Chạy LUÔN LUÔN kể cả khi sig_engine_ detect DDOS_VOLUMETRIC.
    //
    // Lý do: Slowloris tạo nhiều connection → sig_engine_ có thể detect
    // DDOS_VOLUMETRIC (flood) trước khi anomaly_engine_ detect SLOW_DDOS.
    // Nếu skip anomaly_engine_, threat_type sẽ là DDOS_VOLUMETRIC thay vì
    // SLOW_DDOS → action sai (DROP thay vì ALERT + rate limit).
    //
    // Ưu tiên: SLOW_DDOS > DDOS_VOLUMETRIC khi dst_port là HTTP/HTTPS
    // vì SLOW_DDOS cần xử lý khác (rate limit per-IP, không block toàn bộ)
    {
        const bool is_http = (pkt.dst_port == 80  || pkt.dst_port == 8080
                           || pkt.dst_port == 443);
        if (is_http) {
            const DetectionResult anomaly_r =
                anomaly_engine_.analyze(pkt, *flow);

            if (anomaly_r != DetectionResult::NORMAL) {
                result = anomaly_r;
                source = DetectionSource::LAYER1_PROTOCOL_ANOMALY;
            }
            // Nếu anomaly NORMAL nhưng sig detect PORT_SCAN → giữ nguyên
        } else {
            if (result == DetectionResult::NORMAL) {
                result = anomaly_engine_.analyze(pkt, *flow);
                source = DetectionSource::LAYER1_PROTOCOL_ANOMALY;
            }
        }
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

    // ── 10. ML sampling ───────────────────────────────────────────────────────
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

    if (firewall_manager_) {
        struct in_addr addr;
        addr.s_addr = pkt.src_ip;
        const std::string src_ip_str = inet_ntoa(addr);
        const std::string reason     = threatToString(result) + " detected by L1";
        firewall_manager_->autoBlock(src_ip_str, pkt.protocol, 0, reason);
    }

    flow.is_malicious = true;
    flow.threat_type  = threatToString(result);

    const DetectionEvent ev = action_handler_.makeEvent(result, source, pkt);
    if (on_alert_) on_alert_(ev);
}

// =============================================================================
//  shouldSampleForML
//
//  Quyết định có push flow snapshot vào MLJobQueue hay không.
//
//  ── Case [A]: SYN-only flow (n=1) ────────────────────────────────────────
//
//  Bắt hping3 --rand-source: mỗi flow chỉ có đúng 1 SYN packet.
//  Nếu không sample tại n=1, flow sẽ expire trước khi đạt n=10 → bỏ sót.
//
//  Guard isPrivateIP(dst_ip):
//    dst_ip là RFC1918 → scan vào internal host → sample ✓
//    dst_ip là public  → outbound connection (CDN, API) → KHÔNG sample
//
//  Tại sao không dùng is_initiator hay src_port:
//    hping3 --rand-source: is_initiator=TRUE, src_port>=1024, dst=RFC1918
//    Client → CDN:443   : is_initiator=TRUE, src_port>=1024, dst=PUBLIC
//    → Chỉ dst_ip phân biệt được.
//
//  ── Case [B]: Sampling định kỳ ───────────────────────────────────────────
//
//  Tại n=10, flow đã hoàn thành ít nhất 1 RTT → features có nghĩa.
//  Không cần guard isPrivateIP: CDN flow tại n=10 có ack_count>0, bwd_bytes>0
//  → XGBoost classify đúng (BENIGN).
//
//  ── Case [C]: SYN flood tích lũy ─────────────────────────────────────────
//
//  Bắt hping3 với IP cố định: 1 flow tích lũy nhiều SYN liên tục.
//  syn_no_ack > 5: nhiều SYN gửi đi không nhận được ACK phản hồi.
//
//  Guard isPrivateIP(dst_ip):
//    CDN có thể có syn_no_ack tạm thời > 5 trong TLS session resumption
//    → Chỉ sample khi dst là internal host.
//
//  ── Edge cases ────────────────────────────────────────────────────────────
//
//  [E1] Attacker trong mạng nội bộ scan ra ngoài:
//    dst_ip = public → case [A] không trigger
//    → L1 SignatureEngine vẫn cover, case [B] tại n=10 vẫn sample
//
//  [E2] Lateral movement (internal → internal):
//    dst_ip = RFC1918 → case [A] trigger ✓
//
//  [E3] hping3 --rand-source probe port lạ:
//    dst_ip = RFC1918 → case [A] trigger ✓
// =============================================================================
bool WorkerThread::shouldSampleForML(const FlowState& flow) const {
    const uint64_t n = flow.total_packets;

    // ── Case [D]: Flow kết thúc (FIN hoặc RST) ───────────────────────────────
    // Sample ngay khi flow đóng để không bỏ sót flow ngắn.
    // Guard: ít nhất 2 packet để có feature có nghĩa.
    if (n >= 2 && (flow.fin_count > 0 || flow.rst_count > 0))
        return true;

    // ── Case [A]: SYN-only flow ───────────────────────────────────────────────
    if (n == 1) {
        if (isPrivateIP(flow.dst_ip))
            return (flow.syn_count > 0 && flow.ack_count == 0);
        return false;
    }

    // ── Case [C]: SYN flood tích lũy ─────────────────────────────────────────
    if (flow.syn_no_ack   >  5
        && n              %  5 == 0
        && isPrivateIP(flow.dst_ip))
    {
        return true;
    }

    // ── Case [B]: Sampling định kỳ ───────────────────────────────────────────
    if (n == 10)                   return true;
    if (n <  200 && n % 50  == 0)  return true;
    if (n >= 200 && n % 200 == 0)  return true;

    return false;
}

// =============================================================================
//  pushMLJob
// =============================================================================
void WorkerThread::pushMLJob(const PacketInfo&  pkt,
                              const FlowState&   flow,
                              const std::string& flow_key)
{
    // ── 1. Record connection vào window counter ───────────────────────────────
    // Gọi TRƯỚC query để "current connection" được tính vào window
    // (NSL-KDD tính "connections including current one")
    window_counter_.recordConnection(flow.dst_ip, flow.dst_port);

    // ── 2. Query window counters ──────────────────────────────────────────────
    const uint32_t cnt      = window_counter_.queryCount2s(flow.dst_ip);
    const uint32_t srv_cnt  = window_counter_.querySrvCount2s(flow.dst_port);
    const uint32_t dh_cnt   = window_counter_.queryDstHostCount(flow.dst_ip);
    const uint32_t dhs_cnt  = window_counter_.queryDstHostSrvCount(
                                  flow.dst_ip, flow.dst_port);

    // ── 3. Build FlowSnapshot ─────────────────────────────────────────────────
    MLJob job;
    job.flow_snapshot = FlowSnapshot::from(flow,
                                           cnt,
                                           srv_cnt,
                                           dh_cnt,
                                           dhs_cnt);

    // ── 4. Fill job metadata ──────────────────────────────────────────────────
    job.flow_key  = flow_key;
    job.src_ip    = pkt.src_ip;
    job.dst_ip    = pkt.dst_ip;
    job.src_port  = pkt.src_port;
    job.dst_port  = pkt.dst_port;
    job.timestamp = pkt.timestamp_d;

    // ── 5. Push vào queue ─────────────────────────────────────────────────────
    if (!ml_job_queue_->push(std::move(job))) {
        METRICS.queue_drops.fetch_add(1, std::memory_order_relaxed);
        LOG_DEBUG("MLJobQueue full, job dropped for flow: " + flow_key);
    }
}
