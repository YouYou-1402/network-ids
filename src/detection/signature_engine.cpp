// src/detection/signature_engine.cpp
#include "signature_engine.hpp"
#include "../common/logger.hpp"
#include <queue>
#include <netinet/in.h>

// ─── Constructor ──────────────────────────────────────────────────────────────
SignatureEngine::SignatureEngine(IpTracker& ip_tracker)
    : ip_tracker_(ip_tracker)
{
    ac_nodes_.emplace_back(); // root

    addPattern("X-a: b\r\n", SIG_SLOWLORIS);
    addPattern("X-c: d\r\n", SIG_SLOWLORIS);
    addPattern("X-b: c\r\n", SIG_SLOWLORIS);
    addPattern("Content-Length:", SIG_SLOW_POST);

    buildFailLinks();
    LOG_INFO("SignatureEngine: Aho-Corasick built, "
             + std::to_string(SIG_COUNT) + " signature groups");
}

// ─── Aho-Corasick: addPattern ─────────────────────────────────────────────────
void SignatureEngine::addPattern(const std::string& pattern, int sig_id) {
    int cur = 0;
    for (unsigned char c : pattern) {
        auto it = ac_nodes_[cur].children.find(c);
        if (it == ac_nodes_[cur].children.end()) {
            ac_nodes_[cur].children[c] = static_cast<int>(ac_nodes_.size());
            ac_nodes_.emplace_back();
        }
        cur = ac_nodes_[cur].children[c];
    }
    ac_nodes_[cur].outputs.push_back(sig_id);
}

// ─── Aho-Corasick: buildFailLinks (BFS) ──────────────────────────────────────
void SignatureEngine::buildFailLinks() {
    std::queue<int> q;

    for (auto& [c, child] : ac_nodes_[0].children) {
        ac_nodes_[child].fail_link = 0;
        q.push(child);
    }

    while (!q.empty()) {
        int u = q.front(); q.pop();

        for (auto& [c, v] : ac_nodes_[u].children) {
            int f = ac_nodes_[u].fail_link;
            while (f != 0 && !ac_nodes_[f].children.count(c))
                f = ac_nodes_[f].fail_link;

            int candidate = 0;
            auto fit = ac_nodes_[f].children.find(c);
            if (fit != ac_nodes_[f].children.end() && fit->second != v)
                candidate = fit->second;

            ac_nodes_[v].fail_link = candidate;

            const auto& fail_out = ac_nodes_[candidate].outputs;
            ac_nodes_[v].outputs.insert(
                ac_nodes_[v].outputs.end(),
                fail_out.begin(), fail_out.end());

            q.push(v);
        }
    }
}

// ─── Aho-Corasick: search ─────────────────────────────────────────────────────
std::vector<int> SignatureEngine::search(const uint8_t* data,
                                          size_t         len) const {
    std::vector<int> results;
    int cur = 0;

    for (size_t i = 0; i < len; ++i) {
        const uint8_t c = data[i];

        while (cur != 0 && !ac_nodes_[cur].children.count(c))
            cur = ac_nodes_[cur].fail_link;

        auto it = ac_nodes_[cur].children.find(c);
        if (it != ac_nodes_[cur].children.end())
            cur = it->second;

        for (int sid : ac_nodes_[cur].outputs)
            results.push_back(sid);
    }
    return results;
}

// ─── analyze ──────────────────────────────────────────────────────────────────
//
//  Chỉ phân tích packet thuộc flow do attacker/client khởi tạo.
//
//  flow.is_initiator được set trong FlowTable::createFlow():
//    true  → SYN probe, XMAS, NULL, FIN scan, UDP/ICMP packet đầu tiên
//    false → RST response, SYN-ACK, ACK từ server
//
//  Lý do filter response:
//    Khi nmap scan 1000 port, server trả 1000 RST response.
//    Mỗi RST có src_port khác nhau (80, 443, 22...) nhưng dst_port = ephemeral.
//    Nếu không filter, IpStats của server sẽ tích lũy dst_ports_seen
//    → false positive PORT_SCAN trên server IP.
//
//  checkFlagAbuse() vẫn chạy cho cả response flow vì:
//    XMAS/NULL/FIN scan có is_initiator = true (set trong createFlow)
//    → không bị filter ở đây.
// ─────────────────────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::analyze(const PacketInfo& pkt,
                                          FlowState&        flow) {
    updateFlowState(pkt, flow);

    // ── Filter: chỉ analyze probe/initiator flow ──────────────────────────────
    // Response packet từ server (RST, SYN-ACK...) → bỏ qua
    if (!flow.is_initiator)
        return DetectionResult::NORMAL;

    // ── Rate-based detection (cần IpStats của src_ip) ────────────────────────
    IpStats* ip = ip_tracker_.getOrCreate(pkt.src_ip);
    if (ip) {
        // checkDDoS trước: nếu đã là flood thì không cần check port scan
        auto r = checkDDoS(pkt, *ip);
        if (r != DetectionResult::NORMAL) return r;

        r = checkPortScan(pkt, *ip);
        if (r != DetectionResult::NORMAL) return r;
    }

    // ── Flag abuse (XMAS, NULL, FIN scan) ────────────────────────────────────
    auto r = checkFlagAbuse(pkt);
    if (r != DetectionResult::NORMAL) return r;

    // ── Payload signature ─────────────────────────────────────────────────────
    if (pkt.payload_len > 0 && pkt.payload() != nullptr) {
        r = checkPayload(pkt);
        if (r != DetectionResult::NORMAL) return r;
    }

    return DetectionResult::NORMAL;
}

// ─── updateFlowState ──────────────────────────────────────────────────────────
void SignatureEngine::updateFlowState(const PacketInfo& pkt,
                                       FlowState&        flow) {
    const auto now = Clock::now();

    flow.total_packets++;
    flow.total_bytes += pkt.orig_len;
    flow.last_seen    = now;

    if (pkt.hasSYN()) { flow.syn_count++; }
    if (pkt.hasACK()) { flow.ack_count++; }
    if (pkt.hasRST()) { flow.rst_count++; }
    if (pkt.hasFIN()) { flow.fin_count++; }

    // Reset sliding window sau WINDOW_SEC giây
    const double elapsed = std::chrono::duration<double>(
        now - flow.window_start).count();
    if (elapsed > IpTracker::WINDOW_SEC) {
        flow.pkt_rate_window = 0;
        flow.window_start    = now;
    }
    flow.pkt_rate_window++;
}

// ─── checkDDoS ────────────────────────────────────────────────────────────────
//
//  Gọi sau khi đã xác nhận flow.is_initiator = true
//  → pkt.src_ip chắc chắn là attacker, không phải server
//
//  SYN Flood vs Port Scan:
//    Cả 2 đều gửi nhiều SYN → phân biệt bằng port_diversity
//
//    port_diversity = unique_dst_ports / syn_count
//      SYN Flood : flood vào 1-2 port → diversity thấp (< 0.3)
//      Port Scan : mỗi SYN 1 port mới → diversity cao (≈ 1.0)
//
//    Nếu diversity cao → KHÔNG báo DDOS, để checkPortScan xử lý
//
//  Lưu ý: ip.dst_ports_seen được populate bởi checkPortScan()
//         checkDDoS() chỉ đọc size() để tính diversity
//         → thứ tự gọi: checkDDoS trước, checkPortScan sau (trong analyze)
//         → nhưng ip.dst_ports_seen chưa có giá trị mới của packet này!
//
//  Fix: insert dst_port vào ip.dst_ports_seen ngay trong checkDDoS
//       để diversity tính đúng cho packet hiện tại
// ─────────────────────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::checkDDoS(const PacketInfo& pkt,
                                            IpStats&          ip) {
    ip.pkt_count++;

    // ── SYN Flood ──────────────────────────────────────────────────────────────
    if (pkt.protocol == IPPROTO_TCP && pkt.hasSYN() && !pkt.hasACK()) {
        // Insert dst_port trước để diversity tính đúng
        ip.dst_ports_seen.insert(pkt.dst_port);
        ip.syn_count++;

        if (ip.syn_count > SYN_FLOOD_THRESHOLD) {
            const double diversity =
                static_cast<double>(ip.dst_ports_seen.size()) / ip.syn_count;

            if (diversity < PORT_DIVERSITY_FLOOD_THRESHOLD) {
                // Diversity thấp → flood vào ít port → SYN Flood
                LOG_WARN("SYN Flood: src="   + pkt.flowKey()
                         + " syn="           + std::to_string(ip.syn_count)
                         + " ports="         + std::to_string(ip.dst_ports_seen.size())
                         + " diversity="     + std::to_string(diversity)
                         + "/"               + std::to_string(IpTracker::WINDOW_SEC) + "s");
                return DetectionResult::DDOS_VOLUMETRIC;
            }
            // Diversity cao → port scan, checkPortScan sẽ xử lý
            // dst_port đã được insert ở trên → checkPortScan không cần insert lại
        }
    }

    // ── UDP Flood ──────────────────────────────────────────────────────────────
    if (pkt.protocol == IPPROTO_UDP) {
        ip.udp_count++;
        if (ip.udp_count > UDP_FLOOD_THRESHOLD) {
            LOG_WARN("UDP Flood: src=" + pkt.flowKey()
                     + " udp=" + std::to_string(ip.udp_count)
                     + "/" + std::to_string(IpTracker::WINDOW_SEC) + "s");
            return DetectionResult::DDOS_VOLUMETRIC;
        }
    }

    // ── ICMP Flood ─────────────────────────────────────────────────────────────
    if (pkt.protocol == IPPROTO_ICMP) {
        ip.icmp_count++;
        if (ip.icmp_count > ICMP_FLOOD_THRESHOLD) {
            LOG_WARN("ICMP Flood: src=" + pkt.flowKey()
                     + " icmp=" + std::to_string(ip.icmp_count)
                     + "/" + std::to_string(IpTracker::WINDOW_SEC) + "s");
            return DetectionResult::DDOS_VOLUMETRIC;
        }
    }

    return DetectionResult::NORMAL;
}

// ─── checkPortScan ────────────────────────────────────────────────────────────
//
//  Gọi sau khi đã xác nhận flow.is_initiator = true
//  → pkt.dst_port là port đích thực sự bị probe, không phải ephemeral port
//
//  Chỉ track SYN probe (SYN && !ACK) và UDP probe:
//    - RST, ACK, FIN không phải probe → bỏ qua
//    - XMAS/NULL/FIN scan được xử lý bởi checkFlagAbuse(), không cần ở đây
//
//  dst_ports_seen:
//    - TCP SYN: đã được insert trong checkDDoS() → KHÔNG insert lại
//    - UDP:     insert ở đây
//
//  Rule: unique dst_port > PORT_SCAN_THRESHOLD → Port Scan
// ─────────────────────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::checkPortScan(const PacketInfo& pkt,
                                                IpStats&          ip) {
    if (pkt.protocol != IPPROTO_TCP && pkt.protocol != IPPROTO_UDP)
        return DetectionResult::NORMAL;

    if (pkt.protocol == IPPROTO_TCP) {
        // SYN probe: dst_port đã được insert trong checkDDoS()
        // Chỉ cần track syn_no_ack counter
        if (pkt.hasSYN() && !pkt.hasACK()) {
            ip.syn_no_ack++;
        } else {
            // RST, ACK, FIN... → không phải probe → bỏ qua
            // (Dù is_initiator = true, các packet này không phải scan probe)
            return DetectionResult::NORMAL;
        }
    }

    if (pkt.protocol == IPPROTO_UDP) {
        // UDP probe: insert dst_port ở đây (checkDDoS không xử lý UDP port scan)
        ip.dst_ports_seen.insert(pkt.dst_port);
    }

    // Rule: Nhiều unique dst_port → Port Scan
    if (ip.dst_ports_seen.size() > PORT_SCAN_THRESHOLD) {
        LOG_WARN("Port Scan (multi-port): src=" + pkt.flowKey()
                 + " ports=" + std::to_string(ip.dst_ports_seen.size())
                 + "/" + std::to_string(IpTracker::WINDOW_SEC) + "s");
        return DetectionResult::PORT_SCAN;
    }

    return DetectionResult::NORMAL;
}

// ─── checkFlagAbuse ───────────────────────────────────────────────────────────
//
//  Detect các scan dùng flag bất thường:
//    XMAS scan : FIN + PSH + URG
//    NULL scan : không có flag nào (0x00)
//    FIN scan  : chỉ FIN, không ACK
//
//  Các packet này có is_initiator = true (set trong createFlow)
//  nên vẫn đến được hàm này dù analyze() filter response.
// ─────────────────────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::checkFlagAbuse(const PacketInfo& pkt) {
    if (pkt.protocol != IPPROTO_TCP) return DetectionResult::NORMAL;

    constexpr uint8_t XMAS = TCPFlags::FIN | TCPFlags::PSH | TCPFlags::URG;
    if ((pkt.tcp_flags & XMAS) == XMAS) {
        LOG_WARN("XMAS Scan: " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }

    if (pkt.tcp_flags == 0x00) {
        LOG_WARN("NULL Scan: " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }

    if ((pkt.tcp_flags & TCPFlags::FIN) && !(pkt.tcp_flags & TCPFlags::ACK)) {
        LOG_WARN("FIN Scan: " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }

    return DetectionResult::NORMAL;
}

// ─── checkPayload ─────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::checkPayload(const PacketInfo& pkt) {
    const auto matches = search(pkt.payload(), pkt.payload_len);

    for (int sid : matches) {
        if (sid == SIG_SLOWLORIS) {
            LOG_WARN("Slowloris header pattern: " + pkt.flowKey());
            return DetectionResult::SLOW_DDOS;
        }
    }
    return DetectionResult::NORMAL;
}