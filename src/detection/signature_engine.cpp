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
DetectionResult SignatureEngine::analyze(const PacketInfo& pkt,
                                          FlowState&        flow) {
    updateFlowState(pkt, flow);

    IpStats* ip = ip_tracker_.getOrCreate(pkt.src_ip);

    if (ip) {
        auto r = checkDDoS(pkt, *ip);
        if (r != DetectionResult::NORMAL) return r;

        r = checkPortScan(pkt, *ip);
        if (r != DetectionResult::NORMAL) return r;
    }

    auto r = checkFlagAbuse(pkt);
    if (r != DetectionResult::NORMAL) return r;

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

    const double elapsed = std::chrono::duration<double>(
        now - flow.window_start).count();
    if (elapsed > IpTracker::WINDOW_SEC) {
        flow.pkt_rate_window = 0;
        flow.window_start    = now;
    }
    flow.pkt_rate_window++;
}

// ─── checkDDoS ────────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::checkDDoS(const PacketInfo& pkt,
                                            IpStats&          ip) {
    ip.pkt_count++;

    if (pkt.protocol == IPPROTO_TCP && pkt.hasSYN() && !pkt.hasACK()) {
        ip.syn_count++;
        if (ip.syn_count > SYN_FLOOD_THRESHOLD) {
            LOG_WARN("SYN Flood: src=" + pkt.flowKey()
                     + " syn=" + std::to_string(ip.syn_count)
                     + "/" + std::to_string(IpTracker::WINDOW_SEC) + "s");
            return DetectionResult::DDOS_VOLUMETRIC;
        }
    }

    if (pkt.protocol == IPPROTO_UDP) {
        ip.udp_count++;
        if (ip.udp_count > UDP_FLOOD_THRESHOLD) {
            LOG_WARN("UDP Flood: src=" + pkt.flowKey()
                     + " udp=" + std::to_string(ip.udp_count)
                     + "/" + std::to_string(IpTracker::WINDOW_SEC) + "s");
            return DetectionResult::DDOS_VOLUMETRIC;
        }
    }

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
//  FIX BUG 2: Phân biệt SYN Flood vs Port Scan
//
//  Vấn đề cũ:
//    hping3 -S -p 80 → flood 1 port → server trả RST liên tục
//    → rst_received > 15 → báo PORT_SCAN (sai)
//
//  Logic mới:
//    Rule 1 (multi-port): dst_ports_seen > PORT_SCAN_THRESHOLD
//                         → Port Scan rõ ràng
//
//    Rule 2 (RST-based):  rst_received > RST_SCAN_THRESHOLD
//                         VÀ dst_ports_seen >= RST_SCAN_MIN_PORTS
//                         → RST nhiều + nhiều port = SYN scan
//                         → RST nhiều + 1 port = SYN flood (để checkDDoS xử lý)
//
//    Không reset rst_received trong hàm này — IpStats.resetWindow() lo
// ─────────────────────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::checkPortScan(const PacketInfo& pkt,
                                                IpStats&          ip) {
    if (pkt.protocol != IPPROTO_TCP && pkt.protocol != IPPROTO_UDP)
        return DetectionResult::NORMAL;

    if (pkt.dst_port > 0)
        ip.dst_ports_seen.insert(pkt.dst_port);

    if (pkt.protocol == IPPROTO_TCP && pkt.hasSYN() && !pkt.hasACK())
        ip.syn_no_ack++;

    if (pkt.protocol == IPPROTO_TCP && pkt.hasRST())
        ip.rst_received++;

    // Rule 1: Nhiều unique port → Port Scan
    if (ip.dst_ports_seen.size() > PORT_SCAN_THRESHOLD) {
        LOG_WARN("Port Scan (multi-port): src=" + pkt.flowKey()
                 + " ports=" + std::to_string(ip.dst_ports_seen.size())
                 + "/" + std::to_string(IpTracker::WINDOW_SEC) + "s");
        return DetectionResult::PORT_SCAN;
    }

    // Rule 2: RST nhiều → chỉ báo PORT_SCAN khi unique ports đủ lớn
    // FIX: thêm điều kiện dst_ports_seen.size() >= RST_SCAN_MIN_PORTS
    if (ip.rst_received > RST_SCAN_THRESHOLD) {
        const size_t unique_ports = ip.dst_ports_seen.size();
        if (unique_ports >= RST_SCAN_MIN_PORTS) {
            LOG_WARN("Port Scan (SYN scan): src=" + pkt.flowKey()
                     + " rst=" + std::to_string(ip.rst_received)
                     + " ports=" + std::to_string(unique_ports));
            return DetectionResult::PORT_SCAN;
        }
        // unique_ports < RST_SCAN_MIN_PORTS:
        // RST nhiều nhưng chỉ 1 port → SYN flood, không phải scan
        // checkDDoS đã/sẽ xử lý qua syn_count threshold
    }

    return DetectionResult::NORMAL;
}

// ─── checkFlagAbuse ───────────────────────────────────────────────────────────
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