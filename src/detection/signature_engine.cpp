// src/detection/signature_engine.cpp
#include "signature_engine.hpp"
#include "../common/logger.hpp"
#include <queue>
#include <netinet/in.h>

// ─── Constructor ──────────────────────────────────────────────────────────────
SignatureEngine::SignatureEngine(IpTracker& ip_tracker)
    : ip_tracker_(ip_tracker)
{
    ac_nodes_.emplace_back();
    addPattern("X-a: b\r\n",      SIG_SLOWLORIS);
    addPattern("X-c: d\r\n",      SIG_SLOWLORIS);
    addPattern("X-b: c\r\n",      SIG_SLOWLORIS);
    addPattern("Content-Length:", SIG_SLOW_POST);
    buildFailLinks();
    LOG_INFO("SignatureEngine: Aho-Corasick built, "
             + std::to_string(SIG_COUNT) + " signature groups");
}

// ─── Aho-Corasick ─────────────────────────────────────────────────────────────
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
            const auto& fo = ac_nodes_[candidate].outputs;
            ac_nodes_[v].outputs.insert(ac_nodes_[v].outputs.end(),
                                         fo.begin(), fo.end());
            q.push(v);
        }
    }
}

std::vector<int> SignatureEngine::search(const uint8_t* data,
                                          size_t         len) const {
    std::vector<int> results;
    int cur = 0;
    for (size_t i = 0; i < len; ++i) {
        const uint8_t c = data[i];
        while (cur != 0 && !ac_nodes_[cur].children.count(c))
            cur = ac_nodes_[cur].fail_link;
        auto it = ac_nodes_[cur].children.find(c);
        if (it != ac_nodes_[cur].children.end()) cur = it->second;
        for (int sid : ac_nodes_[cur].outputs) results.push_back(sid);
    }
    return results;
}

// ─── updateFlowState ──────────────────────────────────────────────────────────
void SignatureEngine::updateFlowState(const PacketInfo& pkt,
                                       FlowState&        flow) {
    const auto now = Clock::now();
    flow.total_packets++;
    flow.total_bytes += pkt.orig_len;
    flow.last_seen    = now;
    if (pkt.hasSYN()) flow.syn_count++;
    if (pkt.hasACK()) flow.ack_count++;
    if (pkt.hasRST()) flow.rst_count++;
    if (pkt.hasFIN()) flow.fin_count++;
    const double elapsed = std::chrono::duration<double>(
        now - flow.window_start).count();
    if (elapsed > IpTracker::WINDOW_SEC) {
        flow.pkt_rate_window = 0;
        flow.window_start    = now;
    }
    flow.pkt_rate_window++;
}

// ─── analyze ──────────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::analyze(const PacketInfo& pkt,
                                          FlowState&        flow) {
    updateFlowState(pkt, flow);

    if (!flow.is_initiator)
        return DetectionResult::NORMAL;

    // ── Tất cả logic IpStats chạy TRONG withStats callback ───────────────────
    // Dùng struct nhỏ để truyền kết quả ra ngoài callback (tránh capture ref)
    struct Result {
        DetectionResult detection = DetectionResult::NORMAL;
        std::string     log_msg;
        bool            do_reset_scan = false;
    } res;

    // Snapshot các field cần thiết từ flow (immutable trong callback)
    const uint32_t ack_count_snap = flow.ack_count;

    ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
        // ── checkDDoS ─────────────────────────────────────────────────────────
        if (ip.windowElapsed() > IpTracker::WINDOW_SEC)
            ip.resetWindow();

        ip.pkt_count++;

        if (pkt.protocol == IPPROTO_TCP && pkt.hasSYN() && !pkt.hasACK()) {
            ip.syn_count++;

            const bool flood_port_new =
                ip.flood_ports_seen.insert(pkt.dst_port).second;
            if (!flood_port_new)
                ip.syn_flood_count++;

            ip.scan_ports_seen.insert(pkt.dst_port);

            if (ip.syn_bucket.consume(1.0)) {
                if (ip.syn_count >= MIN_PKT_BEFORE_FLOOD_CHECK) {
                    const double flood_ratio =
                        static_cast<double>(ip.syn_flood_count) /
                        static_cast<double>(ip.syn_count);

                    if (flood_ratio >= FLOOD_RATIO_THRESHOLD) {
                        res.log_msg =
                            "[DDoS] SYN Flood: src="   + pkt.flowKey()
                          + " flood_ratio="            + std::to_string(flood_ratio)
                          + " syn="                    + std::to_string(ip.syn_count)
                          + " flood_syn="              + std::to_string(ip.syn_flood_count)
                          + " bucket="                 + std::to_string(ip.syn_bucket.tokens);
                        res.detection = DetectionResult::DDOS_VOLUMETRIC;
                        return;
                    }
                }
            }
        }

        if (pkt.protocol == IPPROTO_UDP) {
            const bool is_quic = (pkt.dst_port == 443 || pkt.src_port == 443);
            if (!is_quic) {
                ip.udp_count++;
                if (ip.udp_bucket.consume(1.0)) {
                    res.log_msg =
                        "[DDoS] UDP Flood: src=" + pkt.flowKey()
                      + " udp="    + std::to_string(ip.udp_count)
                      + " bucket=" + std::to_string(ip.udp_bucket.tokens);
                    res.detection = DetectionResult::DDOS_VOLUMETRIC;
                    return;
                }
            }
        }

        if (pkt.protocol == IPPROTO_ICMP) {
            ip.icmp_count++;
            if (ip.icmp_bucket.consume(1.0)) {
                res.log_msg =
                    "[DDoS] ICMP Flood: src=" + pkt.flowKey()
                  + " icmp="   + std::to_string(ip.icmp_count)
                  + " bucket=" + std::to_string(ip.icmp_bucket.tokens);
                res.detection = DetectionResult::DDOS_VOLUMETRIC;
                return;
            }
        }

        // ── checkPortScan ─────────────────────────────────────────────────────
        if (pkt.protocol == IPPROTO_TCP) {
            if (!pkt.hasSYN() || pkt.hasACK()) return;

            // Dùng snapshot ack_count từ flow (đã capture trước callback)
            if (ack_count_snap == 0)
                ip.syn_no_ack++;

        } else if (pkt.protocol == IPPROTO_UDP) {
            ip.scan_ports_seen.insert(pkt.dst_port);
        } else {
            return;
        }

        const bool enough_ports  = (ip.scan_ports_seen.size() >= PORT_SCAN_THRESHOLD);
        const bool enough_no_ack = (ip.syn_no_ack >= PORT_SCAN_SYN_NO_ACK_MIN);

        if (enough_ports && enough_no_ack) {
            res.log_msg =
                "[PortScan] detected: src=" + pkt.flowKey()
              + " scan_ports="             + std::to_string(ip.scan_ports_seen.size())
              + " syn_no_ack="             + std::to_string(ip.syn_no_ack);
            ip.resetScanTracking();   // reset TRONG lock, an toàn
            res.detection = DetectionResult::PORT_SCAN;
        }
    });

    // ── Log và trả kết quả NGOÀI lock ─────────────────────────────────────────
    if (!res.log_msg.empty()) {
        if (res.detection == DetectionResult::DDOS_VOLUMETRIC)
            LOG_WARN(res.log_msg);
        else
            LOG_WARN(res.log_msg);
    }

    if (res.detection != DetectionResult::NORMAL)
        return res.detection;

    // ── checkFlagAbuse ────────────────────────────────────────────────────────
    auto r = checkFlagAbuse(pkt);
    if (r != DetectionResult::NORMAL) return r;

    // ── checkPayload ──────────────────────────────────────────────────────────
    if (pkt.payload_len > 0 && pkt.payload() != nullptr)
        return checkPayload(pkt);

    return DetectionResult::NORMAL;
}

// ─── checkFlagAbuse ───────────────────────────────────────────────────────────
DetectionResult SignatureEngine::checkFlagAbuse(const PacketInfo& pkt) {
    if (pkt.protocol != IPPROTO_TCP) return DetectionResult::NORMAL;

    constexpr uint8_t XMAS = TCPFlags::FIN | TCPFlags::PSH | TCPFlags::URG;
    if ((pkt.tcp_flags & XMAS) == XMAS) {
        LOG_WARN("[FlagAbuse] XMAS Scan: " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }
    if (pkt.tcp_flags == 0x00) {
        LOG_WARN("[FlagAbuse] NULL Scan: " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }
    if ((pkt.tcp_flags & TCPFlags::FIN) && !(pkt.tcp_flags & TCPFlags::ACK)) {
        LOG_WARN("[FlagAbuse] FIN Scan: " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }
    return DetectionResult::NORMAL;
}

// ─── checkPayload ─────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::checkPayload(const PacketInfo& pkt) {
    const auto matches = search(pkt.payload(), pkt.payload_len);
    for (int sid : matches) {
        if (sid == SIG_SLOWLORIS) {
            LOG_WARN("[Payload] Slowloris: " + pkt.flowKey());
            return DetectionResult::SLOW_DDOS;
        }
    }
    return DetectionResult::NORMAL;
}
