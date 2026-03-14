//src/detection/signature_engine.cpp
#include "signature_engine.hpp"
#include "../common/logger.hpp"
#include <queue>
#include <arpa/inet.h>

SignatureEngine::SignatureEngine() {
    nodes_.emplace_back(); // Root node

    // Slowloris: gửi header từng phần, không bao giờ kết thúc
    addPattern("X-a: b\r\n",        SIG_SLOWLORIS);
    addPattern("X-c: d\r\n",        SIG_SLOWLORIS);

    // Slow POST: Content-Length lớn nhưng body gửi chậm
    addPattern("Content-Length:",   SIG_SLOW_POST);

    // XMAS scan: FIN+PSH+URG set
    // NULL scan: không có flag nào
    // (Các scan này được detect qua flag check, không qua payload)

    buildFailLinks();
    LOG_INFO("SignatureEngine initialized with "
             + std::to_string(SIG_COUNT) + " signature groups");
}

// ─── Aho-Corasick: Add Pattern ────────────────────────────────────────────────
void SignatureEngine::addPattern(const std::string& pattern, int sig_id) {
    int cur = 0;
    for (char c : pattern) {
        if (!nodes_[cur].children.count(c)) {
            nodes_[cur].children[c] = static_cast<int>(nodes_.size());
            nodes_.emplace_back();
        }
        cur = nodes_[cur].children[c];
    }
    nodes_[cur].outputs.push_back(sig_id);
}

// ─── Aho-Corasick: Build Fail Links (BFS) ────────────────────────────────────
void SignatureEngine::buildFailLinks() {
    std::queue<int> q;

    // Level 1: fail về root
    for (auto& [c, child] : nodes_[0].children) {
        nodes_[child].fail_link = 0;
        q.push(child);
    }

    while (!q.empty()) {
        int u = q.front(); q.pop();

        for (auto& [c, v] : nodes_[u].children) {
            int f = nodes_[u].fail_link;

            while (f != 0 && !nodes_[f].children.count(c))
                f = nodes_[f].fail_link;

            nodes_[v].fail_link = (nodes_[f].children.count(c) && nodes_[f].children.at(c) != v)
                                   ? nodes_[f].children.at(c) : 0;

            // Kế thừa outputs từ fail link
            auto& fail_out = nodes_[nodes_[v].fail_link].outputs;
            nodes_[v].outputs.insert(
                nodes_[v].outputs.end(),
                fail_out.begin(), fail_out.end());

            q.push(v);
        }
    }
}

// ─── Aho-Corasick: Search ─────────────────────────────────────────────────────
std::vector<int> SignatureEngine::search(const uint8_t* data,
                                          size_t         len) const {
    std::vector<int> results;
    int cur = 0;

    for (size_t i = 0; i < len; i++) {
        char c = static_cast<char>(data[i]);

        while (cur != 0 && !nodes_[cur].children.count(c))
            cur = nodes_[cur].fail_link;

        if (nodes_[cur].children.count(c))
            cur = nodes_[cur].children.at(c);

        for (int sig_id : nodes_[cur].outputs)
            results.push_back(sig_id);
    }
    return results;
}

// ─── Main Analyze ─────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::analyze(const PacketInfo& pkt,
                                          FlowState&        flow) {
    // 1. Cập nhật flow state
    flow.total_packets++;
    flow.total_bytes += pkt.orig_len;
    flow.last_seen    = Clock::now();

    // Cập nhật TCP flag counters
    if (pkt.hasSYN()) flow.syn_count++;
    if (pkt.hasACK()) flow.ack_count++;
    if (pkt.hasRST()) flow.rst_count++;
    if (pkt.hasFIN()) flow.fin_count++;

    // Cập nhật sliding window
    double elapsed = std::chrono::duration<double>(
        Clock::now() - flow.window_start).count();
    if (elapsed > WINDOW_SECONDS)
        flow.resetWindow();
    flow.pkt_rate_window++;

    // 2. Kiểm tra DDoS rules
    auto ddos_result = checkDDoSRules(pkt, flow);
    if (ddos_result != DetectionResult::NORMAL)
        return ddos_result;

    // 3. Kiểm tra Port Scan rules
    auto scan_result = checkPortScanRules(pkt, flow);
    if (scan_result != DetectionResult::NORMAL)
        return scan_result;

    // 4. Kiểm tra payload signatures (Aho-Corasick)
    if (pkt.payload_len > 0) {
        auto payload_result = checkPayloadSignatures(pkt);
        if (payload_result != DetectionResult::NORMAL)
            return payload_result;
    }

    return DetectionResult::NORMAL;
}

// ─── DDoS Rules ───────────────────────────────────────────────────────────────
DetectionResult SignatureEngine::checkDDoSRules(const PacketInfo& pkt,
                                                 FlowState&        flow) {
    // Rule 1: SYN Flood — quá nhiều SYN không có ACK
    if (pkt.hasSYN() && !pkt.hasACK()) {
        flow.syn_no_ack++;
        if (flow.syn_no_ack > SYN_RATE_THRESHOLD) {
            LOG_WARN("SYN Flood detected from "
                     + pkt.flowKey()
                     + " | SYN count: " + std::to_string(flow.syn_no_ack));
            return DetectionResult::DDOS_VOLUMETRIC;
        }
    }

    // Rule 2: UDP Flood — packet rate cao từ 1 IP
    if (pkt.protocol == IPPROTO_UDP) {
        if (flow.packetRate() > UDP_RATE_THRESHOLD) {
            LOG_WARN("UDP Flood detected from "
                     + pkt.flowKey()
                     + " | Rate: " + std::to_string(flow.packetRate()) + " pps");
            return DetectionResult::DDOS_VOLUMETRIC;
        }
    }

    return DetectionResult::NORMAL;
}

// ─── Port Scan Rules ──────────────────────────────────────────────────────────
DetectionResult SignatureEngine::checkPortScanRules(const PacketInfo& pkt,
                                                     FlowState&        flow) {
    // Theo dõi các port đích khác nhau từ cùng src_ip
    if (pkt.dst_port > 0)
        flow.dst_ports_seen.insert(pkt.dst_port);

    // Rule 1: Quá nhiều port khác nhau trong 10s
    if (flow.dst_ports_seen.size() > PORT_SCAN_THRESHOLD) {
        LOG_WARN("Port Scan detected from "
                 + pkt.flowKey()
                 + " | Unique ports: "
                 + std::to_string(flow.dst_ports_seen.size()));
        return DetectionResult::PORT_SCAN;
    }

    // Rule 2: XMAS scan (FIN + PSH + URG)
    constexpr uint8_t XMAS_FLAGS = TCPFlags::FIN | TCPFlags::PSH | TCPFlags::URG;
    if ((pkt.tcp_flags & XMAS_FLAGS) == XMAS_FLAGS) {
        LOG_WARN("XMAS Scan detected from " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }

    // Rule 3: NULL scan (không có flag nào)
    if (pkt.protocol == IPPROTO_TCP && pkt.tcp_flags == 0x00) {
        LOG_WARN("NULL Scan detected from " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }

    // Rule 4: SYN/RST ratio cao
    if (flow.syn_count > 10 && flow.rst_count > 0) {
        double ratio = static_cast<double>(flow.rst_count)
                     / static_cast<double>(flow.syn_count);
        if (ratio > SYN_RST_RATIO) {
            LOG_WARN("High SYN/RST ratio from "
                     + pkt.flowKey()
                     + " | Ratio: " + std::to_string(ratio));
            return DetectionResult::PORT_SCAN;
        }
    }

    return DetectionResult::NORMAL;
}

// ─── Payload Signature Check ──────────────────────────────────────────────────
DetectionResult SignatureEngine::checkPayloadSignatures(const PacketInfo& pkt) {
    auto matches = search(pkt.payload(), pkt.payload_len);

    for (int sig_id : matches) {
        switch (sig_id) {
            case SIG_SLOWLORIS:
                LOG_WARN("Slowloris signature detected from "
                         + pkt.flowKey());
                return DetectionResult::SLOW_DDOS;

            case SIG_SLOW_POST:
                // Content-Length sẽ được validate thêm ở ProtocolAnomaly
                break;

            default:
                break;
        }
    }
    return DetectionResult::NORMAL;
}
