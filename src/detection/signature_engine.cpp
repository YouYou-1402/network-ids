// =============================================================================
//  src/detection/signature_engine.cpp
// =============================================================================
#include "signature_engine.hpp"
#include "../common/logger.hpp"
#include "../common/config_loader.hpp"
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <queue>
#include <algorithm>
#include <cstring>

// =============================================================================
//  Constructor — đọc pattern từ rules.json thay vì hardcode
// =============================================================================
SignatureEngine::SignatureEngine(IpTracker& ip_tracker)
    : ip_tracker_(ip_tracker)
{
    const auto& sig = APP_CFG.signatures;
    const auto& th  = APP_CFG.thresholds;

    flood_ratio_threshold_      = sig.flood_ratio;
    port_scan_threshold_        = sig.port_scan_ports;
    port_scan_syn_no_ack_min_   = sig.port_scan_syn_no_ack_min;
    min_pkt_before_flood_check_ = sig.min_pkt_before_flood;
    global_syn_threshold_       = th.global_syn_threshold;
    dst_syn_ratio_min_pkt_      = th.dst_syn_ratio_min_pkt;
    dst_syn_ack_ratio_          = th.dst_syn_ack_ratio;
    behavior_window_sec_        = th.behavior_window_sec;

    // ── Build Aho-Corasick ────────────────────────────────────────────────
    ac_nodes_.emplace_back();   // root node

    if (!sig.sig_rules.empty()) {
        // ── Load từ rules.json ────────────────────────────────────────────
        for (const auto& rule : sig.sig_rules) {
            // Map threat string → sig_id
            // Quy ước: SIG_SLOWLORIS=0, SIG_SLOW_POST=1
            // Mở rộng thêm sig_id mới ở đây nếu cần
            int sig_id = SIG_SLOWLORIS;
            if (rule.threat == "SLOW_DDOS") {
                const bool is_post =
                    rule.name.find("POST") != std::string::npos ||
                    rule.name.find("post") != std::string::npos ||
                    rule.id.find("POST")   != std::string::npos;
                sig_id = is_post ? SIG_SLOW_POST : SIG_SLOWLORIS;
            }

            rule_map_[sig_id] = rule;
            addPattern(rule.pattern, sig_id);

            LOG_INFO("SignatureEngine: loaded rule ["
                     + rule.id + "] " + rule.name
                     + " pattern='" + rule.pattern + "'"
                     + " threat="   + rule.threat
                     + " action="   + rule.action);
        }
    } else {
        // ── Fallback hardcode nếu rules.json không có "signatures" ────────
        LOG_WARN("SignatureEngine: no sig_rules from config"
                 " — using hardcoded fallback");

        addPattern("X-a: b\r\n",      SIG_SLOWLORIS);
        addPattern("X-c: d\r\n",      SIG_SLOWLORIS);
        addPattern("X-b: c\r\n",      SIG_SLOWLORIS);
        addPattern("Content-Length:", SIG_SLOW_POST);

        // Tạo rule_map_ giả để handleDetection vẫn hoạt động
        SignatureRule fallback_sl;
        fallback_sl.id     = "FALLBACK_SL";
        fallback_sl.threat = "SLOW_DDOS";
        fallback_sl.action = "ALERT";
        rule_map_[SIG_SLOWLORIS] = fallback_sl;

        SignatureRule fallback_sp;
        fallback_sp.id     = "FALLBACK_SP";
        fallback_sp.threat = "SLOW_DDOS";
        fallback_sp.action = "ALERT";
        rule_map_[SIG_SLOW_POST] = fallback_sp;
    }

    buildFailLinks();

    LOG_INFO("SignatureEngine: initialized"
             " patterns="        + std::to_string(sig.sig_rules.size())
           + " flood_ratio="     + std::to_string(flood_ratio_threshold_)
           + " port_scan_ports=" + std::to_string(port_scan_threshold_)
           + " global_syn_thr="  + std::to_string(global_syn_threshold_)
           + " dst_ratio="       + std::to_string(dst_syn_ack_ratio_));
}

// =============================================================================
//  Aho-Corasick — addPattern
// =============================================================================
void SignatureEngine::addPattern(const std::string& pattern, int sig_id) {
    int cur = 0;
    for (unsigned char c : pattern) {
        if (ac_nodes_[cur].children[c] == -1) {
            ac_nodes_[cur].children[c] = static_cast<int>(ac_nodes_.size());
            ac_nodes_.emplace_back();
        }
        cur = ac_nodes_[cur].children[c];
    }
    ac_nodes_[cur].is_end  = true;
    ac_nodes_[cur].output  = sig_id;
}

// =============================================================================
//  Aho-Corasick — buildFailLinks  (BFS)
// =============================================================================
void SignatureEngine::buildFailLinks() {
    std::queue<int> q;

    // Root children: fail → root
    for (int c = 0; c < 256; ++c) {
        int ch = ac_nodes_[0].children[c];
        if (ch == -1) {
            ac_nodes_[0].children[c] = 0;
        } else {
            ac_nodes_[ch].fail = 0;
            q.push(ch);
        }
    }

    while (!q.empty()) {
        int u = q.front(); q.pop();
        // Propagate output along fail chain
        if (ac_nodes_[u].output == -1)
            ac_nodes_[u].output = ac_nodes_[ac_nodes_[u].fail].output;

        for (int c = 0; c < 256; ++c) {
            int ch = ac_nodes_[u].children[c];
            if (ch == -1) {
                ac_nodes_[u].children[c] =
                    ac_nodes_[ac_nodes_[u].fail].children[c];
            } else {
                ac_nodes_[ch].fail =
                    ac_nodes_[ac_nodes_[u].fail].children[c];
                q.push(ch);
            }
        }
    }
}

// =============================================================================
//  Aho-Corasick — acSearch
//  Trả về sig_id đầu tiên match, hoặc SIG_NONE nếu không match
// =============================================================================
int SignatureEngine::acSearch(const uint8_t* data, size_t len) const {
    int cur = 0;
    for (size_t i = 0; i < len; ++i) {
        cur = ac_nodes_[cur].children[static_cast<unsigned char>(data[i])];
        if (ac_nodes_[cur].output != -1)
            return ac_nodes_[cur].output;
    }
    return SIG_NONE;
}

// =============================================================================
//  analyze — main entry point
// =============================================================================
DetectionResult SignatureEngine::analyze(const PacketInfo& pkt,
                                          FlowState&        flow) {
    // ── Global SYN flood (distributed, bất kể src) ────────────────────────
    if (pkt.hasSYN() && !pkt.hasACK()) {
        auto r = checkGlobalSyn(pkt);
        if (r != DetectionResult::NORMAL) return r;

        r = checkDstSynRatio(pkt);
        if (r != DetectionResult::NORMAL) return r;
    }

    // ── Per-source checks ─────────────────────────────────────────────────
    auto r = checkFloodRate(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    r = checkPortScan(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    r = checkFlagAbuse(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    return checkPayload(pkt, flow);
}

// =============================================================================
//  checkGlobalSyn
// =============================================================================
DetectionResult SignatureEngine::checkGlobalSyn(const PacketInfo& pkt) {
    const bool over = IpTracker::globalSyn().record(
        global_syn_threshold_, behavior_window_sec_);

    if (over) {
        LOG_WARN("SignatureEngine: global SYN flood"
                 " window_syns=" +
                 std::to_string(IpTracker::globalSyn().getWindowSyns())
                 + " threshold=" + std::to_string(global_syn_threshold_));
        return DetectionResult::DDOS_VOLUMETRIC;
    }
    return DetectionResult::NORMAL;
}

// =============================================================================
//  checkDstSynRatio
// =============================================================================
DetectionResult SignatureEngine::checkDstSynRatio(const PacketInfo& pkt) {
    DetectionResult result = DetectionResult::NORMAL;

    dst_tracker_.withStats(pkt.dst_ip, [&](DstStats& dst) {
        dst.syn_count++;

        // Reset window nếu hết thời gian
        if (dst.windowElapsed() > behavior_window_sec_)
            dst.resetWindow();

        if (dst.syn_count < dst_syn_ratio_min_pkt_)
            return;

        if (dst.synAckRatio() >= dst_syn_ack_ratio_) {
            LOG_WARN("SignatureEngine: dst SYN/ACK ratio flood"
                     " syn="   + std::to_string(dst.syn_count)
                     + " ack=" + std::to_string(dst.ack_count)
                     + " ratio=" + std::to_string(dst.synAckRatio()));
            result = DetectionResult::DDOS_VOLUMETRIC;
        }
    });

    return result;
}

// =============================================================================
//  checkFloodRate
// =============================================================================
DetectionResult SignatureEngine::checkFloodRate(const PacketInfo& pkt,
                                                 FlowState&        flow) {
    DetectionResult result = DetectionResult::NORMAL;

    ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
        ip.pkt_count++;

        // Reset window mỗi behavior_window_sec_
        if (ip.windowElapsed() > behavior_window_sec_)
            ip.resetWindow();

        if (pkt.hasSYN() && !pkt.hasACK()) {
            ip.syn_count++;
            ip.syn_flood_count++;

            // Token bucket consume
            if (ip.syn_bucket.consume()) {
                if (ip.pkt_count >= min_pkt_before_flood_check_) {
                    LOG_WARN("SignatureEngine: SYN flood"
                             " src=" + pkt.flowKey()
                             + " syn=" + std::to_string(ip.syn_count));
                    result = DetectionResult::DDOS_VOLUMETRIC;
                }
            }
        } else if (pkt.protocol == IPPROTO_UDP) {
            ip.udp_count++;
            if (ip.udp_bucket.consume()) {
                LOG_WARN("SignatureEngine: UDP flood"
                         " src=" + pkt.flowKey()
                         + " udp=" + std::to_string(ip.udp_count));
                result = DetectionResult::DDOS_VOLUMETRIC;
            }
        } else if (pkt.protocol == IPPROTO_ICMP) {
            ip.icmp_count++;
            if (ip.icmp_bucket.consume()) {
                LOG_WARN("SignatureEngine: ICMP flood"
                         " src=" + pkt.flowKey()
                         + " icmp=" + std::to_string(ip.icmp_count));
                result = DetectionResult::DDOS_VOLUMETRIC;
            }
        }

        // Flood ratio check (SYN vs total)
        if (ip.pkt_count >= min_pkt_before_flood_check_) {
            const double ratio = static_cast<double>(ip.syn_count)
                               / static_cast<double>(ip.pkt_count);
            if (ratio >= flood_ratio_threshold_) {
                LOG_WARN("SignatureEngine: flood ratio exceeded"
                         " ratio=" + std::to_string(ratio)
                         + " threshold=" + std::to_string(flood_ratio_threshold_)
                         + " src=" + pkt.flowKey());
                result = DetectionResult::DDOS_VOLUMETRIC;
            }
        }
    });

    return result;
}

// =============================================================================
//  checkPortScan
//  Chỉ track SYN probe từ is_initiator=true để tránh nhiễm RST response
// =============================================================================
DetectionResult SignatureEngine::checkPortScan(const PacketInfo& pkt,
                                                FlowState&        flow) {
    // Chỉ track SYN không có ACK (probe packet)
    if (!pkt.hasSYN() || pkt.hasACK())
        return DetectionResult::NORMAL;

    // Chỉ analyze flow khởi tạo bởi attacker
    if (!flow.is_initiator)
        return DetectionResult::NORMAL;

    flow.dst_ports_seen.insert(pkt.dst_port);
    flow.syn_no_ack++;

    // Đồng bộ vào IpStats để BehavioralEngine cũng thấy
    ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
        ip.scan_ports_seen.insert(pkt.dst_port);
        ip.syn_no_ack = flow.syn_no_ack;
    });

    const uint32_t unique_ports =
        static_cast<uint32_t>(flow.dst_ports_seen.size());

    if (unique_ports  >= port_scan_threshold_ &&
        flow.syn_no_ack >= port_scan_syn_no_ack_min_)
    {
        LOG_WARN("SignatureEngine: port scan detected"
                 " src="          + pkt.flowKey()
                 + " unique_ports=" + std::to_string(unique_ports)
                 + " syn_no_ack="   + std::to_string(flow.syn_no_ack)
                 + " threshold="    + std::to_string(port_scan_threshold_));
        return DetectionResult::PORT_SCAN;
    }

    return DetectionResult::NORMAL;
}

// =============================================================================
//  checkFlagAbuse
//  XMAS scan (FIN+PSH+URG), NULL scan (no flags), FIN scan
// =============================================================================
DetectionResult SignatureEngine::checkFlagAbuse(const PacketInfo& pkt,
                                                 FlowState&        flow) {
    if (pkt.protocol != IPPROTO_TCP)
        return DetectionResult::NORMAL;

    const bool fin = pkt.hasFIN();
    const bool psh = pkt.hasPSH();
    const bool urg = pkt.hasURG();
    const bool syn = pkt.hasSYN();
    const bool ack = pkt.hasACK();
    const bool rst = pkt.hasRST();

    // XMAS scan: FIN + PSH + URG
    if (fin && psh && urg) {
        LOG_WARN("SignatureEngine: XMAS scan from " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }

    // NULL scan: không có flag nào
    if (!fin && !syn && !rst && !psh && !ack && !urg) {
        LOG_WARN("SignatureEngine: NULL scan from " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }

    // FIN scan: chỉ có FIN, không có ACK (không phải close bình thường)
    if (fin && !ack && !syn) {
        LOG_WARN("SignatureEngine: FIN scan from " + pkt.flowKey());
        return DetectionResult::PORT_SCAN;
    }

    return DetectionResult::NORMAL;
}

// =============================================================================
//  checkPayload
//  Aho-Corasick match payload → Slowloris / Slow POST header pattern
// =============================================================================
DetectionResult SignatureEngine::checkPayload(const PacketInfo& pkt,
                                               FlowState&        flow) {
    if (pkt.payload_len == 0 || pkt.payload() == nullptr)
        return DetectionResult::NORMAL;

    const int sig_id = acSearch(pkt.payload(), pkt.payload_len);
    if (sig_id == SIG_NONE)
        return DetectionResult::NORMAL;

    // Lấy metadata từ rule_map_ (đọc từ rules.json)
    const auto it = rule_map_.find(sig_id);
    const std::string rule_id =
        (it != rule_map_.end()) ? it->second.id : "UNKNOWN";
    const std::string action  =
        (it != rule_map_.end()) ? it->second.action : "ALERT";

    LOG_WARN("SignatureEngine: payload match"
             " rule="   + rule_id
             + " sig_id=" + std::to_string(sig_id)
             + " action=" + action
             + " from "   + pkt.flowKey());

    return DetectionResult::SLOW_DDOS;
}
