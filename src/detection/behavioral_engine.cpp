// =============================================================================
//  src/detection/behavioral_engine.cpp
// =============================================================================
#include "behavioral_engine.hpp"
#include "../common/logger.hpp"
#include "../common/config_loader.hpp"
#include <netinet/in.h>
#include <cstring>
#include <cstdio>

// =============================================================================
//  Constructor
// =============================================================================
BehavioralEngine::BehavioralEngine(IpTracker& ip_tracker)
    : ip_tracker_(ip_tracker)
{
    const auto& th = APP_CFG.thresholds;
    http_flood_threshold_    = th.http_flood_req_per_window;
    syn_no_complete_thresh_  = th.syn_no_complete;
    dist_scan_src_threshold_ = th.dist_scan_src_threshold;
    behavior_window_sec_     = th.behavior_window_sec;

    // ── Parse behavior_rules từ rules.json ────────────────────────────────
    //  Override threshold nếu rule tương ứng tồn tại
    for (const auto& rule : APP_CFG.signatures.behavior_rules) {
        parsed_rules_.push_back(rule);
        parseConditionOverride(rule);
        LOG_INFO("BehavioralEngine: loaded rule ["
                 + rule.id + "] " + rule.name
                 + " condition='" + rule.condition + "'"
                 + " threat="     + rule.threat
                 + " action="     + rule.action);
    }

    if (parsed_rules_.empty())
        LOG_WARN("BehavioralEngine: no behavior_rules from config"
                 " — using threshold defaults");

    LOG_INFO("BehavioralEngine: initialized"
             " behavior_rules="  + std::to_string(parsed_rules_.size())
           + " http_flood="      + std::to_string(http_flood_threshold_)
           + " dist_scan="       + std::to_string(dist_scan_src_threshold_)
           + " syn_thresh="      + std::to_string(syn_no_complete_thresh_)
           + " udp_pps="         + std::to_string(udp_pps_threshold_)
           + " window="          + std::to_string(behavior_window_sec_) + "s");
}

// =============================================================================
//  parseConditionOverride
//
//  Supported condition formats (từ rules.json):
//    "syn_no_ack > 100 in 10s"
//    "udp_pps > 1000"
//    "unique_dst_ports > 20 in 10s"
//    "http_req > 200 in 10s"
//    "http_header_incomplete after 30s"   → handled by ProtocolAnomalyEngine
//    "tcp_flags == FIN|PSH|URG"           → handled by SignatureEngine
// =============================================================================
void BehavioralEngine::parseConditionOverride(const BehaviorRule& rule) {
    const std::string& cond = rule.condition;

    // ── syn_no_ack > N in Xs ──────────────────────────────────────────────
    if (cond.find("syn_no_ack") != std::string::npos) {
        uint32_t val = 0; double win = 0.0;
        if (sscanf(cond.c_str(), "syn_no_ack > %u in %lfs", &val, &win) >= 1) {
            syn_no_complete_thresh_ = val;
            if (win > 0.0) behavior_window_sec_ = win;
            LOG_INFO("BehavioralEngine: [" + rule.id + "] override"
                     " syn_no_ack_thresh=" + std::to_string(val)
                     + (win > 0.0 ? " window=" + std::to_string(win) + "s" : ""));
        }
        return;
    }

    // ── udp_pps > N ───────────────────────────────────────────────────────
    if (cond.find("udp_pps") != std::string::npos) {
        uint64_t val = 0;
        if (sscanf(cond.c_str(), "udp_pps > %lu", &val) == 1) {
            udp_pps_threshold_ = val;
            LOG_INFO("BehavioralEngine: [" + rule.id + "] override"
                     " udp_pps_thresh=" + std::to_string(val));
        }
        return;
    }

    // ── unique_dst_ports > N in Xs ────────────────────────────────────────
    if (cond.find("unique_dst_ports") != std::string::npos) {
        uint32_t val = 0; double win = 0.0;
        if (sscanf(cond.c_str(),
                   "unique_dst_ports > %u in %lfs", &val, &win) >= 1) {
            dist_scan_src_threshold_ = val;
            if (win > 0.0) behavior_window_sec_ = win;
            LOG_INFO("BehavioralEngine: [" + rule.id + "] override"
                     " unique_dst_ports_thresh=" + std::to_string(val)
                     + (win > 0.0 ? " window=" + std::to_string(win) + "s" : ""));
        }
        return;
    }

    // ── http_req > N in Xs ────────────────────────────────────────────────
    if (cond.find("http_req") != std::string::npos) {
        uint64_t val = 0; double win = 0.0;
        if (sscanf(cond.c_str(),
                   "http_req > %lu in %lfs", &val, &win) >= 1) {
            http_flood_threshold_ = val;
            if (win > 0.0) behavior_window_sec_ = win;
            LOG_INFO("BehavioralEngine: [" + rule.id + "] override"
                     " http_flood_thresh=" + std::to_string(val)
                     + (win > 0.0 ? " window=" + std::to_string(win) + "s" : ""));
        }
        return;
    }

    // ── Condition handled by other engine → log only ──────────────────────
    LOG_INFO("BehavioralEngine: rule [" + rule.id
             + "] condition handled by other engine: " + cond);
}

// =============================================================================
//  analyze
// =============================================================================
DetectionResult BehavioralEngine::analyze(const PacketInfo& pkt,
                                           FlowState&        flow) {
    auto r = checkHttpFlood(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    r = checkSynNoHandshake(pkt, flow);
    if (r != DetectionResult::NORMAL) return r;

    return checkDistScan(pkt, flow);
}

// =============================================================================
//  checkHttpFlood
//  Đếm HTTP request (GET/POST/HEAD) trong sliding window
// =============================================================================
DetectionResult BehavioralEngine::checkHttpFlood(const PacketInfo& pkt,
                                                   FlowState&        flow) {
    if (pkt.protocol != IPPROTO_TCP)
        return DetectionResult::NORMAL;

    if (pkt.payload_len < 4 || pkt.payload() == nullptr)
        return DetectionResult::NORMAL;

    // Kiểm tra HTTP method prefix
    const char* p = reinterpret_cast<const char*>(pkt.payload());
    const bool is_http_req =
        (strncmp(p, "GET ",  4) == 0) ||
        (strncmp(p, "POST ", 5) == 0) ||
        (strncmp(p, "HEAD ", 5) == 0);

    if (!is_http_req)
        return DetectionResult::NORMAL;

    DetectionResult result = DetectionResult::NORMAL;

    ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
        // FIX #4: Reset window TRƯỚC khi increment
        if (ip.windowElapsed() > behavior_window_sec_)
            ip.resetWindow();

        // FIX #3: Dùng http_req_count thay pkt_count.
        // pkt_count là tổng packet mọi protocol — dùng nó để đếm HTTP request
        // sẽ bị nhiễm bởi SYN/ACK/RST packets không phải HTTP.
        ip.http_req_count++;

        if (ip.http_req_count >= http_flood_threshold_) {
            LOG_WARN("BehavioralEngine: HTTP flood"
                     " src="        + pkt.flowKey()
                     + " req_count=" + std::to_string(ip.http_req_count)
                     + " threshold=" + std::to_string(http_flood_threshold_)
                     + " window="    + std::to_string(behavior_window_sec_) + "s");
            result = DetectionResult::DDOS_VOLUMETRIC;
        }
    });

    return result;
}

// =============================================================================
//  checkSynNoHandshake
//  SYN gửi đi không nhận được ACK phản hồi → SYN flood hoặc half-open scan
// =============================================================================
DetectionResult BehavioralEngine::checkSynNoHandshake(const PacketInfo& pkt,
                                                        FlowState&        flow) {
    if (pkt.protocol != IPPROTO_TCP)
        return DetectionResult::NORMAL;

    // Track SYN không có ACK
    if (pkt.hasSYN() && !pkt.hasACK())
        flow.syn_no_ack++;

    // ACK hoàn thành handshake → reset counter
    if (pkt.hasACK() && !pkt.hasSYN())
        flow.syn_no_ack = (flow.syn_no_ack > 0) ? flow.syn_no_ack - 1 : 0;

    if (flow.syn_no_ack >= syn_no_complete_thresh_) {
        LOG_WARN("BehavioralEngine: SYN no-handshake"
                 " src="        + pkt.flowKey()
                 + " syn_no_ack=" + std::to_string(flow.syn_no_ack)
                 + " threshold="  + std::to_string(syn_no_complete_thresh_));
        return DetectionResult::DDOS_VOLUMETRIC;
    }

    return DetectionResult::NORMAL;
}

// =============================================================================
//  checkDistScan
//  Distributed scan: nhiều src IP khác nhau probe cùng 1 dst port
//  Dùng IpStats.scan_ports_seen đã được SignatureEngine cập nhật
// =============================================================================
DetectionResult BehavioralEngine::checkDistScan(const PacketInfo& pkt,
                                                  FlowState&        flow) {
    if (!pkt.hasSYN() || pkt.hasACK())
        return DetectionResult::NORMAL;

    DetectionResult result = DetectionResult::NORMAL;

    ip_tracker_.withStats(pkt.src_ip, [&](IpStats& ip) {
        if (ip.windowElapsed() > behavior_window_sec_) {
            ip.resetScanTracking();
            return;
        }

        const uint32_t unique =
            static_cast<uint32_t>(ip.scan_ports_seen.size());

        if (unique >= dist_scan_src_threshold_) {
            LOG_WARN("BehavioralEngine: distributed scan"
                     " src="          + pkt.flowKey()
                     + " unique_ports=" + std::to_string(unique)
                     + " threshold="    + std::to_string(dist_scan_src_threshold_));
            result = DetectionResult::PORT_SCAN;
        }
    });

    return result;
}
