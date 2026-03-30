// src/detection/action_handler.cpp
#include "action_handler.hpp"
#include <chrono>

PacketAction ActionHandler::decide(DetectionResult result) const {
    switch (result) {
        case DetectionResult::DDOS_VOLUMETRIC: return policy_.ddos_action;
        case DetectionResult::SLOW_DDOS:       return policy_.slow_ddos_action;
        case DetectionResult::PORT_SCAN:       return policy_.port_scan_action;
        case DetectionResult::OTHER_ATTACK:       return policy_.malformed_action;
        case DetectionResult::NORMAL:          return PacketAction::PASS;
        default:                               return PacketAction::ALERT;
    }
}

DetectionEvent ActionHandler::makeEvent(DetectionResult    result,
                                         DetectionSource    source,
                                         const PacketInfo&  pkt,
                                         const std::string& detail) const {
    DetectionEvent ev;
    ev.result    = result;
    ev.action    = decide(result);
    ev.source    = source;
    ev.detail    = detail.empty() ? threatToString(result) + " from "
                                    + pkt.flowKey() : detail;
    ev.src_ip    = pkt.src_ip;
    ev.dst_ip    = pkt.dst_ip;
    ev.src_port  = pkt.src_port;
    ev.dst_port  = pkt.dst_port;
    ev.timestamp = pkt.timestamp_d;
    return ev;
}
