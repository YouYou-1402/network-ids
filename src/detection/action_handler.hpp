// src/detection/action_handler.hpp
#pragma once
#include "../core/threat_types.hpp"
#include "../core/packet_info.hpp"
#include "flow_state.hpp"
#include <string>

class ActionHandler {
public:
    struct Policy {
        PacketAction ddos_action      = PacketAction::DROP;
        PacketAction slow_ddos_action = PacketAction::ALERT;
        PacketAction port_scan_action = PacketAction::ALERT;
        PacketAction malformed_action = PacketAction::DROP;
    };
    
    ActionHandler()                        : policy_(Policy{}) {}
    explicit ActionHandler(Policy policy)  : policy_(policy)   {}

    PacketAction decide(DetectionResult result) const;

    DetectionEvent makeEvent(DetectionResult    result,
                             DetectionSource    source,
                             const PacketInfo&  pkt,
                             const std::string& detail = "") const;

    void          setPolicy(Policy policy)  { policy_ = policy; }
    const Policy& policy()           const  { return policy_;   }

private:
    Policy policy_;
};
