// src/core/threat_types.hpp
#pragma once
#include <string>
#include <cstdint>

enum class DetectionResult {
    NORMAL,
    DDOS_VOLUMETRIC,   // SYN flood, UDP flood, ICMP flood
    SLOW_DDOS,         // Slowloris, Slow POST, Slow Read
    PORT_SCAN,         // SYN scan, NULL scan, XMAS scan, connect scan
    MALFORMED,          // Reserved — header bất hợp lệ
    UNKNOWN_ANOMALY          
};

enum class PacketAction {
    PASS,
    ALERT,
    DROP
};

enum class DetectionSource {
    LAYER1_SIGNATURE,
    LAYER1_PROTOCOL_ANOMALY,
    LAYER1_BEHAVIORAL,
    LAYER2_ISOLATION_FOREST,
    LAYER2_AUTOENCODER
};

struct DetectionEvent {
    DetectionResult  result    = DetectionResult::NORMAL;
    PacketAction     action    = PacketAction::PASS;
    DetectionSource  source    = DetectionSource::LAYER1_SIGNATURE;
    std::string      detail;
    uint32_t         src_ip    = 0;
    uint32_t         dst_ip    = 0;
    uint16_t         src_port  = 0;
    uint16_t         dst_port  = 0;
    double           timestamp = 0.0;
};

inline std::string threatToString(DetectionResult r) {
    switch (r) {
        case DetectionResult::NORMAL:          return "NORMAL";
        case DetectionResult::DDOS_VOLUMETRIC: return "DDOS_VOLUMETRIC";
        case DetectionResult::SLOW_DDOS:       return "SLOW_DDOS";
        case DetectionResult::PORT_SCAN:       return "PORT_SCAN";
        case DetectionResult::MALFORMED:       return "MALFORMED";
        default:                               return "UNKNOWN";
    }
}

inline std::string actionToString(PacketAction a) {
    switch (a) {
        case PacketAction::PASS:  return "PASS";
        case PacketAction::ALERT: return "ALERT";
        case PacketAction::DROP:  return "DROP";
        default:                  return "UNKNOWN";
    }
}
