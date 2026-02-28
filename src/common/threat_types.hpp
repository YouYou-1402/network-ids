#pragma once
#include <string>
#include <cstdint>

// Kết quả phát hiện của từng engine
enum class DetectionResult {
    NORMAL,
    DDOS_VOLUMETRIC,
    SLOW_DDOS,
    PORT_SCAN,
    MALFORMED
};

// Hành động thực hiện với gói tin
enum class PacketAction {
    PASS,
    DROP,
    ALERT   // Cho qua nhưng ghi cảnh báo
};

// Nguồn phát hiện (Layer 1 hay Layer 2)
enum class DetectionSource {
    LAYER1_SIGNATURE,
    LAYER1_PROTOCOL_ANOMALY,
    LAYER1_BEHAVIORAL,
    LAYER2_ISOLATION_FOREST,
    LAYER2_AUTOENCODER
};

// Struct kết quả đầy đủ
struct DetectionEvent {
    DetectionResult  result;
    PacketAction     action;
    DetectionSource  source;
    std::string      detail;      // Mô tả ngắn gọn
    uint32_t         src_ip;
    uint32_t         dst_ip;
    uint16_t         src_port;
    uint16_t         dst_port;
    double           timestamp;   // Unix timestamp
};

// Helper: convert enum → string để log
inline std::string threatToString(DetectionResult r) {
    switch (r) {
        case DetectionResult::NORMAL:           return "NORMAL";
        case DetectionResult::DDOS_VOLUMETRIC:  return "DDOS_VOLUMETRIC";
        case DetectionResult::SLOW_DDOS:        return "SLOW_DDOS";
        case DetectionResult::PORT_SCAN:        return "PORT_SCAN";
        case DetectionResult::MALFORMED:        return "MALFORMED";
        default:                                return "UNKNOWN";
    }
}

inline std::string actionToString(PacketAction a) {
    switch (a) {
        case PacketAction::PASS:  return "PASS";
        case PacketAction::DROP:  return "DROP";
        case PacketAction::ALERT: return "ALERT";
        default:                  return "UNKNOWN";
    }
}
