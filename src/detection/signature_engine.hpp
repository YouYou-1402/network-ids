//src/detection/signature_engine.hpp
#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "flow_state.hpp"
#include <vector>
#include <string>
#include <unordered_map>

// Aho-Corasick node
struct ACNode {
    std::unordered_map<char, int> children;
    int              fail_link = 0;
    std::vector<int> outputs;   // Pattern IDs matched tại node này
};

// Signature IDs
enum SignatureID {
    SIG_SLOWLORIS   = 0,
    SIG_SLOW_POST   = 1,
    SIG_XMAS_SCAN   = 2,
    SIG_NULL_SCAN   = 3,
    SIG_COUNT       = 4
};

class SignatureEngine {
public:
    SignatureEngine();

    // Phân tích gói tin, trả về DetectionResult
    DetectionResult analyze(const PacketInfo& pkt,
                            FlowState&        flow);

private:
    // Aho-Corasick core
    void addPattern(const std::string& pattern, int sig_id);
    void buildFailLinks();
    std::vector<int> search(const uint8_t* data, size_t len) const;

    // Rule checks
    DetectionResult checkDDoSRules(const PacketInfo& pkt,
                                   FlowState&        flow);
    DetectionResult checkPortScanRules(const PacketInfo& pkt,
                                       FlowState&        flow);
    DetectionResult checkPayloadSignatures(const PacketInfo& pkt);

    std::vector<ACNode> nodes_;

    // Thresholds (có thể load từ config)
    static constexpr uint32_t SYN_RATE_THRESHOLD    = 100;  // SYN/10s
    static constexpr uint32_t UDP_RATE_THRESHOLD    = 1000; // pps
    static constexpr uint32_t PORT_SCAN_THRESHOLD   = 20;   // ports/10s
    static constexpr double   SYN_RST_RATIO         = 0.8;  // 80%
    static constexpr double   WINDOW_SECONDS        = 10.0;
};
