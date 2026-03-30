#pragma once
#include "../core/packet_info.hpp"
#include "../core/threat_types.hpp"
#include "../common/config_loader.hpp"
#include "flow_state.hpp"
#include "ip_tracker.hpp"
#include <vector>
#include <string>
#include <unordered_map>

struct ACNode {
    std::unordered_map<uint8_t, int> children;
    int              fail_link = 0;
    std::vector<int> outputs;
};

enum SignatureID {
    SIG_SLOWLORIS = 0,
    SIG_SLOW_POST = 1,
    SIG_COUNT     = 2
};

class SignatureEngine {
public:
    explicit SignatureEngine(IpTracker& ip_tracker);

    DetectionResult analyze(const PacketInfo& pkt, FlowState& flow);

private:
    // ── Aho-Corasick ──────────────────────────────────────────────────────
    void             addPattern    (const std::string& pattern, int sig_id);
    void             buildFailLinks();
    std::vector<int> search        (const uint8_t* data, size_t len) const;

    // ── Detection helpers ─────────────────────────────────────────────────
    DetectionResult  checkFlagAbuse (const PacketInfo& pkt);
    DetectionResult  checkPayload   (const PacketInfo& pkt);
    void             updateFlowState(const PacketInfo& pkt, FlowState& flow);

    // ── Distributed SYN flood helpers (mới) ──────────────────────────────
    // Trả về DDOS_VOLUMETRIC nếu detect, NORMAL nếu không
    DetectionResult  checkDstSynRatio  (const PacketInfo& pkt);
    DetectionResult  checkGlobalSynRate(const PacketInfo& pkt);

    static bool isMediaTraffic(const PacketInfo& pkt);

    // ── Members ───────────────────────────────────────────────────────────
    IpTracker&          ip_tracker_;
    DstTracker          dst_tracker_;       // per-destination SYN/ACK tracking
    std::vector<ACNode> ac_nodes_;

    // Thresholds đọc từ config lúc khởi tạo
    double   flood_ratio_threshold_      = 0.5;
    size_t   port_scan_threshold_        = 20;
    uint32_t port_scan_syn_no_ack_min_   = 25;
    uint64_t min_pkt_before_flood_check_ = 20;

    // Distributed SYN flood thresholds (mới)
    uint64_t global_syn_threshold_       = 2000;
    uint64_t dst_syn_ratio_min_pkt_      = 100;
    double   dst_syn_ack_ratio_          = 10.0;
    double   behavior_window_sec_        = 10.0;
};
