#pragma once
#include "ml_engine.hpp"
#include "../core/threat_types.hpp"
#include <functional>
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <cstdint>

struct RuleProposal {
    enum class Type   { ADD_TO_BLACKLIST, REDUCE_TIMEOUT,
                        INCREASE_RATE_LIMIT, ADD_SIGNATURE };
    enum class Status { PENDING, APPROVED, REJECTED, AUTO_APPROVED };

    Type            type;
    Status          status     = Status::PENDING;
    uint32_t        src_ip     = 0;
    std::string     detail;
    float           confidence = 0.f;
    double          timestamp  = 0.0;
    DetectionResult threat     = DetectionResult::NORMAL;
};

using ProposalCallback = std::function<void(const RuleProposal&)>;

// =============================================================================
//  FeedbackLoop
//
//  Thay đổi so với mock:
//    - AUTO_APPROVED khi confidence >= 0.85 → block ngay không cần admin
//    - PENDING khi 0.60 <= confidence < 0.85 → chờ admin duyệt
//    - Dedup: không tạo proposal trùng IP trong DEDUP_WINDOW_SEC = 60s
//    - UNKNOWN_ANOMALY → ADD_SIGNATURE (không block ngay, cần điều tra)
// =============================================================================
class FeedbackLoop {
public:
    explicit FeedbackLoop(ProposalCallback on_proposal);

    void onMLResult(const MLResult& result);

    std::vector<RuleProposal> getPendingProposals();
    void   approveProposal(size_t index);
    void   rejectProposal (size_t index);
    size_t pendingCount   () const;

    void setMinConfidence        (float v) { min_confidence_        = v; }
    void setAutoApproveThreshold (float v) { auto_approve_threshold_= v; }

private:
    RuleProposal buildProposal (const MLResult& result) const;
    bool         isDuplicate   (uint32_t src_ip) const;   // PHẢI gọi trong lock
    void         recordSeen    (uint32_t src_ip);          // PHẢI gọi trong lock

    ProposalCallback          on_proposal_;
    std::vector<RuleProposal> pending_proposals_;
    mutable std::mutex        mutex_;

    // Dedup: IP → timestamp lần cuối tạo proposal
    std::unordered_map<uint32_t, double> recent_proposals_;

    float min_confidence_         = 0.60f;
    float auto_approve_threshold_ = 0.85f;

    static constexpr double DEDUP_WINDOW_SEC = 60.0;
};
