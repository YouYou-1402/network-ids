#include "feedback_loop.hpp"
#include "../common/logger.hpp"
#include <arpa/inet.h>
#include <chrono>

FeedbackLoop::FeedbackLoop(ProposalCallback on_proposal)
    : on_proposal_(std::move(on_proposal)) {}

// ─── Nhận kết quả từ MLEngine ─────────────────────────────────────────────────
void FeedbackLoop::onMLResult(const MLResult& result) {
    // Chỉ tạo proposal khi confidence đủ cao
    if (result.confidence < MIN_CONFIDENCE) {
        LOG_DEBUG("FeedbackLoop: Low confidence ("
                  + std::to_string(result.confidence)
                  + "), skipping proposal for " + result.flow_key);
        return;
    }

    RuleProposal proposal = buildProposal(result);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_proposals_.push_back(proposal);
    }

    LOG_INFO("FeedbackLoop: New proposal ["
             + proposal.detail + "] confidence="
             + std::to_string(proposal.confidence));
}

// ─── Build proposal từ MLResult ───────────────────────────────────────────────
RuleProposal FeedbackLoop::buildProposal(const MLResult& result) const {
    RuleProposal p;
    p.src_ip     = result.src_ip;
    p.confidence = result.confidence;
    p.timestamp  = result.timestamp;

    struct in_addr addr;
    addr.s_addr = result.src_ip;
    std::string ip_str = inet_ntoa(addr);

    switch (result.final_result) {
        case DetectionResult::DDOS_VOLUMETRIC:
            p.type   = RuleProposal::Type::ADD_TO_BLACKLIST;
            p.detail = "Add " + ip_str
                     + " to blacklist (DDoS Volumetric, confidence="
                     + std::to_string(result.confidence) + ")";
            break;

        case DetectionResult::SLOW_DDOS:
            p.type   = RuleProposal::Type::REDUCE_TIMEOUT;
            p.detail = "Reduce HTTP timeout for " + ip_str
                     + " (Slow DDoS detected by L2, confidence="
                     + std::to_string(result.confidence) + ")";
            break;

        case DetectionResult::PORT_SCAN:
            p.type   = RuleProposal::Type::ADD_TO_BLACKLIST;
            p.detail = "Add " + ip_str
                     + " to blacklist (Port Scan, confidence="
                     + std::to_string(result.confidence) + ")";
            break;

        default:
            p.type   = RuleProposal::Type::ADD_SIGNATURE;
            p.detail = "Unknown anomaly from " + ip_str;
            break;
    }

    return p;
}

// ─── Quản lý proposals ────────────────────────────────────────────────────────
std::vector<RuleProposal> FeedbackLoop::getPendingProposals() {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_proposals_;
}

void FeedbackLoop::approveProposal(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= pending_proposals_.size()) return;

    RuleProposal& p = pending_proposals_[index];
    LOG_INFO("FeedbackLoop: Proposal APPROVED — " + p.detail);

    // Gọi callback → Layer 1 cập nhật rule
    if (on_proposal_)
        on_proposal_(p);

    pending_proposals_.erase(pending_proposals_.begin() + index);
}

void FeedbackLoop::rejectProposal(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= pending_proposals_.size()) return;

    LOG_INFO("FeedbackLoop: Proposal REJECTED — "
             + pending_proposals_[index].detail);
    pending_proposals_.erase(pending_proposals_.begin() + index);
}

size_t FeedbackLoop::pendingCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_proposals_.size();
}
