//src\ml\feedback_loop.cpp
#include "feedback_loop.hpp"
#include "../common/logger.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <sstream>

static double nowSec() {
    return std::chrono::duration<double>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

static std::string ipStr(uint32_t ip) {
    struct in_addr a; a.s_addr = ip;
    return inet_ntoa(a);
}

FeedbackLoop::FeedbackLoop(ProposalCallback on_proposal)
    : on_proposal_(std::move(on_proposal)) {}

void FeedbackLoop::onMLResult(const MLResult& result) {
    if (result.confidence < min_confidence_)   return;
    if (result.final_result == DetectionResult::NORMAL) return;

    std::lock_guard<std::mutex> lock(mutex_);

    if (isDuplicate(result.src_ip)) {
        LOG_DEBUG("FeedbackLoop: dedup skip " + ipStr(result.src_ip));
        return;
    }

    RuleProposal p = buildProposal(result);

    if (result.confidence >= auto_approve_threshold_) {
        p.status = RuleProposal::Status::AUTO_APPROVED;
        LOG_INFO("FeedbackLoop: AUTO-APPROVE [" + p.detail
                 + "] conf=" + std::to_string(result.confidence));
        if (on_proposal_) on_proposal_(p);
    } else {
        p.status = RuleProposal::Status::PENDING;
        pending_proposals_.push_back(p);
        LOG_INFO("FeedbackLoop: PENDING [" + p.detail
                 + "] conf=" + std::to_string(result.confidence));
    }

    recordSeen(result.src_ip);
}

RuleProposal FeedbackLoop::buildProposal(const MLResult& result) const {
    RuleProposal p;
    p.src_ip     = result.src_ip;
    p.confidence = result.confidence;
    p.timestamp  = result.timestamp;
    p.threat     = result.final_result;

    const std::string ip = ipStr(result.src_ip);

    switch (result.final_result) {
        case DetectionResult::DDOS_VOLUMETRIC:
            p.type   = RuleProposal::Type::ADD_TO_BLACKLIST;
            p.detail = "Blacklist " + ip + " (DDoS Volumetric"
                     + " conf=" + std::to_string(result.confidence) + ")";
            break;

        case DetectionResult::SLOW_DDOS:
            p.type   = RuleProposal::Type::REDUCE_TIMEOUT;
            p.detail = "Reduce HTTP timeout for " + ip
                     + " (Slow DDoS conf=" + std::to_string(result.confidence) + ")";
            break;

        case DetectionResult::PORT_SCAN:
            p.type   = RuleProposal::Type::ADD_TO_BLACKLIST;
            p.detail = "Blacklist " + ip + " (Port Scan"
                     + " conf=" + std::to_string(result.confidence) + ")";
            break;

        case DetectionResult::OTHER_ATTACK:
            // Phân biệt HIGH/MED confidence
            if (result.confidence >= 0.75f) {
                p.type   = RuleProposal::Type::ADD_TO_BLACKLIST;
                p.detail = "Blacklist " + ip + " (Other Attack HIGH conf="
                        + std::to_string(result.confidence) + ")"
                        + " | " + result.xgb_result.detail;
            } else {
                p.type   = RuleProposal::Type::ADD_SIGNATURE;
                p.detail = "Signature for " + ip + " (Other Attack MED conf="
                        + std::to_string(result.confidence) + ")"
                        + " | " + result.detail;
            }
            break;

        case DetectionResult::UNKNOWN_ANOMALY:
            p.type   = RuleProposal::Type::ADD_SIGNATURE;
            p.detail = "Unknown anomaly from " + ip
                    + " (AE-only conf=" + std::to_string(result.confidence) + ")"
                    + " | " + result.ae_result.detail;
            break;

        default:
            p.type   = RuleProposal::Type::ADD_SIGNATURE;
            p.detail = "Anomaly from " + ip;
            break;
    }
    return p;
}

bool FeedbackLoop::isDuplicate(uint32_t src_ip) const {
    auto it = recent_proposals_.find(src_ip);
    if (it == recent_proposals_.end()) return false;
    return (nowSec() - it->second) < DEDUP_WINDOW_SEC;
}

void FeedbackLoop::recordSeen(uint32_t src_ip) {
    recent_proposals_[src_ip] = nowSec();
}

std::vector<RuleProposal> FeedbackLoop::getPendingProposals() {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_proposals_;
}

void FeedbackLoop::approveProposal(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= pending_proposals_.size()) return;
    RuleProposal& p = pending_proposals_[index];
    p.status = RuleProposal::Status::APPROVED;
    LOG_INFO("FeedbackLoop: APPROVED — " + p.detail);
    if (on_proposal_) on_proposal_(p);
    pending_proposals_.erase(pending_proposals_.begin() + index);
}

void FeedbackLoop::rejectProposal(size_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= pending_proposals_.size()) return;
    LOG_INFO("FeedbackLoop: REJECTED — " + pending_proposals_[index].detail);
    pending_proposals_.erase(pending_proposals_.begin() + index);
}

size_t FeedbackLoop::pendingCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_proposals_.size();
}
