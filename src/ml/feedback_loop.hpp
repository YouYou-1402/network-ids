//src/ml/feedback_loop.hpp
#pragma once
#include "ml_engine.hpp"
#include "../core/threat_types.hpp"
#include <functional>
#include <string>
#include <vector>
#include <mutex>
#include <cstdint>

// Đề xuất cập nhật rule từ Layer 2 → Layer 1
struct RuleProposal {
    enum class Type {
        ADD_TO_BLACKLIST,       // Thêm IP vào blacklist
        REDUCE_TIMEOUT,         // Giảm HTTP timeout threshold
        INCREASE_RATE_LIMIT,    // Tăng sensitivity rate limiting
        ADD_SIGNATURE           // Thêm signature mới
    };

    Type        type;
    uint32_t    src_ip     = 0;
    std::string detail;
    float       confidence = 0.f;
    double      timestamp  = 0.0;
};

// Callback để Layer 1 nhận proposals
using ProposalCallback = std::function<void(const RuleProposal&)>;

class FeedbackLoop {
public:
    explicit FeedbackLoop(ProposalCallback on_proposal);

    // Nhận kết quả từ MLEngine và tạo proposals
    void onMLResult(const MLResult& result);

    // Lấy danh sách proposals pending (cho Dashboard hiển thị)
    std::vector<RuleProposal> getPendingProposals();

    // Quản trị viên phê duyệt/từ chối proposal
    void approveProposal(size_t index);
    void rejectProposal(size_t index);

    size_t pendingCount() const;

private:
    RuleProposal buildProposal(const MLResult& result) const;

    ProposalCallback             on_proposal_;
    std::vector<RuleProposal>    pending_proposals_;
    mutable std::mutex           mutex_;

    // Ngưỡng confidence để tự động tạo proposal
    static constexpr float MIN_CONFIDENCE = 0.7f;
};
