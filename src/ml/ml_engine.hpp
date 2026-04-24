#pragma once
// =============================================================================
//  src/ml/ml_engine.hpp
//
//  Thay đổi so với phiên bản cũ:
//    [XÓA] FeatureExtractor extractor_  (21-dim CICIDS2017)
//    [THÊM] NslKddExtractor nslkdd_extractor_ (39-dim NSL-KDD)
//    [SỬA] processJob() dùng vector<float>(39) cho cả XGB lẫn AE
//    [SỬA] combineVoting() xử lý AE score = MSE (không phải probability)
//    [SỬA] start() load NslKddExtractor thay vì StandardScaler binary
//    [GIỮ] Voting bảng, TLS suppression, cooldown — không thay đổi
// =============================================================================

#ifndef ML_ENGINE_HPP
#define ML_ENGINE_HPP

#include "ml_config.hpp"
#include "data_queue.hpp"
#include "onnx_model.hpp"
#include "nslkdd_extractor.hpp"     // ← THAY THẾ feature_extractor.hpp
#include "../core/threat_types.hpp"
#include <thread>
#include <atomic>
#include <functional>
#include <memory>
#include <string>

// =============================================================================
//  MLResult — kết quả tổng hợp từ XGBoost + Autoencoder
// =============================================================================
struct MLResult {
    std::string     flow_key;
    uint32_t        src_ip    = 0;
    uint32_t        dst_ip    = 0;
    uint16_t        src_port  = 0;
    uint16_t        dst_port  = 0;
    double          timestamp = 0.0;

    ModelOutput     xgb_result;
    ModelOutput     ae_result;

    DetectionResult final_result = DetectionResult::NORMAL;
    float           confidence   = 0.f;
    std::string     detail;
};

using MLAlertCallback = std::function<void(const MLResult&)>;

// =============================================================================
//  EngineOutput — kết quả voting nội bộ
// =============================================================================
struct EngineOutput {
    bool        is_anomaly = false;
    float       score      = 0.f;
    int         label      = 0;
    std::string detail;
};

// =============================================================================
//  MLEngine
// =============================================================================
class MLEngine {
public:
    MLEngine(MLJobQueue& job_queue, MLAlertCallback on_ml_alert);
    ~MLEngine();

    MLEngine(const MLEngine&)            = delete;
    MLEngine& operator=(const MLEngine&) = delete;

    // Khởi động với config đầy đủ
    void start(const MLConfig& cfg);

    // Backward compat
    void start(bool               use_mock    = true,
               const std::string& xgb_path    = "",
               const std::string& ae_path     = "",
               const std::string& meta_path   = "",
               const std::string& scaler_path = "");

    void stop();

    // Reload models tại runtime (thread-safe)
    bool reloadModels(const MLConfig& cfg);

    bool        isRunning     () const { return running_;         }
    uint64_t    jobsProcessed () const { return jobs_processed_;  }
    uint64_t    anomaliesFound() const { return anomalies_found_; }
    std::string status        () const;

private:
    void     run();
    MLResult processJob(const MLJob& job);

    // ── Voting ────────────────────────────────────────────────────────────────
    //
    //  XGBoost score  = 1 - P(BENIGN)   ∈ [0.0, 1.0]
    //  AE      score  = MSE(input,recon) ∈ [0.0, ∞)
    //
    //  Bảng voting:
    //    XGB=Attack | AE=Attack | VOTE:HIGH  conf = xgb_w*xgb_score + ae_w*ae_norm
    //    XGB=Attack | AE=Normal | VOTE:MED   conf = xgb_score * 0.80
    //    XGB=Normal | AE=Attack | VOTE:LOW   conf = ae_norm   * 0.60  (nếu ae_confident)
    //    XGB=Normal | AE=Normal | VOTE:NORM  conf = 0.0
    //
    //  ae_norm = min(ae_score / ae_high_threshold, 1.0)
    //    → chuẩn hóa MSE về [0,1] để so sánh với xgb_score
    EngineOutput combineVoting(const ModelOutput& xgb_out,
                               const ModelOutput& ae_out) const;

    static DetectionResult labelToThreat(int label);

    // ── Members ───────────────────────────────────────────────────────────────
    MLJobQueue&       job_queue_;
    MLAlertCallback   on_ml_alert_;

    NslKddExtractor   nslkdd_extractor_;   // ← THAY THẾ FeatureExtractor

    std::unique_ptr<OnnxXGBoost>     xgb_model_;
    std::unique_ptr<OnnxAutoencoder> ae_model_;

    MLConfig              cfg_;
    std::thread           thread_;
    std::atomic<bool>     running_         {false};
    std::atomic<uint64_t> jobs_processed_  {0};
    std::atomic<uint64_t> anomalies_found_ {0};
};

#endif // ML_ENGINE_HPP
