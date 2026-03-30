#pragma once
// =============================================================================
//  src/ml/ml_engine.hpp
//
//  Thay đổi so với phiên bản cũ:
//    [XÓA] struct MLConfig định nghĩa ở đây
//    [THÊM] #include "ml_config.hpp"  ← single source of truth
// =============================================================================

#ifndef ML_ENGINE_HPP
#define ML_ENGINE_HPP

#include "ml_config.hpp"            // MLConfig — định nghĩa duy nhất
#include "data_queue.hpp"
#include "onnx_model.hpp"           // OnnxXGBoost, OnnxAutoencoder, ModelOutput
#include "feature_extractor.hpp"
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

    /// Khởi động với config đầy đủ — dùng trong main.cpp và ui_main.cpp
    void start(const MLConfig& cfg);

    /// Backward compat — mock mode hoặc path trực tiếp
    void start(bool               use_mock    = true,
               const std::string& xgb_path    = "",
               const std::string& ae_path     = "",
               const std::string& scaler_path = "");

    void stop();

    /// Reload models tại runtime (thread-safe)
    bool reloadModels(const MLConfig& cfg);

    bool     isRunning     () const { return running_;         }
    uint64_t jobsProcessed () const { return jobs_processed_;  }
    uint64_t anomaliesFound() const { return anomalies_found_; }
    std::string status() const;

private:
    void     run();
    MLResult processJob(const MLJob& job);

    // Voting logic:
    //  XGBoost  | AE      | Decision
    //  ---------|---------|---------------------------------------------------
    //  Attack   | Attack  | XGBoost label, HIGH   conf = xgb_w*xgb + ae_w*ae
    //  Attack   | Benign  | XGBoost label, MEDIUM conf = xgb_score * 0.80
    //  Benign   | Attack  | UNKNOWN_ANOMALY, LOW  conf = ae_score  * 0.60
    //  Benign   | Benign  | NORMAL
    EngineOutput combineVoting(const ModelOutput& xgb_out,
                               const ModelOutput& ae_out) const;

    static DetectionResult labelToThreat(int label);

    MLJobQueue&       job_queue_;
    MLAlertCallback   on_ml_alert_;
    FeatureExtractor  extractor_;

    std::unique_ptr<OnnxXGBoost>     xgb_model_;
    std::unique_ptr<OnnxAutoencoder> ae_model_;

    MLConfig              cfg_;
    std::thread           thread_;
    std::atomic<bool>     running_         {false};
    std::atomic<uint64_t> jobs_processed_  {0};
    std::atomic<uint64_t> anomalies_found_ {0};
};

#endif // ML_ENGINE_HPP
