#pragma once
// =============================================================================
//  ml_engine.hpp
//  MLEngine — worker thread: đọc MLJob từ queue, chạy XGBoost + AEClassifier,
//             voting, emit MLResult qua callback.
// =============================================================================

#ifndef ML_ENGINE_HPP
#define ML_ENGINE_HPP

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
//  MLResult — kết quả tổng hợp từ XGBoost + AEClassifier
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
//  MLConfig
// =============================================================================

struct MLConfig {
    std::string xgb_model_path;
    std::string ae_model_path;
    std::string scaler_path;

    float xgb_threshold  = 0.5f;
    float ae_threshold   = 0.5f;
    float min_confidence = 0.6f;

    float xgb_weight = 0.65f;
    float ae_weight  = 0.35f;
};

// =============================================================================
//  EngineOutput — kết quả voting nội bộ (dùng trong combineResults)
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

    // Non-copyable
    MLEngine(const MLEngine&)            = delete;
    MLEngine& operator=(const MLEngine&) = delete;

    // Khởi động với config đầy đủ
    void start(const MLConfig& cfg);

    // Backward compat
    void start(bool               use_mock    = true,
               const std::string& xgb_path    = "",
               const std::string& ae_path     = "",
               const std::string& scaler_path = "");

    void stop();

    // Reload models tại runtime (thread-safe)
    bool reloadModels(const MLConfig& cfg);

    // Getters
    bool     isRunning     () const { return running_;          }
    uint64_t jobsProcessed () const { return jobs_processed_;   }
    uint64_t anomaliesFound() const { return anomalies_found_;  }

    std::string status() const;

private:
    void     run();
    MLResult processJob(const MLJob& job);

    // Voting logic
    //
    //  XGBoost  | AE       | Decision
    //  ---------|----------|-------------------------------------------------
    //  Attack   | Attack   | XGBoost label, HIGH   conf = xgb_w*xgb + ae_w*ae
    //  Attack   | Benign   | XGBoost label, MEDIUM conf = xgb_score * 0.80
    //  Benign   | Attack   | UNKNOWN_ANOMALY, LOW  conf = ae_score  * 0.60
    //  Benign   | Benign   | NORMAL
    //
    EngineOutput combineVoting(const ModelOutput& xgb_out,
                               const ModelOutput& ae_out) const;

    // Map label int → DetectionResult
    static DetectionResult labelToThreat(int label);

    // ── Members ──────────────────────────────────────────────────────────
    MLJobQueue&       job_queue_;
    MLAlertCallback   on_ml_alert_;
    FeatureExtractor  extractor_;

    // ✅ Dùng trực tiếp concrete types, KHÔNG dùng IModel
    std::unique_ptr<OnnxXGBoost>     xgb_model_;
    std::unique_ptr<OnnxAutoencoder> ae_model_;

    MLConfig              cfg_;
    std::thread           thread_;
    std::atomic<bool>     running_         {false};
    std::atomic<uint64_t> jobs_processed_  {0};
    std::atomic<uint64_t> anomalies_found_ {0};
};

#endif // ML_ENGINE_HPP
