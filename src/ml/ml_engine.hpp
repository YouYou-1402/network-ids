#pragma once
#include "data_queue.hpp"
#include "onnx_model.hpp"
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

    ModelOutput     xgb_result;    // XGBoost classifier
    ModelOutput     ae_result;     // Autoencoder anomaly

    DetectionResult final_result = DetectionResult::NORMAL;
    float           confidence   = 0.f;
    std::string     detail;
};

using MLAlertCallback = std::function<void(const MLResult&)>;

// =============================================================================
//  MLConfig — cấu hình runtime, có thể reload không cần restart
// =============================================================================
struct MLConfig {
    std::string xgb_model_path;     // path to xgboost.onnx
    std::string ae_model_path;      // path to autoencoder.onnx
    std::string scaler_path;        // path to scaler.bin

    float xgb_threshold  = 0.5f;   // XGBoost: score >= thr → anomaly
    float ae_threshold   = 0.1f;   // Autoencoder: MSE >= thr → anomaly
    float min_confidence = 0.6f;   // Ngưỡng tối thiểu để emit alert

    // Voting weights: final_score = xgb_w * xgb_score + ae_w * ae_score
    // XGBoost có precision cao hơn (supervised) → weight cao hơn
    float xgb_weight = 0.65f;
    float ae_weight  = 0.35f;
};

// =============================================================================
//  MLEngine
// =============================================================================
class MLEngine {
public:
    MLEngine(MLJobQueue& job_queue, MLAlertCallback on_ml_alert);
    ~MLEngine();

    void start(const MLConfig& cfg);

    // Backward compat
    void start(bool               use_mock    = true,
               const std::string& xgb_path    = "",
               const std::string& ae_path     = "",
               const std::string& scaler_path = "");

    void stop();

    bool     isRunning     () const { return running_;          }
    uint64_t jobsProcessed () const { return jobs_processed_;   }
    uint64_t anomaliesFound() const { return anomalies_found_;  }

    // Reload models tại runtime — thread-safe (swap sau khi load xong)
    bool reloadModels(const MLConfig& cfg);

private:
    void     run();
    MLResult processJob(const MLJob& job);

    // Voting: XGBoost (supervised) + Autoencoder (unsupervised)
    //
    //  XGBoost  | AE       | Decision
    //  ---------|----------|-------------------------------------------------
    //  Attack   | Anomaly  | XGBoost label, HIGH conf = xgb_w*xgb + ae_w*ae
    //  Attack   | Normal   | XGBoost label, MEDIUM conf = xgb_score * 0.80
    //  Normal   | Anomaly  | UNKNOWN_ANOMALY, LOW conf = ae_score * 0.60
    //  Normal   | Normal   | NORMAL
    //
    DetectionResult combineResults(const ModelOutput& xgb_out,
                                   const ModelOutput& ae_out,
                                   float&             confidence) const;

    // Map XGBoost label int → DetectionResult
    // Dùng int (không parse string) → không bị lỗi khi đổi tên class
    static DetectionResult xgbLabelToThreat(int label);

    MLJobQueue&       job_queue_;
    MLAlertCallback   on_ml_alert_;
    FeatureExtractor  extractor_;

    std::unique_ptr<IModel> xgb_model_;
    std::unique_ptr<IModel> ae_model_;

    MLConfig              cfg_;
    std::thread           thread_;
    std::atomic<bool>     running_        {false};
    std::atomic<uint64_t> jobs_processed_ {0};
    std::atomic<uint64_t> anomalies_found_{0};
};
