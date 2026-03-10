//src/ml/ml_engine.hpp
#pragma once
#include "data_queue.hpp"
#include "onnx_model.hpp"
#include "feature_extractor.hpp"
#include "../core/threat_types.hpp"
#include <thread>
#include <atomic>
#include <functional>
#include <memory>

// Kết quả tổng hợp từ cả hai models
struct MLResult {
    std::string    flow_key;
    uint32_t       src_ip;
    uint32_t       dst_ip;
    uint16_t       src_port;
    uint16_t       dst_port;
    double         timestamp;

    // Kết quả từng model
    ModelOutput    if_result;   // Isolation Forest
    ModelOutput    ae_result;   // Autoencoder

    // Quyết định tổng hợp
    DetectionResult final_result;
    float           confidence;  // 0.0 – 1.0
    std::string     detail;
};

// Callback khi ML phát hiện bất thường
using MLAlertCallback = std::function<void(const MLResult&)>;

class MLEngine {
public:
    MLEngine(MLJobQueue&     job_queue,
             MLAlertCallback on_ml_alert);
    ~MLEngine();

    // Khởi động ML engine thread
    void start(bool use_mock = true,
               const std::string& if_model_path  = "",
               const std::string& ae_model_path  = "");

    void stop();

    bool isRunning() const { return running_; }

    // Stats
    uint64_t jobsProcessed() const { return jobs_processed_; }
    uint64_t anomaliesFound() const { return anomalies_found_; }

private:
    void run();

    // Xử lý một MLJob
    MLResult processJob(const MLJob& job);

    // Tổng hợp kết quả từ IF + AE
    DetectionResult combineResults(const ModelOutput& if_out,
                                   const ModelOutput& ae_out,
                                   const FeatureVector& fv,
                                   float& confidence) const;

    // Xác định loại tấn công từ feature vector
    DetectionResult classifyThreat(const FeatureVector& fv) const;

    MLJobQueue&       job_queue_;
    MLAlertCallback   on_ml_alert_;
    FeatureExtractor  extractor_;

    std::unique_ptr<IModel> if_model_;
    std::unique_ptr<IModel> ae_model_;

    std::thread       thread_;
    std::atomic<bool> running_{false};

    std::atomic<uint64_t> jobs_processed_{0};
    std::atomic<uint64_t> anomalies_found_{0};
};
