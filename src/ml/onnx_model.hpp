#pragma once
#include "feature_extractor.hpp"
#include <string>
#include <memory>
#include <array>

// =============================================================================
//  ModelOutput
// =============================================================================
struct ModelOutput {
    bool        is_anomaly = false;
    float       score      = 0.f;   // anomaly score [0,1]
    int         label      = 0;     // XGBoost: 0=normal,1=ddos,2=slow,3=scan
    std::string detail;
};

// =============================================================================
//  IModel — interface chung
// =============================================================================
class IModel {
public:
    virtual ~IModel() = default;
    virtual bool        load  (const std::string& path)                              = 0;
    virtual ModelOutput infer (const std::array<float, FeatureVector::SIZE>& input)  = 0;
    virtual std::string name  () const                                               = 0;
    virtual bool        ready () const                                               = 0;
};

// =============================================================================
//  OnnxXGBoost — XGBoost multiclass classifier export sang ONNX
//
//  Input  : [1, 21]  float32
//  Output :
//    label        : [1]     int64    (0=Normal,1=DDoS,2=SlowDDoS,3=PortScan)
//    probabilities: [1, 4]  float32  (softmax per class)
//
//  is_anomaly = (label != 0) && (1 - prob[0] >= threshold)
//  score      = 1 - prob[0]
// =============================================================================
class OnnxXGBoost final : public IModel {
public:
    explicit OnnxXGBoost(float threshold = 0.5f);
    ~OnnxXGBoost() override;

    bool        load  (const std::string& path) override;
    ModelOutput infer (const std::array<float, FeatureVector::SIZE>& input) override;
    std::string name  () const override { return "XGBoost-ONNX"; }
    bool        ready () const override { return ready_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    float                 threshold_;
    bool                  ready_ = false;
};

// =============================================================================
//  OnnxAutoencoder — Autoencoder anomaly detection
//
//  Input  : [1, 21]  float32  (z-score normalized)
//  Output : [1, 21]  float32  (reconstruction)
//
//  anomaly_score = MSE(input, reconstruction)
//  is_anomaly    = (MSE > mse_threshold_)
// =============================================================================
class OnnxAutoencoder final : public IModel {
public:
    explicit OnnxAutoencoder(float mse_threshold = 0.1f);
    ~OnnxAutoencoder() override;

    bool        load  (const std::string& path) override;
    ModelOutput infer (const std::array<float, FeatureVector::SIZE>& input) override;
    std::string name  () const override { return "Autoencoder-ONNX"; }
    bool        ready () const override { return ready_; }

    static float computeMSE(const std::array<float, FeatureVector::SIZE>& input,
                             const float* recon, size_t size);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    float                 mse_threshold_;
    bool                  ready_ = false;
};
