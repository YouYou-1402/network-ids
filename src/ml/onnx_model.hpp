#pragma once
// =============================================================================
//  onnx_model.hpp
//  OnnxXGBoost      — XGBoost multiclass (5 class)
//  OnnxAutoencoder  — Encoder-Classifier multiclass (5 class)
//
//  label: 0=BENIGN  1=DDOS_VOLUMETRIC  2=SLOW_DDOS  3=PORT_SCAN  4=OTHER_ATTACK
//
//  ONNX I/O (khớp với Python export):
//    XGBoost:
//      input[0]  "X"             float[1][21]
//      output[0] "label"         int64[1]
//      output[1] "probabilities" float[1][5]
//    Autoencoder (EncoderClassifier):
//      input[0]  "X"             float[1][21]
//      output[0] "label"         int64[1]
//      output[1] "probabilities" float[1][5]
// =============================================================================

#ifndef ONNX_MODEL_HPP
#define ONNX_MODEL_HPP

#include <array>
#include <memory>
#include <string>
#include "feature_extractor.hpp"   // FeatureVector::SIZE = 21

// ─── ModelOutput ──────────────────────────────────────────────────────────────
struct ModelOutput {
    bool        is_anomaly = false;
    float       score      = 0.f;    // 1 - P(BENIGN)
    int         label      = 0;      // predicted class id
    std::string detail;
};

// ─── Label constants ──────────────────────────────────────────────────────────
static constexpr int MODEL_LABEL_BENIGN          = 0;
static constexpr int MODEL_LABEL_DDOS_VOLUMETRIC = 1;
static constexpr int MODEL_LABEL_SLOW_DDOS       = 2;
static constexpr int MODEL_LABEL_PORT_SCAN       = 3;
static constexpr int MODEL_LABEL_OTHER_ATTACK    = 4;
static constexpr int MODEL_NUM_CLASSES           = 5;

inline const char* modelLabelToStr(int label) {
    switch (label) {
        case MODEL_LABEL_BENIGN:          return "BENIGN";
        case MODEL_LABEL_DDOS_VOLUMETRIC: return "DDOS_VOLUMETRIC";
        case MODEL_LABEL_SLOW_DDOS:       return "SLOW_DDOS";
        case MODEL_LABEL_PORT_SCAN:       return "PORT_SCAN";
        case MODEL_LABEL_OTHER_ATTACK:    return "OTHER_ATTACK";
        default:                          return "UNKNOWN";
    }
}

// =============================================================================
//  OnnxXGBoost
//  Input:   float[1][21]  → "X"
//  Output0: int64[1]      → "label"
//  Output1: float[1][5]   → "probabilities"
// =============================================================================
class OnnxXGBoost {
public:
    explicit OnnxXGBoost(float threshold = 0.5f);
    ~OnnxXGBoost();

    OnnxXGBoost(const OnnxXGBoost&)            = delete;
    OnnxXGBoost& operator=(const OnnxXGBoost&) = delete;
    OnnxXGBoost(OnnxXGBoost&&)                 = default;
    OnnxXGBoost& operator=(OnnxXGBoost&&)      = default;

    bool        load (const std::string& path);
    ModelOutput infer(const std::array<float, FeatureVector::SIZE>& input);

    bool  isReady()             const { return ready_;     }
    float threshold()           const { return threshold_; }
    void  setThreshold(float t)       { threshold_ = t;    }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    float threshold_ = 0.5f;
    bool  ready_     = false;
};

// =============================================================================
//  OnnxAutoencoder  (Encoder-Classifier)
//
//  Python export (train_autoencoder.py):
//    input_names  = ["X"]
//    output_names = ["label", "probabilities"]
//
//  C++ tự động đọc tên từ ONNX metadata tại runtime (không hardcode)
//  → tương thích cả onnxmltools lẫn torch.onnx.export
//
//  Tính toán:
//    label      = output[0] (int64) hoặc argmax(output[1])
//    score      = 1 - probabilities[BENIGN]
//    is_anomaly = (label != BENIGN) && (score >= threshold)
// =============================================================================
class OnnxAutoencoder {
public:
    explicit OnnxAutoencoder(float threshold = 0.5f);
    ~OnnxAutoencoder();

    OnnxAutoencoder(const OnnxAutoencoder&)            = delete;
    OnnxAutoencoder& operator=(const OnnxAutoencoder&) = delete;
    OnnxAutoencoder(OnnxAutoencoder&&)                 = default;
    OnnxAutoencoder& operator=(OnnxAutoencoder&&)      = default;

    bool        load (const std::string& path);
    ModelOutput infer(const std::array<float, FeatureVector::SIZE>& input);

    bool  isReady()             const { return ready_;     }
    float threshold()           const { return threshold_; }
    void  setThreshold(float t)       { threshold_ = t;    }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    float threshold_ = 0.5f;
    bool  ready_     = false;
};

#endif // ONNX_MODEL_HPP
