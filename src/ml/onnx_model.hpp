#pragma once
// =============================================================================
//  onnx_model.hpp
//
//  OnnxXGBoost     — XGBoost multiclass 5-class, input float[1][39]
//  OnnxAutoencoder — Deep AE NSL-KDD,      input float[1][39]
//
//  Cả 2 model đều nhận vector<float>(39) từ NslKddExtractor::extractAndScale()
//  FeatureVector::SIZE=21 chỉ dùng cho L1 detection, KHÔNG liên quan ở đây.
//
//  ── XGBoost I/O ──────────────────────────────────────────────────────────────
//    input[0]  "input"         float[1][39]
//    output[0] "label"         int64[1]
//    output[1] "probabilities" float[1][5]
//    label: 0=BENIGN 1=DDOS_VOLUMETRIC 2=SLOW_DDOS 3=PORT_SCAN 4=OTHER_ATTACK
//
//  ── Autoencoder I/O ──────────────────────────────────────────────────────────
//    input[0]  "input"         float[1][39]
//    output[0] "output"        float[1][39]   ← reconstruction tensor
//
//    Scoring:
//      mse        = mean((input[i] - output[i])^2)
//      is_anomaly = mse > threshold
//      score      = mse
//      label      = MODEL_LABEL_OTHER_ATTACK(4) nếu anomaly
//                   MODEL_LABEL_BENIGN(0)       nếu normal
// =============================================================================

#ifndef ONNX_MODEL_HPP
#define ONNX_MODEL_HPP

#include <vector>
#include <memory>
#include <string>

// =============================================================================
//  Hằng số input dim — đọc từ metadata.json, định nghĩa 1 chỗ duy nhất
// =============================================================================
static constexpr int NSLKDD_INPUT_DIM = 39;

// =============================================================================
//  ModelOutput — kết quả chung cho cả XGBoost và Autoencoder
//
//  XGBoost:
//    score      = 1 - P(BENIGN)      ∈ [0.0, 1.0]
//    label      = class id           ∈ {0, 1, 2, 3, 4}
//    is_anomaly = (label != BENIGN) && (score >= threshold)
//
//  Autoencoder:
//    score      = MSE(input, recon)  ∈ [0.0, ∞)
//    label      = 4 (OTHER_ATTACK) nếu anomaly, 0 (BENIGN) nếu normal
//    is_anomaly = (mse > threshold)
// =============================================================================
struct ModelOutput {
    bool        is_anomaly = false;
    float       score      = 0.f;
    int         label      = 0;
    std::string detail;
};

// =============================================================================
//  Label constants
// =============================================================================
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
//
//  Input : vector<float>(NSLKDD_INPUT_DIM=39)
//  Output: label(int64) + probabilities(float[5])
//
//  Tự động detect output format tại load():
//    Case A: n_outputs=2 → output[0]=label(int64), output[1]=probs(float[5])
//    Case B: n_outputs=1 → output[0]=probs(float[5]), label=argmax(probs)
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

    // input: vector<float>(39) từ NslKddExtractor::extractAndScale()
    ModelOutput infer(const std::vector<float>& input);

    bool  isReady()             const { return ready_;     }
    float threshold()           const { return threshold_; }
    int   inputDim()            const { return input_dim_; }
    void  setThreshold(float t)       { threshold_ = t;    }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    float threshold_ = 0.5f;
    int   input_dim_ = NSLKDD_INPUT_DIM;  // validate tại infer()
    bool  ready_     = false;
};

// =============================================================================
//  OnnxAutoencoder — Deep AE NSL-KDD
//
//  Input : vector<float>(NSLKDD_INPUT_DIM=39)
//  Output: float[39] reconstruction → MSE → binary decision
//
//  input_dim validate tại infer():
//    input.size() != input_dim_ → LOG_WARN, trả về is_anomaly=false
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

    // input: vector<float>(39) từ NslKddExtractor::extractAndScale()
    ModelOutput infer(const std::vector<float>& input);

    bool  isReady()             const { return ready_;     }
    float threshold()           const { return threshold_; }
    int   inputDim()            const { return input_dim_; }
    void  setThreshold(float t)       { threshold_ = t;    }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    float threshold_ = 0.5f;
    int   input_dim_ = NSLKDD_INPUT_DIM;  // đọc lại từ ONNX graph tại load()
    bool  ready_     = false;
};

#endif // ONNX_MODEL_HPP
