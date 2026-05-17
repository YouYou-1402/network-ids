#pragma once
//  src/ml/onnx_model.hpp

#ifndef ONNX_MODEL_HPP
#define ONNX_MODEL_HPP

#include <vector>
#include <memory>
#include <string>

static constexpr int NSLKDD_INPUT_DIM = 35;

struct ModelOutput {
    bool        is_anomaly = false;
    float       score      = 0.f;
    int         label      = 0;
    std::string detail;
};

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

class OnnxAutoencoder {
public:
    explicit OnnxAutoencoder(float threshold = 0.099726f);
    ~OnnxAutoencoder();

    OnnxAutoencoder(const OnnxAutoencoder&)            = delete;
    OnnxAutoencoder& operator=(const OnnxAutoencoder&) = delete;
    OnnxAutoencoder(OnnxAutoencoder&&)                 = default;
    OnnxAutoencoder& operator=(OnnxAutoencoder&&)      = default;

    bool        load (const std::string& path);
    ModelOutput infer(const std::vector<float>& input);

    bool  isReady()             const { return ready_;     }
    float threshold()           const { return threshold_; }
    int   inputDim()            const { return input_dim_; }
    void  setThreshold(float t)       { threshold_ = t;    }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    float threshold_ = 0.099726f;
    int   input_dim_ = NSLKDD_INPUT_DIM;
    bool  ready_     = false;
};

class OnnxXGBoost {
public:
    explicit OnnxXGBoost(float threshold = 0.5f);
    ~OnnxXGBoost();

    OnnxXGBoost(const OnnxXGBoost&)            = delete;
    OnnxXGBoost& operator=(const OnnxXGBoost&) = delete;
    OnnxXGBoost(OnnxXGBoost&&)                 = default;
    OnnxXGBoost& operator=(OnnxXGBoost&&)      = default;

    bool        load (const std::string& path);
    ModelOutput infer(const std::vector<float>& input);

    bool  isReady()             const { return ready_;     }
    float threshold()           const { return threshold_; }
    int   inputDim()            const { return input_dim_; }
    void  setThreshold(float t)       { threshold_ = t;    }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    float threshold_ = 0.5f;
    int   input_dim_ = NSLKDD_INPUT_DIM;
    bool  ready_     = false;
};

#endif // ONNX_MODEL_HPP
