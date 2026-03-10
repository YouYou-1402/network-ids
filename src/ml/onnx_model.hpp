//src/ml/onnx_model.hpp
#pragma once
#include "feature_extractor.hpp"
#include <string>
#include <vector>
#include <memory>

// Kết quả inference từ một model
struct ModelOutput {
    float       score     = 0.f;  // Anomaly score [0,1]
    bool        is_anomaly = false;
    std::string model_name;
    std::string detail;
};

// ─── Interface chung cho mọi ML model ────────────────────────────────────────
class IModel {
public:
    virtual ~IModel() = default;

    virtual bool load(const std::string& model_path) = 0;
    virtual ModelOutput infer(const FeatureVector& fv) = 0;
    virtual bool isLoaded() const = 0;
    virtual std::string name() const = 0;
};

// ─── ONNX Runtime Model ───────────────────────────────────────────────────────
// Wrapper thực sự dùng ONNX Runtime C++ API
// Compile với: -DUSE_ONNX=ON trong CMake
class OnnxModel : public IModel {
public:
    explicit OnnxModel(const std::string& model_name,
                       float              threshold = 0.6f);
    ~OnnxModel() override;

    bool        load(const std::string& model_path) override;
    ModelOutput infer(const FeatureVector& fv) override;
    bool        isLoaded() const override { return loaded_; }
    std::string name()     const override { return name_; }

private:
    std::string name_;
    float       threshold_;
    bool        loaded_ = false;

    // ONNX Runtime objects (pimpl để tránh expose onnxruntime headers)
    struct OnnxImpl;
    std::unique_ptr<OnnxImpl> impl_;
};

// ─── Mock Model (dùng khi không có ONNX Runtime) ─────────────────────────────
// Simulate behavior của Isolation Forest và Autoencoder
// Đủ để test kiến trúc mà không cần model thật
class MockIsolationForest : public IModel {
public:
    explicit MockIsolationForest(float threshold = 0.6f)
        : threshold_(threshold) {}

    bool load(const std::string&) override {
        loaded_ = true;
        return true;
    }

    // Simulate Isolation Forest logic dựa trên heuristics
    ModelOutput infer(const FeatureVector& fv) override;

    bool        isLoaded() const override { return loaded_; }
    std::string name()     const override { return "MockIsolationForest"; }

private:
    float threshold_;
    bool  loaded_ = false;
};

class MockAutoencoder : public IModel {
public:
    explicit MockAutoencoder(float threshold = 0.05f)
        : threshold_(threshold) {}

    bool load(const std::string&) override {
        loaded_ = true;
        return true;
    }

    // Simulate Autoencoder reconstruction error
    ModelOutput infer(const FeatureVector& fv) override;

    bool        isLoaded() const override { return loaded_; }
    std::string name()     const override { return "MockAutoencoder"; }

private:
    float threshold_;
    bool  loaded_ = false;
};
