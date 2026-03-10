//src/ml/onnx_model.cpp
#include "onnx_model.hpp"
#include "../common/logger.hpp"
#include <cmath>
#include <numeric>
#include <sstream>
#include <algorithm> 

// ─── OnnxModel Implementation ─────────────────────────────────────────────────
// Phần này compile khi có ONNX Runtime
// Trong lab không có ONNX → dùng Mock models bên dưới

#ifdef USE_ONNX
#include <onnxruntime_cxx_api.h>

struct OnnxModel::OnnxImpl {
    Ort::Env            env{ORT_LOGGING_LEVEL_WARNING, "NetworkIDS"};
    Ort::SessionOptions session_options;
    std::unique_ptr<Ort::Session> session;
    std::vector<const char*> input_names  = {"input"};
    std::vector<const char*> output_names = {"output"};
};

OnnxModel::OnnxModel(const std::string& model_name, float threshold)
    : name_(model_name)
    , threshold_(threshold)
    , impl_(std::make_unique<OnnxImpl>()) {
    impl_->session_options.SetIntraOpNumThreads(1);
    impl_->session_options.SetGraphOptimizationLevel(
        GraphOptimizationLevel::ORT_ENABLE_BASIC);
}

OnnxModel::~OnnxModel() = default;

bool OnnxModel::load(const std::string& model_path) {
    try {
        impl_->session = std::make_unique<Ort::Session>(
            impl_->env,
            model_path.c_str(),
            impl_->session_options
        );
        loaded_ = true;
        LOG_INFO("ONNX model loaded: " + model_path);
        return true;
    } catch (const Ort::Exception& e) {
        LOG_ERROR("ONNX load failed: " + std::string(e.what()));
        return false;
    }
}

ModelOutput OnnxModel::infer(const FeatureVector& fv) {
    ModelOutput out;
    out.model_name = name_;

    if (!loaded_) {
        out.detail = "Model not loaded";
        return out;
    }

    try {
        auto arr = fv.toArray();

        // Tạo input tensor
        std::vector<int64_t> input_shape = {1, FeatureVector::SIZE};
        Ort::MemoryInfo mem_info = Ort::MemoryInfo::CreateCpu(
            OrtArenaAllocator, OrtMemTypeDefault);

        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            mem_info,
            arr.data(), arr.size(),
            input_shape.data(), input_shape.size()
        );

        // Run inference
        auto outputs = impl_->session->Run(
            Ort::RunOptions{nullptr},
            impl_->input_names.data(),  &input_tensor, 1,
            impl_->output_names.data(), 1
        );

        // Lấy score từ output
        float* output_data = outputs[0].GetTensorMutableData<float>();
        out.score      = output_data[0];
        out.is_anomaly = (out.score > threshold_);
        out.detail     = "ONNX inference score: "
                       + std::to_string(out.score);

    } catch (const Ort::Exception& e) {
        LOG_ERROR("ONNX inference failed: " + std::string(e.what()));
    }

    return out;
}

#else
// Stub khi không có ONNX Runtime
struct OnnxModel::OnnxImpl {};
OnnxModel::OnnxModel(const std::string& n, float t)
    : name_(n), threshold_(t) {}
OnnxModel::~OnnxModel() = default;
bool OnnxModel::load(const std::string&) {
    LOG_WARN("ONNX Runtime not available. Use Mock models.");
    return false;
}
ModelOutput OnnxModel::infer(const FeatureVector&) {
    return ModelOutput{};
}
#endif

// ─── Mock Isolation Forest ────────────────────────────────────────────────────
// Simulate anomaly score dựa trên heuristics từ báo cáo
ModelOutput MockIsolationForest::infer(const FeatureVector& fv) {
    ModelOutput out;
    out.model_name = name();

    float score = 0.f;

    // ── DDoS Volumetric signal ────────────────────────────────────────────────
    // pkt_rate cao + syn_no_ack_ratio cao → score tăng
    float ddos_signal = 0.f;
    if (fv.pkt_rate > 1000.f)
        ddos_signal += std::min((fv.pkt_rate - 1000.f) / 9000.f, 0.4f);
    if (fv.syn_no_ack_ratio > 0.7f)
        ddos_signal += (fv.syn_no_ack_ratio - 0.7f) / 0.3f * 0.3f;

    // ── Slow DDoS signal ──────────────────────────────────────────────────────
    // conn_duration cao + bytes_per_second thấp → score tăng
    float slow_signal = 0.f;
    if (fv.conn_duration > 30.f && fv.bytes_per_second < 10.f) {
        slow_signal += std::min(fv.conn_duration / 300.f, 0.35f);
        slow_signal += (1.f - std::min(fv.bytes_per_second / 10.f, 1.f))
                     * 0.25f;
    }
    if (fv.header_complete < 0.5f && fv.conn_duration > 30.f)
        slow_signal += 0.2f;

    // ── Port Scan signal ──────────────────────────────────────────────────────
    // unique_dst_ports cao + rst_ratio cao → score tăng
    float scan_signal = 0.f;
    if (fv.unique_dst_ports > 20.f)
        scan_signal += std::min((fv.unique_dst_ports - 20.f) / 80.f, 0.4f);
    if (fv.rst_ratio > 0.5f)
        scan_signal += (fv.rst_ratio - 0.5f) / 0.5f * 0.3f;

    // Tổng hợp — lấy max signal
    score = std::max(ddos_signal, std::max(slow_signal, scan_signal));

    // Thêm noise nhỏ để simulate tính ngẫu nhiên của IF
    // (trong production: IF thực sự có randomness từ random trees)
    score = std::clamp(score, 0.f, 1.f);

    out.score      = score;
    out.is_anomaly = (score > threshold_);

    // Xác định loại tấn công dựa trên signal mạnh nhất
    if (out.is_anomaly) {
        if (ddos_signal >= slow_signal && ddos_signal >= scan_signal)
            out.detail = "IF: DDoS Volumetric (score=" + std::to_string(score) + ")";
        else if (slow_signal >= scan_signal)
            out.detail = "IF: Slow DDoS (score=" + std::to_string(score) + ")";
        else
            out.detail = "IF: Port Scan (score=" + std::to_string(score) + ")";
    } else {
        out.detail = "IF: Normal (score=" + std::to_string(score) + ")";
    }

    return out;
}

// ─── Mock Autoencoder ─────────────────────────────────────────────────────────
// Simulate reconstruction error
// Autoencoder học phân phối traffic bình thường
// → Error cao với traffic bất thường
ModelOutput MockAutoencoder::infer(const FeatureVector& fv) {
    ModelOutput out;
    out.model_name = name();

    // Simulate "normal" baseline (trung bình của traffic bình thường)
    // Production: baseline này được học từ training data
    static const FeatureVector NORMAL_BASELINE = []() {
        FeatureVector b;
        b.flow_duration      = 5.f;
        b.pkt_rate           = 50.f;
        b.byte_rate          = 5000.f;
        b.syn_no_ack_ratio   = 0.05f;
        b.conn_duration      = 5.f;
        b.bytes_per_second   = 1000.f;
        b.inter_arrival_mean = 100.f;
        b.inter_arrival_std  = 30.f;
        b.header_complete    = 1.f;
        b.unique_dst_ports   = 2.f;
        b.rst_ratio          = 0.02f;
        return b;
    }();

    // Tính reconstruction error = ||x - x̂||²
    // x̂ ≈ NORMAL_BASELINE (simplified)
    // auto fv_arr   = fv.toArray();
    // auto base_arr = NORMAL_BASELINE.toArray();

    // Normalize trước khi tính error
    FeatureExtractor extractor;
    auto fv_norm   = extractor.normalize(fv).toArray();
    auto base_norm = extractor.normalize(NORMAL_BASELINE).toArray();

    float mse = 0.f;
    for (size_t i = 0; i < FeatureVector::SIZE; i++) {
        float diff = fv_norm[i] - base_norm[i];
        mse += diff * diff;
    }
    mse /= static_cast<float>(FeatureVector::SIZE);

    out.score      = mse;
    out.is_anomaly = (mse > threshold_);

    if (out.is_anomaly) {
        // Xác định loại dựa trên features nổi bật
        if (fv.conn_duration > 30.f && fv.bytes_per_second < 10.f)
            out.detail = "AE: Slow DDoS pattern (MSE="
                       + std::to_string(mse) + ")";
        else if (fv.pkt_rate > 1000.f)
            out.detail = "AE: DDoS Volumetric pattern (MSE="
                       + std::to_string(mse) + ")";
        else
            out.detail = "AE: Anomaly detected (MSE="
                       + std::to_string(mse) + ")";
    } else {
        out.detail = "AE: Normal (MSE=" + std::to_string(mse) + ")";
    }

    return out;
}
