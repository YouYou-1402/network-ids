// =============================================================================
//  onnx_model.cpp
// =============================================================================

#include "onnx_model.hpp"
#include "../common/logger.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <stdexcept>

#ifdef USE_ONNX
#include <onnxruntime_cxx_api.h>
#endif

// =============================================================================
//  Mock — build không có USE_ONNX
// =============================================================================
#ifndef USE_ONNX

struct OnnxXGBoost::Impl {};
OnnxXGBoost::OnnxXGBoost(float t) : threshold_(t) {}
OnnxXGBoost::~OnnxXGBoost() = default;
bool OnnxXGBoost::load(const std::string& p) {
    LOG_WARN("OnnxXGBoost::load — USE_ONNX not enabled: " + p);
    return false;
}
ModelOutput OnnxXGBoost::infer(const std::vector<float>&) {
    return { false, 0.f, MODEL_LABEL_BENIGN, "XGBoost: USE_ONNX not enabled" };
}

struct OnnxAutoencoder::Impl {};
OnnxAutoencoder::OnnxAutoencoder(float t) : threshold_(t) {}
OnnxAutoencoder::~OnnxAutoencoder() = default;
bool OnnxAutoencoder::load(const std::string& p) {
    LOG_WARN("OnnxAutoencoder::load — USE_ONNX not enabled: " + p);
    return false;
}
ModelOutput OnnxAutoencoder::infer(const std::vector<float>&) {
    return { false, 0.f, MODEL_LABEL_BENIGN, "DeepAE: USE_ONNX not enabled" };
}

#else // USE_ONNX ===============================================================

// =============================================================================
//  ORT helpers
// =============================================================================
namespace {

Ort::Env& getOrtEnv() {
    static Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "network-ids");
    return env;
}

Ort::SessionOptions makeSessionOptions() {
    Ort::SessionOptions opts;
    opts.SetIntraOpNumThreads(1);
    opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
    opts.SetExecutionMode(ExecutionMode::ORT_SEQUENTIAL);
    return opts;
}

// Đọc input_dim từ ONNX graph (dim[1] của input tensor đầu tiên)
int readInputDim(Ort::Session& session) {
    Ort::AllocatorWithDefaultOptions alloc;
    auto type_info = session.GetInputTypeInfo(0);
    auto shape     = type_info.GetTensorTypeAndShapeInfo().GetShape();
    // shape = [batch_size(-1), input_dim]
    if (shape.size() < 2 || shape[1] <= 0) {
        LOG_WARN("readInputDim: unexpected shape, fallback to NSLKDD_INPUT_DIM="
                 + std::to_string(NSLKDD_INPUT_DIM));
        return NSLKDD_INPUT_DIM;
    }
    return static_cast<int>(shape[1]);
}

int argmaxN(const float* arr, int n) {
    return static_cast<int>(std::max_element(arr, arr + n) - arr);
}

} // namespace

// =============================================================================
//  OnnxXGBoost::Impl
// =============================================================================
struct OnnxXGBoost::Impl {
    Ort::Session                     session;
    Ort::AllocatorWithDefaultOptions allocator;

    std::string input_name;
    std::string output_label_name;
    std::string output_prob_name;
    bool        has_label_output = false;
    int         input_dim        = NSLKDD_INPUT_DIM;

    explicit Impl(const std::string& path)
        : session(getOrtEnv(), path.c_str(), makeSessionOptions())
    {
        // ── Đọc tên I/O từ ONNX metadata ─────────────────────────────────────
        input_name        = session.GetInputNameAllocated (0, allocator).get();
        const int n_out   = static_cast<int>(session.GetOutputCount());
        output_label_name = session.GetOutputNameAllocated(0, allocator).get();

        if (n_out >= 2) {
            output_prob_name = session.GetOutputNameAllocated(1, allocator).get();
            // Kiểm tra output[0] có phải int64 không
            // ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64 = 7
            auto elem_type = session.GetOutputTypeInfo(0)
                                    .GetTensorTypeAndShapeInfo()
                                    .GetElementType();
            has_label_output = (elem_type == 7);
        } else {
            // 1 output → probabilities only
            output_prob_name = output_label_name;
            has_label_output = false;
        }

        // ── Đọc input_dim từ graph ────────────────────────────────────────────
        input_dim = readInputDim(session);

        // ── Validate prob output shape ────────────────────────────────────────
        const int prob_idx = has_label_output ? 1 : 0;
        auto prob_shape    = session.GetOutputTypeInfo(prob_idx)
                                    .GetTensorTypeAndShapeInfo().GetShape();
        if (prob_shape.size() >= 2 && prob_shape[1] != MODEL_NUM_CLASSES) {
            LOG_WARN("OnnxXGBoost: prob output dim=" + std::to_string(prob_shape[1])
                     + " expected " + std::to_string(MODEL_NUM_CLASSES));
        }

        LOG_INFO("OnnxXGBoost loaded: " + path
                 + "\n  input="      + input_name
                 + " input_dim="     + std::to_string(input_dim)
                 + " n_outputs="     + std::to_string(n_out)
                 + " has_label="     + (has_label_output ? "yes" : "no")
                 + "\n  output[0]="  + output_label_name
                 + (n_out >= 2 ? "  output[1]=" + output_prob_name : ""));
    }
};

// ── OnnxXGBoost ───────────────────────────────────────────────────────────────

OnnxXGBoost::OnnxXGBoost(float t) : threshold_(t) {}
OnnxXGBoost::~OnnxXGBoost() = default;

bool OnnxXGBoost::load(const std::string& path) {
    try {
        impl_      = std::make_unique<Impl>(path);
        input_dim_ = impl_->input_dim;
        ready_     = true;
        return true;
    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxXGBoost::load ORT: " + std::string(e.what()));
    } catch (const std::exception& e) {
        LOG_ERROR("OnnxXGBoost::load: "     + std::string(e.what()));
    }
    return false;
}

ModelOutput OnnxXGBoost::infer(const std::vector<float>& input) {
    ModelOutput out;
    out.detail = "XGBoost: ";
    if (!ready_) { out.detail += "not loaded"; return out; }

    // ── Validate input size ───────────────────────────────────────────────────
    if (static_cast<int>(input.size()) != input_dim_) {
        out.detail += "input size mismatch: got "
                    + std::to_string(input.size())
                    + " expected " + std::to_string(input_dim_);
        LOG_WARN("OnnxXGBoost::infer: " + out.detail);
        return out;
    }

    try {
        auto mem_info = Ort::MemoryInfo::CreateCpu(
            OrtArenaAllocator, OrtMemTypeDefault);

        // Copy vào buffer (ORT cần non-const pointer)
        std::vector<float> buf = input;
        std::array<int64_t, 2> shape { 1, static_cast<int64_t>(input_dim_) };

        Ort::Value in_tensor = Ort::Value::CreateTensor<float>(
            mem_info, buf.data(), buf.size(),
            shape.data(), shape.size());

        int   label    = MODEL_LABEL_BENIGN;
        float p_benign = 1.f;

        if (impl_->has_label_output) {
            // Case A: output[0]=label(int64), output[1]=probs(float[5])
            const char* in_names[]  = { impl_->input_name.c_str()        };
            const char* out_names[] = { impl_->output_label_name.c_str(),
                                        impl_->output_prob_name.c_str()   };
            auto outputs = impl_->session.Run(
                Ort::RunOptions{nullptr},
                in_names, &in_tensor, 1,
                out_names, 2);

            label    = static_cast<int>(outputs[0].GetTensorData<int64_t>()[0]);
            p_benign = outputs[1].GetTensorData<float>()[MODEL_LABEL_BENIGN];

        } else {
            // Case B: output[0]=probs(float[5])
            const char* in_names[]  = { impl_->input_name.c_str()       };
            const char* out_names[] = { impl_->output_prob_name.c_str() };
            auto outputs = impl_->session.Run(
                Ort::RunOptions{nullptr},
                in_names, &in_tensor, 1,
                out_names, 1);

            const float* probs = outputs[0].GetTensorData<float>();
            label    = argmaxN(probs, MODEL_NUM_CLASSES);
            p_benign = probs[MODEL_LABEL_BENIGN];
        }

        out.label      = label;
        out.score      = 1.f - p_benign;
        out.is_anomaly = (label != MODEL_LABEL_BENIGN)
                      && (out.score >= threshold_);

        std::ostringstream oss;
        oss << modelLabelToStr(label)
            << " score="    << std::fixed << std::setprecision(4) << out.score
            << " p_benign=" << std::setprecision(4) << p_benign;
        out.detail += oss.str();

    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxXGBoost::infer ORT: " + std::string(e.what()));
        out.detail += "ORT error: " + std::string(e.what());
    }
    return out;
}

// =============================================================================
//  OnnxAutoencoder::Impl
//
//  Deep AE NSL-KDD:
//    input[0]  "input"  float[1][39]
//    output[0] "output" float[1][39]  ← reconstruction
//
//  input_dim đọc từ ONNX graph tại load().
//  Không có label/probabilities output — chỉ có reconstruction.
// =============================================================================
struct OnnxAutoencoder::Impl {
    Ort::Session                     session;
    Ort::AllocatorWithDefaultOptions allocator;

    std::string input_name;
    std::string output_name;
    int         input_dim = NSLKDD_INPUT_DIM;

    explicit Impl(const std::string& path)
        : session(getOrtEnv(), path.c_str(), makeSessionOptions())
    {
        // ── Đọc tên I/O ───────────────────────────────────────────────────────
        input_name  = session.GetInputNameAllocated (0, allocator).get();
        output_name = session.GetOutputNameAllocated(0, allocator).get();

        const int n_out = static_cast<int>(session.GetOutputCount());

        // ── Đọc input_dim từ graph ────────────────────────────────────────────
        input_dim = readInputDim(session);

        // ── Validate output shape = [batch, input_dim] ────────────────────────
        auto out_shape = session.GetOutputTypeInfo(0)
                                .GetTensorTypeAndShapeInfo().GetShape();

        std::string shape_str = "[";
        for (size_t i = 0; i < out_shape.size(); ++i) {
            if (i) shape_str += ",";
            shape_str += std::to_string(out_shape[i]);
        }
        shape_str += "]";

        if (out_shape.size() >= 2 && out_shape[1] != input_dim) {
            LOG_WARN("OnnxAutoencoder: output shape " + shape_str
                     + " != input_dim " + std::to_string(input_dim)
                     + " — reconstruction MSE sẽ sai!");
        }

        LOG_INFO("OnnxAutoencoder (Deep AE NSL-KDD) loaded: " + path
                 + "\n  input="       + input_name
                 + " output="         + output_name
                 + " input_dim="      + std::to_string(input_dim)
                 + " n_outputs="      + std::to_string(n_out)
                 + " output_shape="   + shape_str);
    }
};

// ── OnnxAutoencoder ───────────────────────────────────────────────────────────

OnnxAutoencoder::OnnxAutoencoder(float t) : threshold_(t) {}
OnnxAutoencoder::~OnnxAutoencoder() = default;

bool OnnxAutoencoder::load(const std::string& path) {
    try {
        impl_      = std::make_unique<Impl>(path);
        input_dim_ = impl_->input_dim;
        ready_     = true;
        return true;
    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxAutoencoder::load ORT: " + std::string(e.what()));
    } catch (const std::exception& e) {
        LOG_ERROR("OnnxAutoencoder::load: "     + std::string(e.what()));
    }
    return false;
}

ModelOutput OnnxAutoencoder::infer(const std::vector<float>& input) {
    ModelOutput out;
    out.detail = "DeepAE: ";
    if (!ready_) { out.detail += "not loaded"; return out; }

    // ── Validate input size ───────────────────────────────────────────────────
    if (static_cast<int>(input.size()) != input_dim_) {
        out.detail += "input size mismatch: got "
                    + std::to_string(input.size())
                    + " expected " + std::to_string(input_dim_);
        LOG_WARN("OnnxAutoencoder::infer: " + out.detail);
        return out;
    }

    try {
        auto mem_info = Ort::MemoryInfo::CreateCpu(
            OrtArenaAllocator, OrtMemTypeDefault);

        std::vector<float> buf = input;
        std::array<int64_t, 2> shape { 1, static_cast<int64_t>(input_dim_) };

        Ort::Value in_tensor = Ort::Value::CreateTensor<float>(
            mem_info, buf.data(), buf.size(),
            shape.data(), shape.size());

        const char* in_names[]  = { impl_->input_name.c_str()  };
        const char* out_names[] = { impl_->output_name.c_str() };

        auto outputs = impl_->session.Run(
            Ort::RunOptions{nullptr},
            in_names, &in_tensor, 1,
            out_names, 1);

        // ── Tính MSE(input, reconstruction) ──────────────────────────────────
        const float* recon = outputs[0].GetTensorData<float>();
        float mse = 0.f;
        for (int i = 0; i < input_dim_; ++i) {
            const float diff = input[i] - recon[i];
            mse += diff * diff;
        }
        mse /= static_cast<float>(input_dim_);

        // ── Quyết định ────────────────────────────────────────────────────────
        out.score      = mse;
        out.is_anomaly = (mse > threshold_);
        out.label      = out.is_anomaly
                       ? MODEL_LABEL_OTHER_ATTACK   // AE chỉ biết "bất thường"
                       : MODEL_LABEL_BENIGN;        // không biết loại cụ thể

        std::ostringstream oss;
        oss << (out.is_anomaly ? "ATTACK" : "NORMAL")
            << " mse="       << std::fixed << std::setprecision(6) << mse
            << " threshold=" << std::setprecision(6) << threshold_;
        out.detail += oss.str();

    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxAutoencoder::infer ORT: " + std::string(e.what()));
        out.detail += "ORT error: " + std::string(e.what());
    }
    return out;
}

#endif // USE_ONNX
