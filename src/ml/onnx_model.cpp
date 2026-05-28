//  src/ml/onnx_model.cpp 


#include "onnx_model.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

#ifdef USE_ONNX
#include <onnxruntime_cxx_api.h>
#endif

#ifndef USE_ONNX
struct OnnxAutoencoder::Impl {};
OnnxAutoencoder::OnnxAutoencoder(float t) : threshold_(t) {}
OnnxAutoencoder::~OnnxAutoencoder() = default;
bool OnnxAutoencoder::load(const std::string& p) {
    LOG_WARN("OnnxAutoencoder::load — USE_ONNX not enabled: " + p); return false;
}
ModelOutput OnnxAutoencoder::infer(const std::vector<float>&) {
    return { false, 0.f, MODEL_LABEL_BENIGN, "DeepAE: USE_ONNX not enabled" };
}

struct OnnxXGBoost::Impl {};
OnnxXGBoost::OnnxXGBoost(float t) : threshold_(t) {}
OnnxXGBoost::~OnnxXGBoost() = default;
bool OnnxXGBoost::load(const std::string& p) {
    LOG_WARN("OnnxXGBoost::load — USE_ONNX not enabled: " + p); return false;
}
ModelOutput OnnxXGBoost::infer(const std::vector<float>&) {
    return { false, 0.f, MODEL_LABEL_BENIGN, "XGBoost: USE_ONNX not enabled" };
}

#else 

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

int readInputDim(Ort::Session& session) {
    auto shape = session.GetInputTypeInfo(0)
                        .GetTensorTypeAndShapeInfo().GetShape();
    if (shape.size() < 2 || shape[1] <= 0) {
        LOG_WARN("readInputDim: fallback to " + std::to_string(NSLKDD_INPUT_DIM));
        return NSLKDD_INPUT_DIM;
    }
    return static_cast<int>(shape[1]);
}

int argmaxN(const float* arr, int n) {
    return static_cast<int>(std::max_element(arr, arr + n) - arr);
}

} // namespace

struct OnnxAutoencoder::Impl {
    Ort::Session                     session;
    Ort::AllocatorWithDefaultOptions allocator;
    std::string input_name;
    std::string output_name;
    int         input_dim = NSLKDD_INPUT_DIM;

    explicit Impl(const std::string& path)
        : session(getOrtEnv(), path.c_str(), makeSessionOptions())
    {
        input_name  = session.GetInputNameAllocated (0, allocator).get();
        output_name = session.GetOutputNameAllocated(0, allocator).get();

        input_dim = readInputDim(session);
        if (input_dim != NSLKDD_INPUT_DIM) {
            LOG_WARN("OnnxAutoencoder: ONNX input_dim=" + std::to_string(input_dim)
                     + " != NSLKDD_INPUT_DIM=" + std::to_string(NSLKDD_INPUT_DIM)
                     + " — kiểm tra lại model và pipeline!");
        }

        auto out_shape = session.GetOutputTypeInfo(0)
                                .GetTensorTypeAndShapeInfo().GetShape();
        std::string ss = "[";
        for (size_t i = 0; i < out_shape.size(); ++i) {
            if (i) ss += ",";
            ss += std::to_string(out_shape[i]);
        }
        ss += "]";

        LOG_INFO("OnnxAutoencoder loaded: " + path
                 + "  input=" + input_name + "  output=" + output_name
                 + "  input_dim=" + std::to_string(input_dim)
                 + "  output_shape=" + ss);
    }
};

OnnxAutoencoder::OnnxAutoencoder(float t) : threshold_(t) {}
OnnxAutoencoder::~OnnxAutoencoder() = default;

bool OnnxAutoencoder::load(const std::string& path) {
    try {
        impl_      = std::make_unique<Impl>(path);
        input_dim_ = impl_->input_dim;
        ready_     = true;
        LOG_INFO("OnnxAutoencoder ready: input_dim=" + std::to_string(input_dim_)
                 + "  threshold=" + std::to_string(threshold_));
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

    if (static_cast<int>(input.size()) != input_dim_) {
        out.detail += "input size mismatch: got " + std::to_string(input.size())
                    + " expected " + std::to_string(input_dim_);
        LOG_WARN("OnnxAutoencoder::infer: " + out.detail);
        return out;
    }

    try {
        auto mem_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        std::vector<float> buf = input;
        std::array<int64_t, 2> shape { 1, static_cast<int64_t>(input_dim_) };

        Ort::Value in_tensor = Ort::Value::CreateTensor<float>(
            mem_info, buf.data(), buf.size(), shape.data(), shape.size());

        const char* in_names[]  = { impl_->input_name.c_str()  };
        const char* out_names[] = { impl_->output_name.c_str() };

        const auto t_ae = InferenceStats::now();
        auto outputs = impl_->session.Run(
            Ort::RunOptions{nullptr}, in_names, &in_tensor, 1, out_names, 1);
        INFER_STATS.recordAe(InferenceStats::elapsedUs(t_ae));

        const float* recon = outputs[0].GetTensorData<float>();
        float mse = 0.f;
        for (int i = 0; i < input_dim_; ++i) {
            const float d = input[i] - recon[i];
            mse += d * d;
        }
        mse /= static_cast<float>(input_dim_);

        out.score      = mse;
        out.is_anomaly = (mse > threshold_);
        out.label      = out.is_anomaly ? MODEL_LABEL_OTHER_ATTACK : MODEL_LABEL_BENIGN;

        std::ostringstream oss;
        oss << (out.is_anomaly ? "ATTACK" : "NORMAL")
            << " mse="       << std::fixed << std::setprecision(6) << mse
            << " threshold=" << threshold_;
        out.detail += oss.str();

    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxAutoencoder::infer ORT: " + std::string(e.what()));
        out.detail += "ORT error: " + std::string(e.what());
    }
    return out;
}

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
        input_name        = session.GetInputNameAllocated(0, allocator).get();
        const int n_out   = static_cast<int>(session.GetOutputCount());
        output_label_name = session.GetOutputNameAllocated(0, allocator).get();

        if (n_out >= 2) {
            output_prob_name = session.GetOutputNameAllocated(1, allocator).get();
            auto elem_type   = session.GetOutputTypeInfo(0)
                                      .GetTensorTypeAndShapeInfo().GetElementType();
            has_label_output = (elem_type == 7);  // INT64
        } else {
            output_prob_name = output_label_name;
            has_label_output = false;
        }

        input_dim = readInputDim(session);
        if (input_dim != NSLKDD_INPUT_DIM) {
            LOG_WARN("OnnxXGBoost: input_dim=" + std::to_string(input_dim)
                     + " != " + std::to_string(NSLKDD_INPUT_DIM));
        }

        LOG_INFO("OnnxXGBoost loaded: " + path
                 + "  input_dim=" + std::to_string(input_dim)
                 + "  n_outputs=" + std::to_string(n_out)
                 + "  has_label=" + (has_label_output ? "yes" : "no"));
    }
};

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

    if (static_cast<int>(input.size()) != input_dim_) {
        out.detail += "input size mismatch: got " + std::to_string(input.size())
                    + " expected " + std::to_string(input_dim_);
        LOG_WARN("OnnxXGBoost::infer: " + out.detail);
        return out;
    }

    try {
        auto mem_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        std::vector<float> buf = input;
        std::array<int64_t, 2> shape { 1, static_cast<int64_t>(input_dim_) };

        Ort::Value in_tensor = Ort::Value::CreateTensor<float>(
            mem_info, buf.data(), buf.size(), shape.data(), shape.size());

        int label = MODEL_LABEL_BENIGN; float p_benign = 1.f;

        if (impl_->has_label_output) {
            const char* in_names[]  = { impl_->input_name.c_str()        };
            const char* out_names[] = { impl_->output_label_name.c_str(),
                                        impl_->output_prob_name.c_str()   };
            const auto t_xgb = InferenceStats::now();
            auto outputs = impl_->session.Run(
                Ort::RunOptions{nullptr}, in_names, &in_tensor, 1, out_names, 2);
            INFER_STATS.recordXgb(InferenceStats::elapsedUs(t_xgb));
            label    = static_cast<int>(outputs[0].GetTensorData<int64_t>()[0]);
            p_benign = outputs[1].GetTensorData<float>()[MODEL_LABEL_BENIGN];
        } else {
            const char* in_names[]  = { impl_->input_name.c_str()       };
            const char* out_names[] = { impl_->output_prob_name.c_str() };
            const auto t_xgb = InferenceStats::now();
            auto outputs = impl_->session.Run(
                Ort::RunOptions{nullptr}, in_names, &in_tensor, 1, out_names, 1);
            INFER_STATS.recordXgb(InferenceStats::elapsedUs(t_xgb));
            const float* probs = outputs[0].GetTensorData<float>();
            label    = argmaxN(probs, MODEL_NUM_CLASSES);
            p_benign = probs[MODEL_LABEL_BENIGN];
        }

        out.label      = label;
        out.score      = 1.f - p_benign;
        out.is_anomaly = (label != MODEL_LABEL_BENIGN) && (out.score >= threshold_);

        std::ostringstream oss;
        oss << modelLabelToStr(label)
            << " score="    << std::fixed << std::setprecision(4) << out.score
            << " p_benign=" << p_benign;
        out.detail += oss.str();

    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxXGBoost::infer ORT: " + std::string(e.what()));
        out.detail += "ORT error: " + std::string(e.what());
    }
    return out;
}

#endif // USE_ONNX
