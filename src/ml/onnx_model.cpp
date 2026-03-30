// =============================================================================
//  onnx_model.cpp
// =============================================================================

#include "onnx_model.hpp"
#include "../common/logger.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
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
ModelOutput OnnxXGBoost::infer(const std::array<float, FeatureVector::SIZE>&) {
    return { false, 0.f, 0, "XGBoost: USE_ONNX not enabled" };
}

struct OnnxAutoencoder::Impl {};
OnnxAutoencoder::OnnxAutoencoder(float t) : threshold_(t) {}
OnnxAutoencoder::~OnnxAutoencoder() = default;
bool OnnxAutoencoder::load(const std::string& p) {
    LOG_WARN("OnnxAutoencoder::load — USE_ONNX not enabled: " + p);
    return false;
}
ModelOutput OnnxAutoencoder::infer(const std::array<float, FeatureVector::SIZE>&) {
    return { false, 0.f, 0, "AEClassifier: USE_ONNX not enabled" };
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

int argmax5(const float* arr) {
    return static_cast<int>(
        std::max_element(arr, arr + MODEL_NUM_CLASSES) - arr);
}

} // namespace

// =============================================================================
//  OnnxXGBoost::Impl
// =============================================================================
struct OnnxXGBoost::Impl {
    Ort::Session                     session;
    Ort::AllocatorWithDefaultOptions allocator;

    // Tên đọc từ ONNX metadata — không hardcode
    std::string input_name;
    std::string output_label_name;
    std::string output_prob_name;

    // Có thể không có output label (một số onnxmltools export chỉ có probs)
    bool has_label_output = true;

    std::array<int64_t, 2> input_shape {
        1, static_cast<int64_t>(FeatureVector::SIZE)
    };

    explicit Impl(const std::string& path)
        : session(getOrtEnv(), path.c_str(), makeSessionOptions())
    {
        input_name = session.GetInputNameAllocated(0, allocator).get();

        const int n_outputs = static_cast<int>(session.GetOutputCount());
        output_label_name   = session.GetOutputNameAllocated(0, allocator).get();

        if (n_outputs >= 2) {
            output_prob_name = session.GetOutputNameAllocated(1, allocator).get();
            has_label_output = true;
        } else {
            // Chỉ có 1 output → là probabilities
            output_prob_name  = output_label_name;
            has_label_output  = false;
        }

        LOG_INFO("OnnxXGBoost loaded: " + path
                 + "\n  input=" + input_name
                 + " n_outputs=" + std::to_string(n_outputs)
                 + " label_out=" + output_label_name
                 + " prob_out="  + output_prob_name
                 + " has_label=" + (has_label_output ? "yes" : "no"));
    }
};

OnnxXGBoost::OnnxXGBoost(float t) : threshold_(t) {}
OnnxXGBoost::~OnnxXGBoost() = default;

bool OnnxXGBoost::load(const std::string& path) {
    try {
        impl_  = std::make_unique<Impl>(path);
        ready_ = true;
        return true;
    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxXGBoost::load ORT: " + std::string(e.what()));
    } catch (const std::exception& e) {
        LOG_ERROR("OnnxXGBoost::load: " + std::string(e.what()));
    }
    return false;
}

ModelOutput OnnxXGBoost::infer(
    const std::array<float, FeatureVector::SIZE>& input)
{
    ModelOutput out;
    out.detail = "XGBoost: ";
    if (!ready_) { out.detail += "not loaded"; return out; }

    try {
        auto mem_info = Ort::MemoryInfo::CreateCpu(
            OrtArenaAllocator, OrtMemTypeDefault);
        std::array<float, FeatureVector::SIZE> buf = input;

        Ort::Value in_tensor = Ort::Value::CreateTensor<float>(
            mem_info, buf.data(), buf.size(),
            impl_->input_shape.data(), impl_->input_shape.size());

        int label = 0;
        float p_benign = 0.f;

        if (impl_->has_label_output) {
            // 2 outputs: label + probabilities
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
            // 1 output: probabilities only
            const char* in_names[]  = { impl_->input_name.c_str()       };
            const char* out_names[] = { impl_->output_prob_name.c_str() };

            auto outputs = impl_->session.Run(
                Ort::RunOptions{nullptr},
                in_names, &in_tensor, 1,
                out_names, 1);

            const float* probs = outputs[0].GetTensorData<float>();
            label    = argmax5(probs);
            p_benign = probs[MODEL_LABEL_BENIGN];
        }

        out.label      = label;
        out.score      = 1.f - p_benign;
        out.is_anomaly = (label != MODEL_LABEL_BENIGN)
                      && (out.score >= threshold_);

        std::ostringstream oss;
        oss << modelLabelToStr(label)
            << " score=" << std::fixed << std::setprecision(3) << out.score
            << " p_benign=" << p_benign;
        out.detail += oss.str();

    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxXGBoost::infer: " + std::string(e.what()));
        out.detail += "ORT error: " + std::string(e.what());
    }
    return out;
}

// =============================================================================
//  OnnxAutoencoder::Impl
//  ─────────────────────────────────────────────────────────────────────────
//  Tự động detect output format tại load():
//
//  Case A — torch.onnx.export (train_autoencoder.py):
//    n_outputs = 2
//    output[0] = "label"          int64[batch]
//    output[1] = "probabilities"  float[batch][5]
//
//  Case B — onnxmltools / skl2onnx (nếu dùng):
//    n_outputs = 1
//    output[0] = "output"         float[batch][5]   (softmax)
//
//  → C++ tự xử lý cả 2 case
// =============================================================================
struct OnnxAutoencoder::Impl {
    Ort::Session                     session;
    Ort::AllocatorWithDefaultOptions allocator;

    std::string input_name;
    std::string output_label_name;   // output[0]
    std::string output_prob_name;    // output[1] (nếu có)

    bool has_label_output = false;   // true = Case A, false = Case B
    int  n_outputs        = 0;

    std::array<int64_t, 2> input_shape {
        1, static_cast<int64_t>(FeatureVector::SIZE)
    };

    explicit Impl(const std::string& path)
        : session(getOrtEnv(), path.c_str(), makeSessionOptions())
    {
        input_name = session.GetInputNameAllocated(0, allocator).get();
        n_outputs  = static_cast<int>(session.GetOutputCount());

        output_label_name = session.GetOutputNameAllocated(0, allocator).get();

        if (n_outputs >= 2) {
            output_prob_name  = session.GetOutputNameAllocated(1, allocator).get();
            // Kiểm tra output[0] có phải int64 không (label)
            auto type_info = session.GetOutputTypeInfo(0);
            auto elem_type = type_info.GetTensorTypeAndShapeInfo()
                                      .GetElementType();
            // ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64 = 7
            has_label_output = (elem_type == 7);
        } else {
            output_prob_name  = output_label_name;
            has_label_output  = false;
        }

        // Log shape của prob output
        int prob_idx = has_label_output ? 1 : 0;
        auto shape   = session.GetOutputTypeInfo(prob_idx)
                              .GetTensorTypeAndShapeInfo().GetShape();
        std::string shape_str = "[";
        for (size_t i = 0; i < shape.size(); ++i) {
            if (i) shape_str += ",";
            shape_str += std::to_string(shape[i]);
        }
        shape_str += "]";

        if (shape.size() >= 2 && shape[1] != MODEL_NUM_CLASSES) {
            LOG_WARN("OnnxAutoencoder: prob output shape " + shape_str
                     + " expected [?,5]");
        }

        LOG_INFO("OnnxAutoencoder loaded: " + path
                 + "\n  input=" + input_name
                 + " n_outputs=" + std::to_string(n_outputs)
                 + " has_label=" + (has_label_output ? "yes" : "no")
                 + " prob_shape=" + shape_str
                 + "\n  output[0]=" + output_label_name
                 + (n_outputs >= 2 ? " output[1]=" + output_prob_name : ""));
    }
};

OnnxAutoencoder::OnnxAutoencoder(float t) : threshold_(t) {}
OnnxAutoencoder::~OnnxAutoencoder() = default;

bool OnnxAutoencoder::load(const std::string& path) {
    try {
        impl_  = std::make_unique<Impl>(path);
        ready_ = true;
        return true;
    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxAutoencoder::load ORT: " + std::string(e.what()));
    } catch (const std::exception& e) {
        LOG_ERROR("OnnxAutoencoder::load: " + std::string(e.what()));
    }
    return false;
}

ModelOutput OnnxAutoencoder::infer(
    const std::array<float, FeatureVector::SIZE>& input)
{
    ModelOutput out;
    out.detail = "AEClassifier: ";
    if (!ready_) { out.detail += "not loaded"; return out; }

    try {
        auto mem_info = Ort::MemoryInfo::CreateCpu(
            OrtArenaAllocator, OrtMemTypeDefault);
        std::array<float, FeatureVector::SIZE> buf = input;

        Ort::Value in_tensor = Ort::Value::CreateTensor<float>(
            mem_info, buf.data(), buf.size(),
            impl_->input_shape.data(), impl_->input_shape.size());

        int          label    = 0;
        float        p_benign = 0.f;
        const float* probs    = nullptr;
        std::vector<float> probs_buf; // buffer nếu cần copy

        if (impl_->has_label_output) {
            // Case A: output[0]=label(int64), output[1]=probs(float[1][5])
            const char* in_names[]  = { impl_->input_name.c_str()        };
            const char* out_names[] = { impl_->output_label_name.c_str(),
                                        impl_->output_prob_name.c_str()   };

            auto outputs = impl_->session.Run(
                Ort::RunOptions{nullptr},
                in_names, &in_tensor, 1,
                out_names, 2);

            label    = static_cast<int>(outputs[0].GetTensorData<int64_t>()[0]);
            probs    = outputs[1].GetTensorData<float>();
            p_benign = probs[MODEL_LABEL_BENIGN];

        } else {
            // Case B: output[0]=probs(float[1][5])
            const char* in_names[]  = { impl_->input_name.c_str()        };
            const char* out_names[] = { impl_->output_prob_name.c_str()  };

            auto outputs = impl_->session.Run(
                Ort::RunOptions{nullptr},
                in_names, &in_tensor, 1,
                out_names, 1);

            probs    = outputs[0].GetTensorData<float>();
            label    = argmax5(probs);
            p_benign = probs[MODEL_LABEL_BENIGN];
        }

        out.label      = label;
        out.score      = 1.f - p_benign;
        out.is_anomaly = (label != MODEL_LABEL_BENIGN)
                      && (out.score >= threshold_);

        // Detail với full prob vector
        std::ostringstream oss;
        oss << modelLabelToStr(label)
            << " score=" << std::fixed << std::setprecision(3) << out.score
            << " probs=[";
        if (probs) {
            for (int i = 0; i < MODEL_NUM_CLASSES; ++i) {
                if (i) oss << ",";
                oss << std::setprecision(3) << probs[i];
            }
        }
        oss << "]";
        out.detail += oss.str();

    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxAutoencoder::infer: " + std::string(e.what()));
        out.detail += "ORT error: " + std::string(e.what());
    }
    return out;
}

#endif // USE_ONNX
