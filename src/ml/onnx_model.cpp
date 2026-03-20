#include "onnx_model.hpp"
#include "../common/logger.hpp"
#include <sstream>
#include <iomanip>
#include <stdexcept>

// =============================================================================
//  Include ONNX Runtime header
//
//  Hỗ trợ 3 layout phổ biến (tự động chọn đúng qua CMake):
//
//  Layout A — apt install libonnxruntime-dev (Debian/Ubuntu mới):
//    /usr/local/include/onnxruntime_cxx_api.h          ← máy này
//
//  Layout B — Microsoft tarball giải nén vào /usr/local:
//    /usr/local/include/onnxruntime/core/session/onnxruntime_cxx_api.h
//
//  Layout C — apt install onnxruntime-dev (repo Microsoft):
//    /usr/include/onnxruntime/core/session/onnxruntime_cxx_api.h
//
//  CMakeLists.txt sẽ định nghĩa đúng ONNX_INCLUDE_DIR
//  và truyền vào compiler qua -I flag.
//  File này chỉ cần #include tên file, không cần đường dẫn đầy đủ.
// =============================================================================
#ifdef USE_ONNX
#include <onnxruntime_cxx_api.h>
#endif

// =============================================================================
//  Nếu KHÔNG có ONNX Runtime → Mock implementation
//  Toàn bộ class vẫn compile và link bình thường
//  load() trả về false, infer() trả về score=0 / is_anomaly=false
// =============================================================================
#ifndef USE_ONNX

// ── OnnxXGBoost Mock ──────────────────────────────────────────────────────────
struct OnnxXGBoost::Impl {};

OnnxXGBoost::OnnxXGBoost(float threshold) : threshold_(threshold) {}
OnnxXGBoost::~OnnxXGBoost() = default;

bool OnnxXGBoost::load(const std::string& path) {
    LOG_WARN("OnnxXGBoost::load — built without USE_ONNX, model ignored: " + path);
    return false;
}

ModelOutput OnnxXGBoost::infer(
    const std::array<float, FeatureVector::SIZE>&)
{
    return { false, 0.f, 0, "XGBoost: USE_ONNX not enabled" };
}

// ── OnnxAutoencoder Mock ──────────────────────────────────────────────────────
struct OnnxAutoencoder::Impl {};

OnnxAutoencoder::OnnxAutoencoder(float mse_threshold)
    : mse_threshold_(mse_threshold) {}
OnnxAutoencoder::~OnnxAutoencoder() = default;

bool OnnxAutoencoder::load(const std::string& path) {
    LOG_WARN("OnnxAutoencoder::load — built without USE_ONNX, model ignored: " + path);
    return false;
}

ModelOutput OnnxAutoencoder::infer(
    const std::array<float, FeatureVector::SIZE>&)
{
    return { false, 0.f, 0, "Autoencoder: USE_ONNX not enabled" };
}

float OnnxAutoencoder::computeMSE(
    const std::array<float, FeatureVector::SIZE>&,
    const float*, size_t)
{
    return 0.f;
}

#else // USE_ONNX — Real implementation

// =============================================================================
//  ORT helpers — dùng chung cho cả 2 model
// =============================================================================
namespace {

// Global ORT environment — khởi tạo 1 lần, thread-safe
Ort::Env& getOrtEnv() {
    static Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "network-ids");
    return env;
}

Ort::SessionOptions makeSessionOptions() {
    Ort::SessionOptions opts;
    opts.SetIntraOpNumThreads(1);   // 1 thread/model — tránh tranh chấp CPU
    opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
    opts.SetExecutionMode(ExecutionMode::ORT_SEQUENTIAL);
    return opts;
}

} // namespace

// =============================================================================
//  OnnxXGBoost
// =============================================================================

struct OnnxXGBoost::Impl {
    Ort::Session                     session;
    Ort::AllocatorWithDefaultOptions allocator;

    std::string input_name;
    std::string output_label_name;
    std::string output_prob_name;

    // Input shape: [1, 21]
    std::array<int64_t, 2> input_shape {
        1, static_cast<int64_t>(FeatureVector::SIZE)
    };

    explicit Impl(const std::string& path)
        : session(getOrtEnv(), path.c_str(), makeSessionOptions())
    {
        // XGBoost ONNX thường có:
        //   input:  "X"
        //   output: "label", "probabilities"
        input_name        = session.GetInputNameAllocated (0, allocator).get();
        output_label_name = session.GetOutputNameAllocated(0, allocator).get();
        output_prob_name  = session.GetOutputNameAllocated(1, allocator).get();

        LOG_INFO("OnnxXGBoost loaded — input=" + input_name
                 + " label=" + output_label_name
                 + " prob="  + output_prob_name);
    }
};

OnnxXGBoost::OnnxXGBoost(float threshold) : threshold_(threshold) {}
OnnxXGBoost::~OnnxXGBoost() = default;

bool OnnxXGBoost::load(const std::string& path) {
    try {
        impl_  = std::make_unique<Impl>(path);
        ready_ = true;
        return true;
    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxXGBoost::load ORT: " + std::string(e.what()));
        return false;
    } catch (const std::exception& e) {
        LOG_ERROR("OnnxXGBoost::load: " + std::string(e.what()));
        return false;
    }
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

        // ORT API cần non-const pointer
        std::array<float, FeatureVector::SIZE> buf = input;

        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            mem_info,
            buf.data(), buf.size(),
            impl_->input_shape.data(), impl_->input_shape.size());

        const char* in_names[]  = { impl_->input_name.c_str()        };
        const char* out_names[] = { impl_->output_label_name.c_str(),
                                    impl_->output_prob_name.c_str()   };

        auto outputs = impl_->session.Run(
            Ort::RunOptions{nullptr},
            in_names,  &input_tensor, 1,
            out_names, 2);

        const int64_t label     = outputs[0].GetTensorData<int64_t>()[0];
        const float*  probs     = outputs[1].GetTensorData<float>();
        const float   prob_norm = probs[0];   // P(normal)

        out.label      = static_cast<int>(label);
        out.score      = 1.f - prob_norm;
        out.is_anomaly = (label != 0) && (out.score >= threshold_);

        static const char* CLASS_NAMES[] = {
            "Normal", "DDoS Volumetric", "Slow DDoS", "Port Scan"
        };
        const char* cls = (label >= 0 && label < 4)
            ? CLASS_NAMES[label] : "Unknown";

        std::ostringstream oss;
        oss << cls
            << " (score=" << std::fixed << std::setprecision(3) << out.score
            << " p_norm=" << prob_norm << ")";
        out.detail += oss.str();

    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxXGBoost::infer ORT: " + std::string(e.what()));
        out.detail += "ORT error";
    }
    return out;
}

// =============================================================================
//  OnnxAutoencoder
// =============================================================================

struct OnnxAutoencoder::Impl {
    Ort::Session                     session;
    Ort::AllocatorWithDefaultOptions allocator;

    std::string input_name;
    std::string output_name;

    std::array<int64_t, 2> input_shape {
        1, static_cast<int64_t>(FeatureVector::SIZE)
    };

    explicit Impl(const std::string& path)
        : session(getOrtEnv(), path.c_str(), makeSessionOptions())
    {
        input_name  = session.GetInputNameAllocated (0, allocator).get();
        output_name = session.GetOutputNameAllocated(0, allocator).get();
        LOG_INFO("OnnxAutoencoder loaded — input=" + input_name
                 + " output=" + output_name);
    }
};

OnnxAutoencoder::OnnxAutoencoder(float mse_threshold)
    : mse_threshold_(mse_threshold) {}
OnnxAutoencoder::~OnnxAutoencoder() = default;

bool OnnxAutoencoder::load(const std::string& path) {
    try {
        impl_  = std::make_unique<Impl>(path);
        ready_ = true;
        return true;
    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxAutoencoder::load ORT: " + std::string(e.what()));
        return false;
    } catch (const std::exception& e) {
        LOG_ERROR("OnnxAutoencoder::load: " + std::string(e.what()));
        return false;
    }
}

float OnnxAutoencoder::computeMSE(
    const std::array<float, FeatureVector::SIZE>& input,
    const float* recon, size_t size)
{
    float mse = 0.f;
    for (size_t i = 0; i < size; ++i) {
        const float d = input[i] - recon[i];
        mse += d * d;
    }
    return mse / static_cast<float>(size);
}

ModelOutput OnnxAutoencoder::infer(
    const std::array<float, FeatureVector::SIZE>& input)
{
    ModelOutput out;
    out.detail = "Autoencoder: ";
    if (!ready_) { out.detail += "not loaded"; return out; }

    try {
        auto mem_info = Ort::MemoryInfo::CreateCpu(
            OrtArenaAllocator, OrtMemTypeDefault);

        std::array<float, FeatureVector::SIZE> buf = input;

        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            mem_info,
            buf.data(), buf.size(),
            impl_->input_shape.data(), impl_->input_shape.size());

        const char* in_names[]  = { impl_->input_name.c_str()  };
        const char* out_names[] = { impl_->output_name.c_str() };

        auto outputs = impl_->session.Run(
            Ort::RunOptions{nullptr},
            in_names,  &input_tensor, 1,
            out_names, 1);

        const float* recon = outputs[0].GetTensorData<float>();
        const float  mse   = computeMSE(input, recon, FeatureVector::SIZE);

        out.score      = mse;
        out.is_anomaly = (mse > mse_threshold_);

        std::ostringstream oss;
        oss << (out.is_anomaly ? "ANOMALY" : "normal")
            << " (MSE=" << std::fixed << std::setprecision(5) << mse
            << " thr="  << mse_threshold_ << ")";
        out.detail += oss.str();

    } catch (const Ort::Exception& e) {
        LOG_ERROR("OnnxAutoencoder::infer ORT: " + std::string(e.what()));
        out.detail += "ORT error";
    }
    return out;
}

#endif // USE_ONNX
