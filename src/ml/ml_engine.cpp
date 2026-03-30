// =============================================================================
//  ml_engine.cpp
// =============================================================================

#include "ml_engine.hpp"
#include "onnx_model.hpp"
#include "../common/logger.hpp"
#include <sstream>
#include <iomanip>

// =============================================================================
//  Constructor / Destructor
// =============================================================================

MLEngine::MLEngine(MLJobQueue& job_queue, MLAlertCallback on_ml_alert)
    : job_queue_   (job_queue)
    , on_ml_alert_ (std::move(on_ml_alert))
    , xgb_model_   (nullptr)
    , ae_model_    (nullptr)
{}

MLEngine::~MLEngine() {
    stop();
}

// =============================================================================
//  start
// =============================================================================

void MLEngine::start(const MLConfig& cfg) {
    if (running_) return;
    cfg_ = cfg;

    if (!cfg_.scaler_path.empty()) {
        if (extractor_.loadScaler(cfg_.scaler_path))
            LOG_INFO("MLEngine: scaler loaded from " + cfg_.scaler_path);
        else
            LOG_WARN("MLEngine: scaler FAILED — AEClassifier sẽ cho kết quả sai");
    } else {
        LOG_WARN("MLEngine: scaler_path rỗng — dùng raw features");
    }

    xgb_model_ = std::make_unique<OnnxXGBoost>(cfg_.xgb_threshold);
    if (!cfg_.xgb_model_path.empty()) {
        if (xgb_model_->load(cfg_.xgb_model_path))
            LOG_INFO("MLEngine: XGBoost loaded");
        else
            LOG_ERROR("MLEngine: XGBoost FAILED — " + cfg_.xgb_model_path);
    }

    ae_model_ = std::make_unique<OnnxAutoencoder>(cfg_.ae_threshold);
    if (!cfg_.ae_model_path.empty()) {
        if (ae_model_->load(cfg_.ae_model_path))
            LOG_INFO("MLEngine: AEClassifier loaded");
        else
            LOG_ERROR("MLEngine: AEClassifier FAILED — " + cfg_.ae_model_path);
    }

    LOG_INFO(status());
    running_ = true;
    thread_  = std::thread(&MLEngine::run, this);
}


void MLEngine::start(bool               use_mock,
                     const std::string& xgb_path,
                     const std::string& ae_path,
                     const std::string& scaler_path)
{
    MLConfig cfg;
    cfg.xgb_model_path = xgb_path;
    cfg.ae_model_path  = ae_path;
    cfg.scaler_path    = scaler_path;
    (void)use_mock;
    start(cfg);
}

// =============================================================================
//  stop
//  ✅ RingBuffer KHÔNG có shutdown() → dùng running_=false + timeout pop
// =============================================================================

void MLEngine::stop() {
    if (!running_) return;
    running_ = false;
    // Không gọi shutdown() — RingBuffer::pop() tự timeout sau 200ms
    // → worker thread check running_=false và thoát
    if (thread_.joinable())
        thread_.join();
    LOG_INFO("MLEngine stopped. jobs=" + std::to_string(jobs_processed_)
             + " anomalies=" + std::to_string(anomalies_found_));
}

// =============================================================================
//  reloadModels — thread-safe swap
// =============================================================================

bool MLEngine::reloadModels(const MLConfig& cfg) {
    auto new_xgb = std::make_unique<OnnxXGBoost>(cfg.xgb_threshold);
    auto new_ae  = std::make_unique<OnnxAutoencoder>(cfg.ae_threshold);

    bool xgb_ok = !cfg.xgb_model_path.empty() && new_xgb->load(cfg.xgb_model_path);
    bool ae_ok  = !cfg.ae_model_path.empty()  && new_ae->load(cfg.ae_model_path);

    if (!xgb_ok && !ae_ok) {
        LOG_ERROR("MLEngine::reloadModels: both models failed to load");
        return false;
    }

    // Swap — worker thread đang dùng isReady()/infer() nhưng
    // unique_ptr swap là atomic trên x86; nếu cần strict safety thì dùng mutex
    xgb_model_ = std::move(new_xgb);
    ae_model_  = std::move(new_ae);
    cfg_       = cfg;

    if (!cfg_.scaler_path.empty())
        extractor_.loadScaler(cfg_.scaler_path);

    LOG_INFO("MLEngine: models reloaded.\n" + status());
    return true;
}

// =============================================================================
//  run — worker loop
//  ✅ RingBuffer::pop(timeout_ms) → std::optional<MLJob>
//     Không có shutdown() → check running_ sau mỗi timeout
// =============================================================================

void MLEngine::run() {
    LOG_INFO("MLEngine worker thread started");

    while (running_) {
        // pop() block tối đa 200ms rồi trả nullopt → kiểm tra running_
        std::optional<MLJob> opt = job_queue_.pop(200);

        if (!opt.has_value())
            continue;   // timeout → vòng lại check running_

        MLResult result = processJob(*opt);
        ++jobs_processed_;

        if (result.final_result != DetectionResult::NORMAL) {
            ++anomalies_found_;
            if (result.confidence >= cfg_.min_confidence && on_ml_alert_)
                on_ml_alert_(result);
        }
    }

    LOG_INFO("MLEngine worker thread exited");
}

// =============================================================================
//  processJob
//  ✅ job.features là FeatureVector → dùng extractor_.normalizeRaw()
//     rồi mới truyền std::array<float, SIZE> vào infer()
// =============================================================================

MLResult MLEngine::processJob(const MLJob& job) {
    MLResult result;
    result.flow_key  = job.flow_key;
    result.src_ip    = job.src_ip;
    result.dst_ip    = job.dst_ip;
    result.src_port  = job.src_port;
    result.dst_port  = job.dst_port;
    result.timestamp = job.timestamp;

    // FeatureVector → std::array<float, SIZE> (normalize nếu scaler loaded)
    const std::array<float, FeatureVector::SIZE> features =
        extractor_.scalerLoaded()
            ? extractor_.normalizeRaw(job.features)   // z-score normalize
            : job.features.toArray();                  // raw fallback

    // Run XGBoost
    if (xgb_model_ && xgb_model_->isReady())
        result.xgb_result = xgb_model_->infer(features);

    // Run AEClassifier
    if (ae_model_ && ae_model_->isReady())
        result.ae_result = ae_model_->infer(features);

    // Voting
    EngineOutput ev   = combineVoting(result.xgb_result, result.ae_result);
    result.confidence = ev.score;
    result.final_result = labelToThreat(ev.label);
    result.detail     = ev.detail;

    return result;
}

// =============================================================================
//  combineVoting
//
//  XGBoost  | AE      | Confidence
//  ---------|---------|------------------------------------------
//  Attack   | Attack  | HIGH   = xgb_w*xgb_score + ae_w*ae_score
//  Attack   | Benign  | MEDIUM = xgb_score * 0.80
//  Benign   | Attack  | LOW    = ae_score  * 0.60
//  Benign   | Benign  | NORMAL = 0.0
// =============================================================================

EngineOutput MLEngine::combineVoting(const ModelOutput& xgb_out,
                                     const ModelOutput& ae_out) const
{
    EngineOutput ev;

    const bool xgb_ready = xgb_model_ && xgb_model_->isReady();
    const bool ae_ready  = ae_model_  && ae_model_->isReady();

    // ── Không model nào ready ─────────────────────────────────────────────
    if (!xgb_ready && !ae_ready) {
        ev.label  = MODEL_LABEL_BENIGN;
        ev.score  = 0.f;
        ev.detail = "No model ready";
        return ev;
    }

    // ── Chỉ 1 model ready ────────────────────────────────────────────────
    if (xgb_ready && !ae_ready) {
        ev.is_anomaly = xgb_out.is_anomaly;
        ev.label      = xgb_out.label;
        ev.score      = xgb_out.score;
        ev.detail     = "[XGB only] " + xgb_out.detail;
        return ev;
    }
    if (!xgb_ready && ae_ready) {
        ev.is_anomaly = ae_out.is_anomaly;
        ev.label      = ae_out.label;
        ev.score      = ae_out.score * 0.60f;   // AE alone → lower conf
        ev.detail     = "[AE only] " + ae_out.detail;
        return ev;
    }

    // ── Cả 2 ready → weighted voting ─────────────────────────────────────
    const bool xgb_attack = (xgb_out.label != MODEL_LABEL_BENIGN);
    const bool ae_attack  = (ae_out.label  != MODEL_LABEL_BENIGN);

    std::ostringstream oss;

    if (xgb_attack && ae_attack) {
        ev.label      = xgb_out.label;   // XGBoost label ưu tiên (supervised)
        ev.score      = cfg_.xgb_weight * xgb_out.score
                      + cfg_.ae_weight  * ae_out.score;
        ev.is_anomaly = true;
        oss << "[VOTE:HIGH] ";

    } else if (xgb_attack && !ae_attack) {
        ev.label      = xgb_out.label;
        ev.score      = xgb_out.score * 0.80f;
        ev.is_anomaly = (ev.score >= cfg_.xgb_threshold);
        oss << "[VOTE:MED] ";

    } else if (!xgb_attack && ae_attack) {
        ev.label      = ae_out.label;
        ev.score      = ae_out.score * 0.60f;
        ev.is_anomaly = (ev.score >= cfg_.ae_threshold);
        oss << "[VOTE:LOW] ";

    } else {
        ev.label      = MODEL_LABEL_BENIGN;
        ev.score      = 0.f;
        ev.is_anomaly = false;
        oss << "[VOTE:NORM] ";
    }

    oss << modelLabelToStr(ev.label)
        << " score=" << std::fixed << std::setprecision(3) << ev.score
        << " | XGB: " << xgb_out.detail
        << " | AE: "  << ae_out.detail;
    ev.detail = oss.str();

    return ev;
}

// =============================================================================
//  labelToThreat
// =============================================================================

DetectionResult MLEngine::labelToThreat(int label) {
    switch (label) {
        case MODEL_LABEL_BENIGN:          return DetectionResult::NORMAL;
        case MODEL_LABEL_DDOS_VOLUMETRIC: return DetectionResult::DDOS_VOLUMETRIC;
        case MODEL_LABEL_SLOW_DDOS:       return DetectionResult::SLOW_DDOS;
        case MODEL_LABEL_PORT_SCAN:       return DetectionResult::PORT_SCAN;
        case MODEL_LABEL_OTHER_ATTACK:    return DetectionResult::OTHER_ATTACK;
        default:                          return DetectionResult::UNKNOWN_ANOMALY;
    }
}

// =============================================================================
//  status
// =============================================================================

std::string MLEngine::status() const {
    std::ostringstream oss;
    oss << "MLEngine:"
        << "\n  XGBoost      : "
        << (xgb_model_ && xgb_model_->isReady() ? "READY" : "NOT LOADED")
        << "\n  AEClassifier : "
        << (ae_model_  && ae_model_->isReady()  ? "READY" : "NOT LOADED")
        << "\n  Scaler       : "
        << (extractor_.scalerLoaded() ? "LOADED" : "NOT LOADED (using raw features)")
        << "\n  Weights      : xgb=" << cfg_.xgb_weight
        << " ae=" << cfg_.ae_weight
        << "\n  Thresholds   : xgb=" << cfg_.xgb_threshold
        << " ae=" << cfg_.ae_threshold
        << "\n  Min conf     : " << cfg_.min_confidence;
    return oss.str();
}
