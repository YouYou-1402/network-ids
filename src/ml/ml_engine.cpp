#include "ml_engine.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"
#include "../common/engine_config.hpp"
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

// Label constants — phải khớp với training script
// 0 = BENIGN, 1 = DDoS Volumetric, 2 = Slow DDoS, 3 = Port Scan
static constexpr int XGB_LABEL_NORMAL    = 0;
static constexpr int XGB_LABEL_DDOS      = 1;
static constexpr int XGB_LABEL_SLOW_DDOS = 2;
static constexpr int XGB_LABEL_SCAN      = 3;

static std::string ipToStr(uint32_t ip) {
    struct in_addr a; a.s_addr = ip;
    return inet_ntoa(a);
}

// =============================================================================
//  MLEngine
// =============================================================================

MLEngine::MLEngine(MLJobQueue& job_queue, MLAlertCallback on_ml_alert)
    : job_queue_   (job_queue)
    , on_ml_alert_ (std::move(on_ml_alert))
{}

MLEngine::~MLEngine() { stop(); }

// --- start (full config) -----------------------------------------------------
void MLEngine::start(const MLConfig& cfg) {
    cfg_ = cfg;

    // Load scaler
    if (!cfg_.scaler_path.empty()) {
        if (!extractor_.loadScaler(cfg_.scaler_path))
            LOG_WARN("MLEngine: scaler load failed — features will NOT be scaled");
    } else {
        LOG_WARN("MLEngine: no scaler_path — features will NOT be scaled");
    }

    // Load XGBoost
    xgb_model_ = std::make_unique<OnnxXGBoost>(cfg_.xgb_threshold);
    if (!cfg_.xgb_model_path.empty()) {
        if (!xgb_model_->load(cfg_.xgb_model_path)) {
            LOG_ERROR("MLEngine: XGBoost load FAILED: " + cfg_.xgb_model_path);
            xgb_model_.reset();
        }
    } else {
        LOG_WARN("MLEngine: no xgb_model_path — XGBoost disabled");
        xgb_model_.reset();
    }

    // Load Autoencoder
    ae_model_ = std::make_unique<OnnxAutoencoder>(cfg_.ae_threshold);
    if (!cfg_.ae_model_path.empty()) {
        if (!ae_model_->load(cfg_.ae_model_path)) {
            LOG_ERROR("MLEngine: Autoencoder load FAILED: " + cfg_.ae_model_path);
            ae_model_.reset();
        }
    } else {
        LOG_WARN("MLEngine: no ae_model_path — Autoencoder disabled");
        ae_model_.reset();
    }

    if (!xgb_model_ && !ae_model_)
        LOG_ERROR("MLEngine: BOTH models failed — ML Layer 2 DISABLED");

    running_ = true;
    thread_  = std::thread(&MLEngine::run, this);

    LOG_INFO("MLEngine started:"
             " XGBoost="  + std::string(xgb_model_ ? "OK" : "DISABLED")
             + " AE="     + std::string(ae_model_  ? "OK" : "DISABLED")
             + " scaler=" + std::string(extractor_.scalerLoaded() ? "OK" : "DISABLED")
             + " xgb_w="  + std::to_string(cfg_.xgb_weight)
             + " ae_w="   + std::to_string(cfg_.ae_weight)
             + " min_conf=" + std::to_string(cfg_.min_confidence));
}

// --- start (backward compat) -------------------------------------------------
void MLEngine::start(bool               use_mock,
                     const std::string& xgb_path,
                     const std::string& ae_path,
                     const std::string& scaler_path)
{
    if (use_mock) {
        LOG_WARN("MLEngine: use_mock=true — running WITHOUT models");
        running_ = true;
        thread_  = std::thread(&MLEngine::run, this);
        return;
    }
    MLConfig cfg;
    cfg.xgb_model_path = xgb_path;
    cfg.ae_model_path  = ae_path;
    cfg.scaler_path    = scaler_path;
    start(cfg);
}

// --- stop --------------------------------------------------------------------
void MLEngine::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
    LOG_INFO("MLEngine stopped."
             " jobs="       + std::to_string(jobs_processed_)
             + " anomalies=" + std::to_string(anomalies_found_));
}

// --- reloadModels ------------------------------------------------------------
bool MLEngine::reloadModels(const MLConfig& cfg) {
    cfg_ = cfg;

    auto new_xgb = std::make_unique<OnnxXGBoost>(cfg_.xgb_threshold);
    auto new_ae  = std::make_unique<OnnxAutoencoder>(cfg_.ae_threshold);

    bool xgb_ok = !cfg_.xgb_model_path.empty()
               && new_xgb->load(cfg_.xgb_model_path);
    bool ae_ok  = !cfg_.ae_model_path.empty()
               && new_ae->load(cfg_.ae_model_path);

    // Swap sau khi load xong — run() chỉ đọc trong 1 thread → không cần lock
    if (xgb_ok) xgb_model_ = std::move(new_xgb);
    if (ae_ok)  ae_model_  = std::move(new_ae);

    extractor_.loadScaler(cfg_.scaler_path);

    LOG_INFO("MLEngine::reloadModels:"
             " XGBoost=" + std::string(xgb_ok ? "OK" : "FAIL")
             + " AE="    + std::string(ae_ok  ? "OK" : "FAIL"));
    return xgb_ok || ae_ok;
}

// --- run ---------------------------------------------------------------------
void MLEngine::run() {
    LOG_INFO("MLEngine inference loop running");
    while (running_) {
        auto job_opt = job_queue_.pop(200);
        if (!job_opt.has_value()) continue;

        if (!ENGINE_CFG.ml_enabled.load(std::memory_order_relaxed))
            continue;

        if (!xgb_model_ && !ae_model_) continue;

        const MLJob& job    = job_opt.value();
        MLResult     result = processJob(job);
        jobs_processed_.fetch_add(1, std::memory_order_relaxed);

        if (result.final_result != DetectionResult::NORMAL
            && result.confidence >= cfg_.min_confidence)
        {
            anomalies_found_.fetch_add(1, std::memory_order_relaxed);
            //METRICS.ml_anomalies.fetch_add(1, std::memory_order_relaxed);
            if (on_ml_alert_) on_ml_alert_(result);
        }
    }
}

// --- processJob --------------------------------------------------------------
MLResult MLEngine::processJob(const MLJob& job) {
    MLResult result;
    result.flow_key  = job.flow_key;
    result.src_ip    = job.src_ip;
    result.dst_ip    = job.dst_ip;
    result.src_port  = job.src_port;
    result.dst_port  = job.dst_port;
    result.timestamp = job.timestamp;

    // Normalize features bằng StandardScaler
    // job.features: FeatureVector đã được extract() trong WorkerThread
    const auto norm = extractor_.normalizeRaw(job.features);

    if (xgb_model_) result.xgb_result = xgb_model_->infer(norm);
    else            result.xgb_result.detail = "XGBoost: disabled";

    if (ae_model_)  result.ae_result  = ae_model_->infer(norm);
    else            result.ae_result.detail  = "Autoencoder: disabled";

    result.final_result = combineResults(
        result.xgb_result, result.ae_result, result.confidence);

    std::ostringstream oss;
    oss << "[L2] " << result.xgb_result.detail
        << " | "   << result.ae_result.detail
        << " | conf=" << std::fixed << std::setprecision(3) << result.confidence
        << " src="  << ipToStr(result.src_ip) << ":" << result.src_port;
    result.detail = oss.str();

    return result;
}

// --- combineResults ----------------------------------------------------------
DetectionResult MLEngine::combineResults(const ModelOutput& xgb_out,
                                          const ModelOutput& ae_out,
                                          float&             confidence) const
{
    const bool xgb_attack = xgb_out.is_anomaly;
    const bool ae_anomaly = ae_out.is_anomaly;

    if (!xgb_attack && !ae_anomaly) {
        confidence = std::max(0.f,
            1.f - (cfg_.xgb_weight * xgb_out.score
                 + cfg_.ae_weight  * ae_out.score));
        return DetectionResult::NORMAL;
    }

    if (xgb_attack && ae_anomaly) {
        confidence = std::min(1.f,
            cfg_.xgb_weight * xgb_out.score
          + cfg_.ae_weight  * ae_out.score);
        return xgbLabelToThreat(xgb_out.label);
    }

    if (xgb_attack) {
        confidence = xgb_out.score * 0.80f;
        return xgbLabelToThreat(xgb_out.label);
    }

    // Chỉ AE detect → có thể zero-day
    confidence = ae_out.score * 0.60f;
    return DetectionResult::UNKNOWN_ANOMALY;
}

// --- xgbLabelToThreat --------------------------------------------------------
DetectionResult MLEngine::xgbLabelToThreat(int label) {
    switch (label) {
        case XGB_LABEL_DDOS:      return DetectionResult::DDOS_VOLUMETRIC;
        case XGB_LABEL_SLOW_DDOS: return DetectionResult::SLOW_DDOS;
        case XGB_LABEL_SCAN:      return DetectionResult::PORT_SCAN;
        default:                  return DetectionResult::UNKNOWN_ANOMALY;
    }
}
