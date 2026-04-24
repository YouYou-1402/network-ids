// =============================================================================
//  src/ml/ml_engine.cpp
//
//  Thay đổi so với phiên bản cũ:
//    [FIX-1] nslkdd_meta_path   → ae_meta_path      (khớp MLConfig)
//            nslkdd_scaler_path → scaler_nslkdd_path (khớp MLConfig)
//            (3 chỗ: start(), backward-compat start(), reloadModels())
//
//    [FIX-2] combineVoting() — ae_confident + ae_norm logic:
//            ae_confident = ae_out.is_anomaly
//                           (OnnxAutoencoder set khi MSE >= ae_threshold)
//            ae_norm = clamp(ae_out.score / (ae_threshold * 3.0f), 0, 1)
//                      → ae_threshold*3 = "rất chắc là attack"
//                      → ae_high_threshold (0.85) giữ lại cho VOTE:HIGH boost
//
//    [FIX-3] Cooldown cleanup: xóa entry > 60s (không phải cooldown_sec * 2)
//            Tránh map tích lũy khi alert_cooldown_sec nhỏ (1s)
// =============================================================================

#include "ml_engine.hpp"
#include "onnx_model.hpp"
#include "../common/logger.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <unordered_map>
#include <chrono>

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
//  start(MLConfig)
// =============================================================================

void MLEngine::start(const MLConfig& cfg) {
    if (running_) return;
    cfg_ = cfg;

    // ── Load NslKddExtractor ──────────────────────────────────────────────────
    //
    // Thứ tự load: meta trước, scaler sau.
    //   meta   chứa ae_threshold (override cfg_.ae_threshold nếu > 0)
    //   scaler chứa mean/std binary (23 mean + 23 std = 184 bytes)
    //
    // [FIX-1] Dùng ae_meta_path + scaler_nslkdd_path (khớp MLConfig)
    bool extractor_ok = false;
    if (!cfg_.scaler_nslkdd_path.empty()) {
        // meta là optional — loadMeta() fallback về hardcode nếu file không có
        nslkdd_extractor_.loadMeta(cfg_.ae_meta_path);

        if (nslkdd_extractor_.loadScaler(cfg_.scaler_nslkdd_path)) {
            extractor_ok = true;
            LOG_INFO("MLEngine: NslKddExtractor ready"
                     " input_dim=" + std::to_string(nslkdd_extractor_.inputDim())
                     + " threshold=" + std::to_string(nslkdd_extractor_.threshold()));
        } else {
            LOG_ERROR("MLEngine: NslKddExtractor scaler FAILED — "
                      + cfg_.scaler_nslkdd_path);
        }
    } else {
        LOG_WARN("MLEngine: scaler_nslkdd_path rỗng"
                 " — NslKddExtractor không sẵn sàng, ML inference sẽ không chạy");
    }

    // ── Load XGBoost ──────────────────────────────────────────────────────────
    xgb_model_ = std::make_unique<OnnxXGBoost>(cfg_.xgb_threshold);
    if (!cfg_.xgb_model_path.empty()) {
        if (xgb_model_->load(cfg_.xgb_model_path))
            LOG_INFO("MLEngine: XGBoost loaded"
                     " input_dim=" + std::to_string(xgb_model_->inputDim()));
        else
            LOG_ERROR("MLEngine: XGBoost FAILED — " + cfg_.xgb_model_path);
    }

    // ── Load Autoencoder ──────────────────────────────────────────────────────
    //
    // ae_threshold ưu tiên theo thứ tự:
    //   1. cfg_.ae_threshold > 0  → dùng config (đã parse từ config.json)
    //   2. nslkdd_extractor_.threshold() → từ ae_meta.json
    //   3. Fallback hardcode 0.099726f (trong NslKddExtractor)
    float ae_thresh = cfg_.ae_threshold;
    if (ae_thresh <= 0.f && extractor_ok)
        ae_thresh = nslkdd_extractor_.threshold();
    if (ae_thresh <= 0.f)
        ae_thresh = 0.099726f;

    ae_model_ = std::make_unique<OnnxAutoencoder>(ae_thresh);
    if (!cfg_.ae_model_path.empty()) {
        if (ae_model_->load(cfg_.ae_model_path))
            LOG_INFO("MLEngine: Autoencoder loaded"
                     " input_dim=" + std::to_string(ae_model_->inputDim())
                     + " threshold=" + std::to_string(ae_thresh));
        else
            LOG_ERROR("MLEngine: Autoencoder FAILED — " + cfg_.ae_model_path);
    }

    // ── Validate input_dim nhất quán ─────────────────────────────────────────
    //
    // Cả XGBoost và Autoencoder đều nhận vector<float>(39) từ NslKddExtractor
    // → input_dim phải bằng nhau và bằng NSLKDD_TOTAL_DIM (39)
    if (extractor_ok && ae_model_->isReady()) {
        if (nslkdd_extractor_.inputDim() != ae_model_->inputDim()) {
            LOG_WARN("MLEngine: input_dim mismatch!"
                     " extractor=" + std::to_string(nslkdd_extractor_.inputDim())
                     + " ae_model=" + std::to_string(ae_model_->inputDim()));
        }
    }
    if (extractor_ok && xgb_model_->isReady()) {
        if (nslkdd_extractor_.inputDim() != xgb_model_->inputDim()) {
            LOG_WARN("MLEngine: input_dim mismatch!"
                     " extractor=" + std::to_string(nslkdd_extractor_.inputDim())
                     + " xgb_model=" + std::to_string(xgb_model_->inputDim()));
        }
    }

    LOG_INFO(status());
    running_ = true;
    thread_  = std::thread(&MLEngine::run, this);
}

// ── Backward compat ───────────────────────────────────────────────────────────
// [FIX-1] Dùng ae_meta_path + scaler_nslkdd_path
void MLEngine::start(bool               use_mock,
                     const std::string& xgb_path,
                     const std::string& ae_path,
                     const std::string& meta_path,
                     const std::string& scaler_path)
{
    MLConfig cfg;
    cfg.xgb_model_path    = xgb_path;
    cfg.ae_model_path     = ae_path;
    cfg.ae_meta_path      = meta_path;      // [FIX-1]
    cfg.scaler_nslkdd_path = scaler_path;   // [FIX-1]
    (void)use_mock;
    start(cfg);
}

// =============================================================================
//  stop
// =============================================================================

void MLEngine::stop() {
    if (!running_) return;
    running_ = false;
    if (thread_.joinable())
        thread_.join();
    LOG_INFO("MLEngine stopped."
             " jobs="       + std::to_string(jobs_processed_)
             + " anomalies=" + std::to_string(anomalies_found_));
}

// =============================================================================
//  reloadModels
// =============================================================================

bool MLEngine::reloadModels(const MLConfig& cfg) {
    // ── Load extractor mới ────────────────────────────────────────────────────
    // [FIX-1] Dùng ae_meta_path + scaler_nslkdd_path
    NslKddExtractor new_extractor;
    if (!cfg.scaler_nslkdd_path.empty()) {
        new_extractor.loadMeta(cfg.ae_meta_path);   // [FIX-1] optional
        if (!new_extractor.loadScaler(cfg.scaler_nslkdd_path)) {
            LOG_ERROR("MLEngine::reloadModels: NslKddExtractor scaler failed — "
                      + cfg.scaler_nslkdd_path);
            return false;
        }
    }

    // ── Load models mới ───────────────────────────────────────────────────────
    float ae_thresh = cfg.ae_threshold;
    if (ae_thresh <= 0.f && new_extractor.isReady())
        ae_thresh = new_extractor.threshold();
    if (ae_thresh <= 0.f)
        ae_thresh = 0.099726f;

    auto new_xgb = std::make_unique<OnnxXGBoost>    (cfg.xgb_threshold);
    auto new_ae  = std::make_unique<OnnxAutoencoder> (ae_thresh);

    bool xgb_ok = !cfg.xgb_model_path.empty() && new_xgb->load(cfg.xgb_model_path);
    bool ae_ok  = !cfg.ae_model_path.empty()  && new_ae ->load(cfg.ae_model_path);

    if (!xgb_ok && !ae_ok) {
        LOG_ERROR("MLEngine::reloadModels: both models failed to load");
        return false;
    }

    // ── Swap atomically ───────────────────────────────────────────────────────
    nslkdd_extractor_ = std::move(new_extractor);
    xgb_model_        = std::move(new_xgb);
    ae_model_         = std::move(new_ae);
    cfg_              = cfg;

    LOG_INFO("MLEngine: models reloaded.\n" + status());
    return true;
}

// =============================================================================
//  run — worker loop
// =============================================================================

void MLEngine::run() {
    LOG_INFO("MLEngine worker thread started");

    using Clock     = std::chrono::steady_clock;
    using TimePoint = std::chrono::time_point<Clock>;

    std::unordered_map<std::string, TimePoint> alert_cooldown_map;
    auto last_cleanup = Clock::now();

    while (running_) {
        std::optional<MLJob> opt = job_queue_.pop(200);
        if (!opt.has_value()) continue;

        MLResult result = processJob(*opt);
        ++jobs_processed_;

        if (result.final_result == DetectionResult::NORMAL) continue;
        if (result.confidence   <  cfg_.min_confidence)     continue;

        ++anomalies_found_;
        if (!on_ml_alert_) continue;

        // ── Cooldown per flow_key ─────────────────────────────────────────────
        const auto now = Clock::now();
        auto it = alert_cooldown_map.find(result.flow_key);
        if (it != alert_cooldown_map.end()) {
            const double elapsed =
                std::chrono::duration<double>(now - it->second).count();
            if (elapsed < static_cast<double>(cfg_.alert_cooldown_sec))
                continue;
            it->second = now;
        } else {
            alert_cooldown_map[result.flow_key] = now;
        }

        on_ml_alert_(result);

        // ── Cleanup cooldown map mỗi 60s ─────────────────────────────────────
        // [FIX-3] Xóa entry > 60s (không phải cooldown_sec * 2)
        //   Lý do: alert_cooldown_sec = 1s → cooldown_sec*2 = 2s
        //          cleanup chạy mỗi 60s → map tích lũy 58s entry cũ
        //   Fix: xóa tất cả entry có age > 60s
        if (std::chrono::duration<double>(now - last_cleanup).count() > 60.0) {
            for (auto it2 = alert_cooldown_map.begin();
                 it2 != alert_cooldown_map.end(); )
            {
                const double age =
                    std::chrono::duration<double>(now - it2->second).count();
                it2 = (age > 60.0)
                    ? alert_cooldown_map.erase(it2)
                    : std::next(it2);
            }
            last_cleanup = now;
        }
    }

    LOG_INFO("MLEngine worker thread exited");
}

// =============================================================================
//  TLS helpers
// =============================================================================

static constexpr std::array<uint16_t, 6> TLS_PORTS = {
    443, 8443, 9443, 465, 993, 995
};

static bool isTlsPort(uint16_t port) {
    for (auto p : TLS_PORTS) if (p == port) return true;
    return false;
}

// =============================================================================
//  processJob
//
//  Pipeline:
//    1. NslKddExtractor::extractAndScale(flow_snapshot) → vector<float>(39)
//    2. XGBoost::infer(vec39)    → label + score (probability)
//    3. Autoencoder::infer(vec39) → label + score (MSE)
//    4. TLS AE suppression (TLS port && XGB=BENIGN → reset AE)
//    5. combineVoting()
//    6. TLS PORT_SCAN suppression (output)
// =============================================================================

MLResult MLEngine::processJob(const MLJob& job) {
    MLResult result;
    result.flow_key  = job.flow_key;
    result.src_ip    = job.src_ip;
    result.dst_ip    = job.dst_ip;
    result.src_port  = job.src_port;
    result.dst_port  = job.dst_port;
    result.timestamp = job.timestamp;

    // ── Guard: extractor chưa sẵn sàng ───────────────────────────────────────
    if (!nslkdd_extractor_.isReady()) {
        result.detail = "NslKddExtractor not ready";
        return result;
    }

    // ── 1. Extract + Scale → vector<float>(39) ────────────────────────────────
    const std::vector<float> vec39 =
        nslkdd_extractor_.extractAndScale(job.flow_snapshot);

    // ── 2. XGBoost inference ──────────────────────────────────────────────────
    if (xgb_model_ && xgb_model_->isReady())
        result.xgb_result = xgb_model_->infer(vec39);

    // ── 3. Autoencoder inference ──────────────────────────────────────────────
    if (ae_model_ && ae_model_->isReady())
        result.ae_result = ae_model_->infer(vec39);

    // ── 4. TLS AE suppression ─────────────────────────────────────────────────
    //
    // Điều kiện: TLS port VÀ XGB=BENIGN
    //   NSL-KDD AE train trên plaintext features
    //   TLS traffic: payload encrypted → src_bytes/dst_bytes pattern khác
    //   → AE có thể cho MSE cao không phải vì attack mà vì TLS overhead
    //   Khi XGB đã nói BENIGN → tin XGB, reset AE về BENIGN
    const bool is_tls = isTlsPort(job.dst_port) || isTlsPort(job.src_port);
    if (is_tls && result.xgb_result.label == MODEL_LABEL_BENIGN) {
        result.ae_result = ModelOutput{};
        LOG_DEBUG("MLEngine: TLS+XGB=BENIGN → AE suppressed ["
                  + job.flow_key + "]");
    }

    // ── 5. Voting ─────────────────────────────────────────────────────────────
    const EngineOutput ev = combineVoting(result.xgb_result, result.ae_result);
    result.confidence   = ev.score;
    result.final_result = labelToThreat(ev.label);
    result.detail       = ev.detail;

    // ── 6. TLS PORT_SCAN suppression ──────────────────────────────────────────
    if (is_tls
        && result.final_result == DetectionResult::PORT_SCAN
        && result.confidence   <  0.90f)
    {
        LOG_DEBUG("MLEngine: TLS PORT_SCAN suppressed (conf="
                  + std::to_string(result.confidence) + ") ["
                  + job.flow_key + "]");
        result.final_result = DetectionResult::NORMAL;
        result.confidence   = 0.0f;
        result.detail      += " [Suppressed: TLS false positive]";
    }

    return result;
}

// =============================================================================
//  combineVoting
//
//  ── Scale problem ────────────────────────────────────────────────────────────
//
//  XGBoost score = 1 - P(BENIGN)   ∈ [0.0, 1.0]   (probability)
//  AE      score = MSE(input,recon) ∈ [0.0, ∞)     (reconstruction error)
//
//  Chuẩn hóa AE score → [0, 1]:
//    ae_norm = clamp(ae_score / (ae_threshold * 3.0f), 0.0, 1.0)
//
//    Lý do dùng ae_threshold * 3:
//      ae_threshold = 0.099726 = điểm "bắt đầu là attack" (P95 train MSE)
//      ae_threshold * 3 ≈ 0.30  = điểm "rất chắc là attack"
//      → ae_norm = 1.0 khi MSE = 3x threshold
//      → ae_norm = 0.33 khi MSE = threshold (vừa vượt ngưỡng)
//
//    Ví dụ:
//      ae_score = 0.05  → ae_norm = 0.05/0.30 = 0.17  (dưới ngưỡng)
//      ae_score = 0.10  → ae_norm = 0.10/0.30 = 0.33  (vừa attack)
//      ae_score = 0.20  → ae_norm = 0.20/0.30 = 0.67  (rõ attack)
//      ae_score = 0.30  → ae_norm = 0.30/0.30 = 1.00  (rất chắc)
//      ae_score = 0.50  → ae_norm = min(1.67, 1.0) = 1.0
//
//  [FIX-2] ae_confident = ae_out.is_anomaly
//    OnnxAutoencoder::infer() đã set is_anomaly = (MSE >= ae_threshold)
//    → Không cần so sánh lại với ae_high_threshold ở đây
//    → ae_high_threshold (0.85) chỉ dùng làm fallback nếu ae_threshold = 0
//
//  ── Bảng voting ──────────────────────────────────────────────────────────────
//
//    XGB=Attack | AE=Attack | VOTE:HIGH  score = xgb_w*xgb_score + ae_w*ae_norm
//    XGB=Attack | AE=Normal | VOTE:MED   score = xgb_score * 0.80
//    XGB=Normal | AE=Attack | VOTE:LOW   score = ae_norm   * 0.60
//    XGB=Normal | AE=Normal | VOTE:NORM  score = 0.0
// =============================================================================

EngineOutput MLEngine::combineVoting(const ModelOutput& xgb_out,
                                     const ModelOutput& ae_out) const
{
    EngineOutput ev;

    const bool xgb_ready = xgb_model_ && xgb_model_->isReady();
    const bool ae_ready  = ae_model_  && ae_model_->isReady();

    // ── No model ready ────────────────────────────────────────────────────────
    if (!xgb_ready && !ae_ready) {
        ev.label  = MODEL_LABEL_BENIGN;
        ev.score  = 0.f;
        ev.detail = "No model ready";
        return ev;
    }

    // ── Chuẩn hóa AE score → [0, 1] ──────────────────────────────────────────
    // [FIX-2] Dùng ae_threshold * 3 làm điểm "rất chắc" thay vì ae_high_threshold
    //   ae_threshold = cfg_.ae_threshold (từ config.json = 0.099726)
    //   Nếu ae_threshold = 0 (chưa set) → fallback ae_high_threshold
    const float ae_ref = (cfg_.ae_threshold > 0.f)
                       ? cfg_.ae_threshold * 3.0f
                       : cfg_.ae_high_threshold;

    const float ae_norm = (ae_ref > 0.f)
        ? std::min(ae_out.score / ae_ref, 1.0f)
        : 0.f;

    // [FIX-2] ae_confident = OnnxAutoencoder đã set is_anomaly
    //   is_anomaly = (MSE >= ae_threshold) — tính trong OnnxAutoencoder::infer()
    const bool ae_confident = ae_out.is_anomaly;

    // ── XGB only ──────────────────────────────────────────────────────────────
    if (xgb_ready && !ae_ready) {
        ev.is_anomaly = xgb_out.is_anomaly;
        ev.label      = xgb_out.label;
        ev.score      = xgb_out.score;
        ev.detail     = "[XGB only] " + xgb_out.detail;
        return ev;
    }

    // ── AE only ───────────────────────────────────────────────────────────────
    if (!xgb_ready && ae_ready) {
        ev.is_anomaly = ae_confident;
        ev.label      = ae_confident ? MODEL_LABEL_OTHER_ATTACK
                                     : MODEL_LABEL_BENIGN;
        ev.score      = ae_confident ? ae_norm * 0.60f : 0.f;
        ev.detail     = "[AE only] " + ae_out.detail;
        return ev;
    }

    // ── Cả 2 model ready ─────────────────────────────────────────────────────
    const bool xgb_attack = (xgb_out.label != MODEL_LABEL_BENIGN);

    std::ostringstream oss;

    if (xgb_attack && ae_confident) {
        // ── VOTE:HIGH — cả 2 đồng thuận ──────────────────────────────────────
        // label = XGB (multiclass, biết loại cụ thể)
        // score = weighted sum, cả 2 đã ở [0,1]
        ev.label      = xgb_out.label;
        ev.score      = cfg_.xgb_weight * xgb_out.score
                      + cfg_.ae_weight  * ae_norm;
        ev.is_anomaly = true;
        oss << "[VOTE:HIGH] ";

    } else if (xgb_attack && !ae_confident) {
        // ── VOTE:MED — chỉ XGBoost detect ────────────────────────────────────
        // AE không confirm → giảm confidence 20%
        ev.label      = xgb_out.label;
        ev.score      = xgb_out.score * 0.80f;
        ev.is_anomaly = (ev.score >= cfg_.xgb_threshold);
        oss << "[VOTE:MED] ";

    } else if (!xgb_attack && ae_confident) {
        // ── VOTE:LOW — chỉ AE detect ─────────────────────────────────────────
        // XGB nói BENIGN nhưng AE thấy bất thường
        // → OTHER_ATTACK (AE không biết loại cụ thể)
        // → confidence thấp (0.60x) vì XGB không confirm
        ev.label      = MODEL_LABEL_OTHER_ATTACK;
        ev.score      = ae_norm * 0.60f;
        ev.is_anomaly = true;
        oss << "[VOTE:LOW] ";

    } else {
        // ── VOTE:NORM — cả 2 BENIGN ───────────────────────────────────────────
        ev.label      = MODEL_LABEL_BENIGN;
        ev.score      = 0.f;
        ev.is_anomaly = false;
        oss << "[VOTE:NORM] ";
    }

    oss << modelLabelToStr(ev.label)
        << " score="   << std::fixed << std::setprecision(4) << ev.score
        << " | XGB: "  << xgb_out.detail
        << " | AE: "   << ae_out.detail
        << " ae_norm=" << std::setprecision(4) << ae_norm;
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
        << "\n  XGBoost        : "
        << (xgb_model_ && xgb_model_->isReady()
            ? "READY (input_dim=" + std::to_string(xgb_model_->inputDim()) + ")"
            : "NOT LOADED")
        << "\n  Autoencoder    : "
        << (ae_model_ && ae_model_->isReady()
            ? "READY (input_dim=" + std::to_string(ae_model_->inputDim())
              + " threshold=" + std::to_string(ae_model_->threshold()) + ")"
            : "NOT LOADED")
        << "\n  NslKddExtractor: "
        << (nslkdd_extractor_.isReady()
            ? "READY (input_dim=" + std::to_string(nslkdd_extractor_.inputDim())
              + " threshold=" + std::to_string(nslkdd_extractor_.threshold()) + ")"
            : "NOT READY")
        << "\n  Weights        : xgb=" << cfg_.xgb_weight
        << " ae=" << cfg_.ae_weight
        << "\n  Thresholds     : xgb=" << cfg_.xgb_threshold
        << " ae=" << cfg_.ae_threshold
        << " ae_ref=" << (cfg_.ae_threshold * 3.0f)
        << "\n  Min confidence : " << cfg_.min_confidence
        << "\n  Alert cooldown : " << cfg_.alert_cooldown_sec << "s";
    return oss.str();
}
