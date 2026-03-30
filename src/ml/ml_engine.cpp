// =============================================================================
//  src/ml/ml_engine.cpp
//
//  Fix so với phiên bản cũ:
//    [FIX-1] run(): VOTE:LOW chỉ alert khi score >= min_confidence
//            (không dùng ae_threshold=0.10 làm ngưỡng alert nữa)
//    [FIX-2] combineVoting(): khi XGB=BENIGN + AE=Attack,
//            yêu cầu ae_score >= ae_high_threshold (0.85) mới là anomaly
//    [FIX-3] processJob(): TLS suppression — dst_port 443 + XGB=BENIGN
//            → reset AE result về BENIGN (AE không reliable với encrypted)
//    [FIX-4] run(): alert_cooldown_map — dedup per flow_key / 10 giây
// =============================================================================

#include "ml_engine.hpp"
#include "onnx_model.hpp"
#include "../common/logger.hpp"
#include <sstream>
#include <iomanip>
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
// =============================================================================

void MLEngine::stop() {
    if (!running_) return;
    running_ = false;
    if (thread_.joinable())
        thread_.join();
    LOG_INFO("MLEngine stopped. jobs=" + std::to_string(jobs_processed_)
             + " anomalies=" + std::to_string(anomalies_found_));
}

// =============================================================================
//  reloadModels
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
//
//  [FIX-1] Dùng min_confidence làm ngưỡng alert thống nhất.
//          Trước đây VOTE:LOW dùng ae_threshold=0.10 → 0.577 > 0.10 → alert.
//          Nay: 0.577 < min_confidence=0.60 → KHÔNG alert.
//
//  [FIX-4] alert_cooldown_map: per flow_key cooldown alert_cooldown_sec giây.
//          Cùng flow_key chỉ trigger on_ml_alert_ tối đa 1 lần / 10 giây.
//          → Triệt tiêu hoàn toàn duplicate alert trong log.
// =============================================================================

void MLEngine::run() {
    LOG_INFO("MLEngine worker thread started");

    using Clock     = std::chrono::steady_clock;
    using TimePoint = std::chrono::time_point<Clock>;

    // flow_key → thời điểm alert gần nhất
    std::unordered_map<std::string, TimePoint> alert_cooldown_map;
    auto last_cleanup = Clock::now();

    while (running_) {
        std::optional<MLJob> opt = job_queue_.pop(200);
        if (!opt.has_value()) continue;

        MLResult result = processJob(*opt);
        ++jobs_processed_;

        if (result.final_result == DetectionResult::NORMAL) continue;

        // [FIX-1] Ngưỡng alert thống nhất = min_confidence
        // VOTE:LOW: score = ae_score * 0.60 = 0.961 * 0.60 = 0.577
        // 0.577 < 0.60 → skip → KHÔNG alert (fix false positive YouTube)
        if (result.confidence < cfg_.min_confidence) continue;

        ++anomalies_found_;
        if (!on_ml_alert_) continue;

        // [FIX-4] Cooldown check per flow_key
        const auto now = Clock::now();
        auto it = alert_cooldown_map.find(result.flow_key);
        if (it != alert_cooldown_map.end()) {
            const double elapsed =
                std::chrono::duration<double>(now - it->second).count();
            if (elapsed < static_cast<double>(cfg_.alert_cooldown_sec))
                continue;   // Còn trong cooldown → bỏ qua
            it->second = now;
        } else {
            alert_cooldown_map[result.flow_key] = now;
        }

        on_ml_alert_(result);

        // Dọn cooldown map mỗi 60s để tránh memory leak
        if (std::chrono::duration<double>(now - last_cleanup).count() > 60.0) {
            for (auto it2 = alert_cooldown_map.begin();
                 it2 != alert_cooldown_map.end(); ) {
                const double age =
                    std::chrono::duration<double>(now - it2->second).count();
                it2 = (age > cfg_.alert_cooldown_sec * 2.0f)
                    ? alert_cooldown_map.erase(it2)
                    : std::next(it2);
            }
            last_cleanup = now;
        }
    }

    LOG_INFO("MLEngine worker thread exited");
}

// =============================================================================
//  processJob
//
//  [FIX-3] TLS/HTTPS suppression:
//    Điều kiện: (dst_port hoặc src_port là TLS port) VÀ XGB=BENIGN
//    Hành động: reset ae_result về default BENIGN (score=0)
//    Lý do: AE được train trên plaintext traffic.
//           TLS payload = encrypted bytes → entropy cao → reconstruction
//           error cao → AE nhầm thành PORT_SCAN (pattern ngắn, varied bytes).
//           Khi XGB (supervised, train trên labeled data) đã nói BENIGN,
//           ta tin XGB hơn AE trong trường hợp TLS.
// =============================================================================

static constexpr std::array<uint16_t, 6> TLS_PORTS = {
    443, 8443, 9443, 465, 993, 995
};
static bool isTlsPort(uint16_t port) {
    for (auto p : TLS_PORTS) if (p == port) return true;
    return false;
}

MLResult MLEngine::processJob(const MLJob& job) {
    MLResult result;
    result.flow_key  = job.flow_key;
    result.src_ip    = job.src_ip;
    result.dst_ip    = job.dst_ip;
    result.src_port  = job.src_port;
    result.dst_port  = job.dst_port;
    result.timestamp = job.timestamp;

    const std::array<float, FeatureVector::SIZE> features =
        extractor_.scalerLoaded()
            ? extractor_.normalizeRaw(job.features)
            : job.features.toArray();

    if (xgb_model_ && xgb_model_->isReady())
        result.xgb_result = xgb_model_->infer(features);

    if (ae_model_ && ae_model_->isReady())
        result.ae_result = ae_model_->infer(features);

    // [FIX-3] TLS suppression
    const bool is_tls = isTlsPort(job.dst_port) || isTlsPort(job.src_port);
    if (is_tls && result.xgb_result.label == MODEL_LABEL_BENIGN) {
        result.ae_result = ModelOutput{};   // reset về BENIGN, score=0
        LOG_DEBUG("MLEngine: TLS port " + std::to_string(job.dst_port)
                  + " + XGB=BENIGN → AE suppressed [" + job.flow_key + "]");
    }

    // TLS Suppression mở rộng:
    bool is_tls_port = (job.dst_port == 443 || job.src_port == 443);
    
    // Nếu là cổng TLS và XGBoost báo Port Scan với độ tin cậy không tuyệt đối (< 0.9)
    if (is_tls_port && 
        result.xgb_result.label == MODEL_LABEL_PORT_SCAN && 
        result.xgb_result.score < 0.9f) 
    {
        result.final_result = DetectionResult::NORMAL;
        result.confidence = 0.0f;
        result.detail += " [Suppressed: Probable False Positive on TLS]";
    }

    EngineOutput ev     = combineVoting(result.xgb_result, result.ae_result);
    result.confidence   = ev.score;
    result.final_result = labelToThreat(ev.label);
    result.detail       = ev.detail;

    return result;
}

// =============================================================================
//  combineVoting
//
//  [FIX-2] VOTE:LOW case (XGB=BENIGN, AE=Attack):
//    Trước: is_anomaly = (ae_score * 0.60 >= ae_threshold=0.10) → luôn TRUE
//    Sau:   is_anomaly = (ae_score >= ae_high_threshold=0.85)
//           score = ae_confident ? ae_score * 0.60 : 0.0
//
//  Ví dụ từ log:
//    AE score=0.961 → 0.961 >= 0.85 → ae_confident=true
//    score = 0.961 * 0.60 = 0.577
//    Nhưng 0.577 < min_confidence=0.60 → bị chặn ở run() [FIX-1]
//    → KHÔNG alert ✅
//
//  Bảng voting đầy đủ:
//    XGBoost  | AE           | Result
//    ---------|--------------|------------------------------------------
//    Attack   | Attack       | HIGH   = xgb_w*xgb + ae_w*ae
//    Attack   | Benign       | MEDIUM = xgb_score * 0.80
//    Benign   | Attack≥0.85  | LOW    = ae_score  * 0.60
//    Benign   | Attack<0.85  | NORMAL = 0.0  (suppress weak AE signal)
//    Benign   | Benign       | NORMAL = 0.0
// =============================================================================

EngineOutput MLEngine::combineVoting(const ModelOutput& xgb_out,
                                     const ModelOutput& ae_out) const
{
    EngineOutput ev;

    const bool xgb_ready = xgb_model_ && xgb_model_->isReady();
    const bool ae_ready  = ae_model_  && ae_model_->isReady();

    if (!xgb_ready && !ae_ready) {
        ev.label  = MODEL_LABEL_BENIGN;
        ev.score  = 0.f;
        ev.detail = "No model ready";
        return ev;
    }

    if (xgb_ready && !ae_ready) {
        ev.is_anomaly = xgb_out.is_anomaly;
        ev.label      = xgb_out.label;
        ev.score      = xgb_out.score;
        ev.detail     = "[XGB only] " + xgb_out.detail;
        return ev;
    }
    if (!xgb_ready && ae_ready) {
        // [FIX-2] AE alone: yêu cầu score >= ae_high_threshold
        const bool ae_confident = (ae_out.score >= cfg_.ae_high_threshold);
        ev.is_anomaly = ae_out.is_anomaly && ae_confident;
        ev.label      = ae_confident ? ae_out.label : MODEL_LABEL_BENIGN;
        ev.score      = ae_confident ? ae_out.score * 0.60f : 0.f;
        ev.detail     = "[AE only] " + ae_out.detail;
        return ev;
    }

    // Cả 2 ready
    const bool xgb_attack = (xgb_out.label != MODEL_LABEL_BENIGN);
    const bool ae_attack  = (ae_out.label  != MODEL_LABEL_BENIGN);

    std::ostringstream oss;

    if (xgb_attack && ae_attack) {
        // Cả 2 đồng thuận → HIGH
        ev.label      = xgb_out.label;
        ev.score      = cfg_.xgb_weight * xgb_out.score
                      + cfg_.ae_weight  * ae_out.score;
        ev.is_anomaly = true;
        oss << "[VOTE:HIGH] ";

    } else if (xgb_attack && !ae_attack) {
        // Chỉ XGB → MEDIUM
        ev.label      = xgb_out.label;
        ev.score      = xgb_out.score * 0.80f;
        ev.is_anomaly = (ev.score >= cfg_.xgb_threshold);
        oss << "[VOTE:MED] ";

    } else if (!xgb_attack && ae_attack) {
        // [FIX-2] Chỉ AE → LOW, nhưng chỉ khi AE đủ chắc (>= ae_high_threshold)
        const bool ae_confident = (ae_out.score >= cfg_.ae_high_threshold);
        ev.label      = ae_confident ? ae_out.label : MODEL_LABEL_BENIGN;
        ev.score      = ae_confident ? ae_out.score * 0.60f : 0.f;
        ev.is_anomaly = ae_confident;
        oss << (ae_confident ? "[VOTE:LOW] " : "[VOTE:NORM] ");

    } else {
        // Cả 2 BENIGN → NORMAL
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
        << "\n  XGBoost        : "
        << (xgb_model_ && xgb_model_->isReady() ? "READY" : "NOT LOADED")
        << "\n  AEClassifier   : "
        << (ae_model_  && ae_model_->isReady()  ? "READY" : "NOT LOADED")
        << "\n  Scaler         : "
        << (extractor_.scalerLoaded() ? "LOADED" : "NOT LOADED (raw features)")
        << "\n  Weights        : xgb=" << cfg_.xgb_weight
        << " ae=" << cfg_.ae_weight
        << "\n  Thresholds     : xgb=" << cfg_.xgb_threshold
        << " ae=" << cfg_.ae_threshold
        << " ae_high=" << cfg_.ae_high_threshold
        << "\n  Min confidence : " << cfg_.min_confidence
        << "\n  Alert cooldown : " << cfg_.alert_cooldown_sec << "s";
    return oss.str();
}
