#include "ml_engine.hpp"
#include "../common/logger.hpp"
#include "../common/metrics.hpp"
#include <arpa/inet.h>
#include <sstream>

MLEngine::MLEngine(MLJobQueue& job_queue, MLAlertCallback on_ml_alert)
    : job_queue_(job_queue)
    , on_ml_alert_(std::move(on_ml_alert)) {}

MLEngine::~MLEngine() {
    stop();
}

// ─── Start ────────────────────────────────────────────────────────────────────
void MLEngine::start(bool        use_mock,
                     const std::string& if_model_path,
                     const std::string& ae_model_path) {
    // Khởi tạo models
    if (use_mock) {
        if_model_ = std::make_unique<MockIsolationForest>(0.6f);
        ae_model_ = std::make_unique<MockAutoencoder>(0.05f);
        if_model_->load("");
        ae_model_->load("");
        LOG_INFO("MLEngine: Using MOCK models (no ONNX Runtime)");
    } else {
        if_model_ = std::make_unique<OnnxModel>("IsolationForest", 0.6f);
        ae_model_ = std::make_unique<OnnxModel>("Autoencoder",     0.05f);

        if (!if_model_->load(if_model_path)) {
            LOG_WARN("IF model load failed, falling back to mock");
            if_model_ = std::make_unique<MockIsolationForest>(0.6f);
            if_model_->load("");
        }
        if (!ae_model_->load(ae_model_path)) {
            LOG_WARN("AE model load failed, falling back to mock");
            ae_model_ = std::make_unique<MockAutoencoder>(0.05f);
            ae_model_->load("");
        }
    }

    running_ = true;
    thread_  = std::thread(&MLEngine::run, this);
    LOG_INFO("MLEngine started");
}

void MLEngine::stop() {
    running_ = false;
    if (thread_.joinable())
        thread_.join();
    LOG_INFO("MLEngine stopped. Jobs processed: "
             + std::to_string(jobs_processed_)
             + ", Anomalies: " + std::to_string(anomalies_found_));
}

// ─── Main inference loop ──────────────────────────────────────────────────────
void MLEngine::run() {
    LOG_INFO("MLEngine inference loop running");

    while (running_) {
        // Pop job từ queue (blocking 200ms)
        auto job_opt = job_queue_.pop(200);
        if (!job_opt.has_value()) continue;

        const MLJob& job = job_opt.value();

        // Chạy inference
        MLResult result = processJob(job);
        jobs_processed_++;

        // Chỉ callback khi phát hiện bất thường
        if (result.final_result != DetectionResult::NORMAL) {
            anomalies_found_++;
            if (on_ml_alert_)
                on_ml_alert_(result);
        }
    }
}

// ─── Process một job ──────────────────────────────────────────────────────────
MLResult MLEngine::processJob(const MLJob& job) {
    MLResult result;
    result.flow_key  = job.flow_key;
    result.src_ip    = job.src_ip;
    result.dst_ip    = job.dst_ip;
    result.src_port  = job.src_port;
    result.dst_port  = job.dst_port;
    result.timestamp = job.timestamp;

    // Normalize features trước khi inference
    FeatureVector norm_fv = extractor_.normalize(job.features);

    // ── Isolation Forest inference ────────────────────────────────────────────
    result.if_result = if_model_->infer(norm_fv);

    // ── Autoencoder inference ─────────────────────────────────────────────────
    result.ae_result = ae_model_->infer(norm_fv);

    // ── Tổng hợp kết quả ─────────────────────────────────────────────────────
    result.final_result = combineResults(
        result.if_result,
        result.ae_result,
        norm_fv,
        result.confidence
    );

    // Build detail string
    std::ostringstream oss;
    oss << "[L2] " << result.if_result.detail
        << " | " << result.ae_result.detail
        << " | Confidence: " << result.confidence;
    result.detail = oss.str();

    return result;
}

// ─── Combine IF + AE results ──────────────────────────────────────────────────
DetectionResult MLEngine::combineResults(const ModelOutput& if_out,
                                          const ModelOutput& ae_out,
                                          const FeatureVector& fv,
                                          float& confidence) const {
    // Voting strategy:
    // ┌─────────────┬──────────────┬──────────────────────────────┐
    // │ IF result   │ AE result    │ Decision                     │
    // ├─────────────┼──────────────┼──────────────────────────────┤
    // │ Anomaly     │ Anomaly      │ HIGH confidence anomaly      │
    // │ Anomaly     │ Normal       │ MEDIUM — classify by IF      │
    // │ Normal      │ Anomaly      │ MEDIUM — classify by AE      │
    // │ Normal      │ Normal       │ Normal                       │
    // └─────────────┴──────────────┴──────────────────────────────┘

    bool if_anomaly = if_out.is_anomaly;
    bool ae_anomaly = ae_out.is_anomaly;

    if (!if_anomaly && !ae_anomaly) {
        confidence = 1.f - std::max(if_out.score, ae_out.score);
        return DetectionResult::NORMAL;
    }

    if (if_anomaly && ae_anomaly) {
        // Cả hai đồng ý → confidence cao
        confidence = (if_out.score + ae_out.score) / 2.f;
        return classifyThreat(fv);
    }

    // Chỉ một model phát hiện → confidence thấp hơn
    if (if_anomaly) {
        confidence = if_out.score * 0.7f;
        return classifyThreat(fv);
    }

    // ae_anomaly only
    confidence = ae_out.score * 0.7f;
    return classifyThreat(fv);
}

// ─── Classify threat type từ features ────────────────────────────────────────
DetectionResult MLEngine::classifyThreat(const FeatureVector& fv) const {
    // Ma trận phát hiện từ báo cáo:
    // Slow DDoS:        conn_duration cao + bytes_per_second thấp
    // DDoS Volumetric:  pkt_rate cao + syn_no_ack_ratio cao
    // Port Scan:        unique_dst_ports cao + rst_ratio cao

    float slow_ddos_score = 0.f;
    float ddos_score      = 0.f;
    float scan_score      = 0.f;

    // Slow DDoS indicators
    if (fv.conn_duration > 0.1f)       // normalized > 0.1 → > 360s raw
        slow_ddos_score += 0.4f;
    if (fv.bytes_per_second < 0.001f)  // normalized rất thấp
        slow_ddos_score += 0.3f;
    if (fv.header_complete < 0.5f)
        slow_ddos_score += 0.3f;

    // DDoS Volumetric indicators
    if (fv.pkt_rate > 0.02f)           // normalized > 0.02 → > 1000 pps raw
        ddos_score += 0.5f;
    if (fv.syn_no_ack_ratio > 0.7f)
        ddos_score += 0.5f;

    // Port Scan indicators
    if (fv.unique_dst_ports > 0.0003f) // normalized > 0.0003 → > 20 ports raw
        scan_score += 0.5f;
    if (fv.rst_ratio > 0.5f)
        scan_score += 0.5f;

    // Trả về loại có score cao nhất
    if (slow_ddos_score >= ddos_score && slow_ddos_score >= scan_score)
        return DetectionResult::SLOW_DDOS;
    if (ddos_score >= scan_score)
        return DetectionResult::DDOS_VOLUMETRIC;
    return DetectionResult::PORT_SCAN;
}
