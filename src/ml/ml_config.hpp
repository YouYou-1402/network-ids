#pragma once
// =============================================================================
//  src/ml/ml_config.hpp
//
//  Thay đổi so với phiên bản cũ:
//    [THÊM] scaler_nslkdd_path — path tới scaler_nslkdd.bin (23-dim, 184 bytes)
//    [THÊM] ae_meta_path       — path tới ae_meta.json (chứa ae_threshold)
//    [FIX]  ae_threshold default = 0.099726f (đồng bộ với Python pipeline)
// =============================================================================

#include <string>

// =============================================================================
//  MLConfig — cấu hình cho MLEngine
//
//  Được load từ config.json section "ml" bởi ConfigLoader.
//  Được truyền vào MLEngine::init() khi khởi động.
// =============================================================================
struct MLConfig {

    // ── Model paths ───────────────────────────────────────────────────────────
    // xgb_model_path : CICIDS2017 XGBoost ONNX (21-dim input)
    // ae_model_path  : NSL-KDD Deep Autoencoder ONNX (39-dim input)
    std::string xgb_model_path;
    std::string ae_model_path;

    // ── Scaler paths ──────────────────────────────────────────────────────────
    // scaler_path        : CICIDS2017 StandardScaler (21 mean + 21 std = 168 bytes)
    // scaler_nslkdd_path : NSL-KDD StandardScaler   (23 mean + 23 std = 184 bytes)
    //
    // Format binary: [float32 mean × N][float32 std × N]
    // Được export bởi export_scaler.py
    std::string scaler_path;
    std::string scaler_nslkdd_path;

    // ── Meta path ─────────────────────────────────────────────────────────────
    // ae_meta_path : JSON file chứa ae_threshold (và các meta khác nếu cần)
    // Format: { "ae_threshold": 0.099726 }
    //
    // Nếu file không tồn tại → NslKddExtractor dùng ae_threshold bên dưới
    std::string ae_meta_path;

    // ── Thresholds ────────────────────────────────────────────────────────────
    // xgb_threshold    : XGBoost output >= threshold → ATTACK
    // ae_threshold     : AE MSE >= threshold → ANOMALY
    //                    Giá trị 0.099726 = percentile 95 của MSE trên train set
    //                    (khớp chính xác với Python pipeline)
    // ae_high_threshold: MSE >= ae_high_threshold → HIGH confidence anomaly
    //                    Dùng trong voting để boost ae_weight
    // min_confidence   : Final confidence < min_confidence → suppress alert
    float xgb_threshold     = 0.50f;
    float ae_threshold      = 0.099726f;  // ← khớp Python, không phải 0.10
    float ae_high_threshold = 0.85f;
    float min_confidence    = 0.60f;

    // ── Ensemble weights ──────────────────────────────────────────────────────
    // Final confidence = xgb_weight * xgb_conf + ae_weight * ae_conf
    // Tổng không bắt buộc = 1.0 (MLEngine normalize nếu cần)
    float xgb_weight = 0.65f;
    float ae_weight  = 0.35f;

    // ── Misc ──────────────────────────────────────────────────────────────────
    // alert_cooldown_sec : suppress alert cho cùng flow_key trong N giây
    float alert_cooldown_sec = 1.0f;
};
