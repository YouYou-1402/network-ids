#pragma once
// =============================================================================
//  src/ml/ml_config.hpp
//
//  Thêm so với phiên bản cũ:
//    [THÊM] ae_high_threshold  = 0.85f  — ngưỡng AE "rất chắc" khi XGB=BENIGN
//    [THÊM] alert_cooldown_sec = 10.0f  — dedup alert cùng flow_key
// =============================================================================

#include <string>

struct MLConfig {
    std::string xgb_model_path;
    std::string ae_model_path;
    std::string scaler_path;

    // ── Model thresholds ──────────────────────────────────────────────────
    float xgb_threshold     = 0.50f;   // XGB: score >= này → attack
    float ae_threshold      = 0.10f;   // AE: reconstruction error threshold
                                       //     (dùng nội bộ trong OnnxAutoencoder)

    // [THÊM] ae_high_threshold: ngưỡng AE khi XGB=BENIGN (VOTE:LOW case)
    // Chỉ khi AE score >= 0.85 mới xét là anomaly — tránh false positive
    // với TLS/HTTPS traffic (AE không reliable với encrypted payload)
    float ae_high_threshold = 0.85f;

    // ── Voting weights ────────────────────────────────────────────────────
    float min_confidence     = 0.60f;  // Ngưỡng alert cuối cùng (duy nhất)
    float xgb_weight         = 1.00f;
    float ae_weight          = 0.00f;  // 0 = tắt AE trong weighted sum

    // ── Alert dedup ───────────────────────────────────────────────────────
    // [THÊM] Cooldown per flow_key: chỉ alert 1 lần / N giây
    // Giải quyết duplicate alert khi L2 feeder push cùng flow nhiều lần
    float alert_cooldown_sec = 10.0f;
};
