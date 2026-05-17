#pragma once
//  src/ml/ml_config.hpp
#include <string>

struct MLConfig {

    std::string xgb_model_path;
    std::string ae_model_path;
    std::string scaler_path;
    std::string scaler_nslkdd_path;
    std::string freq_map_path;
    std::string ae_meta_path;

    float xgb_threshold     = 0.50f;
    float ae_threshold      = 0.099726f;  
    float ae_high_threshold = 0.85f;
    float min_confidence    = 0.60f;
    float xgb_weight = 0.65f;
    float ae_weight  = 0.35f;
    float alert_cooldown_sec = 1.0f;
};
