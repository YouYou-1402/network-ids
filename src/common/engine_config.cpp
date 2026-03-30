// src/common/engine_config.cpp  ← file mới, thêm vào CMakeLists
#include "engine_config.hpp"
#include "config_loader.hpp"

void EngineConfig::syncFromConfig() {
    const auto& c = APP_CFG;
    detection_enabled.store(c.detection_enabled, std::memory_order_relaxed);
    ml_enabled.store       (c.ml_enabled,        std::memory_order_relaxed);
}
