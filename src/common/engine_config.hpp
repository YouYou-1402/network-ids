// src/common/engine_config.hpp
#pragma once
#include <atomic>

/// Cấu hình bật/tắt các engine — thread-safe, không cần lock
/// Singleton vì cần truy cập từ nhiều tầng (WorkerThread, MLEngine, ui_main)
struct EngineConfig {
    std::atomic<bool> detection_enabled { true };
    std::atomic<bool> ml_enabled        { true };

    /// Sync từ AppConfig sau khi ConfigLoader::load() đã chạy
    /// Gọi 1 lần trong main() ngay sau ConfigLoader::load()
    void syncFromConfig();

    static EngineConfig& instance() {
        static EngineConfig cfg;
        return cfg;
    }

private:
    EngineConfig() = default;
};

#define ENGINE_CFG EngineConfig::instance()
