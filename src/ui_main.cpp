#include "ui/qt/main_window.hpp"
#include "analysis/alert_manager.hpp"
#include "detection/dispatcher.hpp"
#include "ml/ml_engine.hpp"
#include "ml/data_queue.hpp"
#include "capture/io/packet_ring_buffer.hpp"
#include "firewall/firewall_manager.hpp"
#include "common/logger.hpp"
#include "common/engine_config.hpp"

#include <QApplication>
#include <csignal>
#include <memory>
#include <filesystem>

static QApplication* g_app = nullptr;

void signalHandler(int) {
    if (g_app) g_app->quit();
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    g_app = &app;

    signal(SIGINT,  signalHandler);
    signal(SIGTERM, signalHandler);

    app.setApplicationName("Network IDS/IPS");
    app.setOrganizationName("HVKTQS");

    // ── Logging ───────────────────────────────────────────────────────────────
    const std::string log_dir = "../logs/";
    std::filesystem::create_directories(log_dir);
    Logger::instance().setLevel(Logger::Level::INFO);
    Logger::instance().setLogFile(log_dir + "/system.log");
    LOG_INFO("=== Network IDS/IPS UI started ===");

    // ── Backend components ────────────────────────────────────────────────────
    PacketRingBuffer ring_buf(65536);

    AlertManager alert_manager(1000);
    alert_manager.setAlertLogFile(log_dir + "/alert.log");

    MLJobQueue ml_job_queue;
    MLEngine ml_engine(
        ml_job_queue,
        [&alert_manager](const MLResult& r) {
            alert_manager.addL2Alert(r);
        });
    ml_engine.start();

    Dispatcher dispatcher(4, ring_buf);
    dispatcher.start([&alert_manager](const DetectionEvent& ev) {
        alert_manager.addL1Alert(ev);
    });

    // ── FirewallManager — in-memory (không cần root) ──────────────────────────
    auto firewall_manager =
        std::make_unique<FirewallManager>(FirewallManager::InMemoryTag{});

    // Auto-load rules từ config cố định
    const std::string fw_rules_path =
        "/media/linhlinh/learn/nckh/network-ids/config/firewall_rules.json";

    if (std::filesystem::exists(fw_rules_path)) {
        firewall_manager->loadRules(fw_rules_path);
        LOG_INFO("Firewall rules loaded: BL="
                 + std::to_string(firewall_manager->blacklistSize())
                 + " WL=" + std::to_string(firewall_manager->whitelistSize()));
    } else {
        // Tạo thư mục config nếu chưa có
        std::filesystem::create_directories(
            "/media/linhlinh/learn/nckh/network-ids/config");
        LOG_INFO("Config dir created, no existing rules to load.");
    }

    LOG_INFO("Backend initialized: ring_buf=65536 workers=4 ml=enabled"
             " firewall=" + firewall_manager->backendName());

    // ── UI ────────────────────────────────────────────────────────────────────
    MainWindow window(
        alert_manager,
        dispatcher,
        ml_engine,
        ring_buf,
        firewall_manager.get());
    window.show();

    const int ret = app.exec();

    // ── Auto-save rules khi thoát ─────────────────────────────────────────────
    if (firewall_manager->blacklistSize() + firewall_manager->whitelistSize() > 0) {
        if (firewall_manager->saveRules(fw_rules_path))
            LOG_INFO("Firewall rules auto-saved to " + fw_rules_path);
    }

    dispatcher.stop();
    ml_engine.stop();
    LOG_INFO("=== Shutdown complete ===");
    return ret;
}
