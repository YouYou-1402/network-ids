// =============================================================================
//  src/ui_main.cpp
//
//  Thay đổi so với phiên bản cũ:
//    [XÓA] 8 dòng convert MLCfg → MLConfig (duplicate)
//    [ĐỔI] ml_engine.start(cfg.ml)  ← cfg.ml đã là MLConfig
// =============================================================================

#include "ui/qt/main_window.hpp"
#include "analysis/alert_manager.hpp"
#include "detection/dispatcher.hpp"
#include "ml/ml_engine.hpp"
#include "ml/data_queue.hpp"
#include "ml/feedback_loop.hpp"
#include "capture/io/packet_ring_buffer.hpp"
#include "firewall/firewall_manager.hpp"
#include "common/logger.hpp"
#include "common/engine_config.hpp"
#include "common/config_loader.hpp"

#include <QApplication>
#include <QMessageBox>
#include <csignal>
#include <memory>
#include <filesystem>
#include <unistd.h>
#include <arpa/inet.h>

static QApplication* g_app = nullptr;

void signalHandler(int) {
    if (g_app) g_app->quit();
}

int main(int argc, char* argv[]) {
    // RESPONSIVE: bật HiDPI scaling trước khi tạo QApplication
    // AA_EnableHighDpiScaling: Qt tự scale UI theo device pixel ratio (DPI màn hình)
    // AA_UseHighDpiPixmaps:    icon/pixmap cũng được scale theo DPI
    // Hai attribute này phải được set TRƯỚC khi QApplication được khởi tạo.
    // Trên Qt6, HiDPI mặc định bật — hai dòng này không gây hại.
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
#endif

    QApplication app(argc, argv);
    g_app = &app;

    signal(SIGINT,  signalHandler);
    signal(SIGTERM, signalHandler);

    app.setApplicationName("Network IDS/IPS");
    app.setOrganizationName("HVKTQS");

    // ── 1. Load config JSON ───────────────────────────────────────────────────
    const std::string cfg_path = (argc > 1)
        ? argv[1]
        : "/media/linhlinh/learn/nckh/network-ids/config/config.json";

    try {
        ConfigLoader::load(cfg_path);
    } catch (const std::exception& e) {
        QMessageBox::critical(nullptr, "Config Error",
            QString("Failed to load config:\n%1").arg(e.what()));
        return 1;
    }

    const AppConfig& cfg = APP_CFG;

    // ── 2. Sync EngineConfig atomic flags ─────────────────────────────────────
    ENGINE_CFG.syncFromConfig();

    // ── 3. Setup logging từ config ────────────────────────────────────────────
    const std::string log_dir = std::filesystem::path(cfg.system.log_file)
                                    .parent_path().string();
    std::filesystem::create_directories(log_dir);

    Logger::instance().setLevel(Logger::Level::INFO);
    Logger::instance().setLogFile(cfg.system.log_file);

    LOG_INFO("=== Network IDS/IPS UI started ==="
             " config=" + cfg_path +
             " euid="   + std::to_string(::geteuid()));

    // ── 4. Kiểm tra quyền root ────────────────────────────────────────────────
    const bool is_root = (::geteuid() == 0);
    if (!is_root) {
        LOG_WARN("Running without root — kernel firewall backend unavailable");
        QMessageBox::warning(
            nullptr,
            "No Root Privileges",
            "⚠️  App is running without root privileges.\n\n"
            "Firewall rules will be stored IN-MEMORY ONLY.\n"
            "Packets will NOT be blocked at kernel level.\n\n"
            "To enable real blocking:\n"
            "  sudo ./network-ids");
    }

    // ── 5. Ring buffer ────────────────────────────────────────────────────────
    PacketRingBuffer ring_buf(65536);

    // ── 6. Alert Manager ──────────────────────────────────────────────────────
    AlertManager alert_manager(1000);
    alert_manager.setAlertLogFile(cfg.system.alert_log_file);

    // ── 7. ML Job Queue ───────────────────────────────────────────────────────
    MLJobQueue ml_job_queue(16384);  // heap-allocated, ~2.7MB

    // ── 8. Firewall Manager ───────────────────────────────────────────────────
    std::unique_ptr<FirewallManager> firewall_manager;

    if (is_root) {
        firewall_manager = std::make_unique<FirewallManager>(
            cfg.firewall.use_nftables);
        LOG_INFO("FirewallManager backend: " + firewall_manager->backendName());
    } else {
        firewall_manager =
            std::make_unique<FirewallManager>(FirewallManager::InMemoryTag{});
        LOG_INFO("FirewallManager: in-memory mode (no root)");
    }

    const std::string fw_rules_path = cfg.firewall.rules_file;
    std::filesystem::create_directories(
        std::filesystem::path(fw_rules_path).parent_path());

    if (std::filesystem::exists(fw_rules_path)) {
        firewall_manager->loadRules(fw_rules_path);
        LOG_INFO("Firewall rules loaded: BL="
                 + std::to_string(firewall_manager->blacklistSize())
                 + " WL=" + std::to_string(firewall_manager->whitelistSize()));
    }

    // ── 9. Feedback Loop ──────────────────────────────────────────────────────
    FeedbackLoop feedback_loop(
        [&firewall_manager](const RuleProposal& p) {
            switch (p.type) {
                case RuleProposal::Type::ADD_TO_BLACKLIST: {
                    if (!firewall_manager) break;
                    struct in_addr addr;
                    addr.s_addr = p.src_ip;
                    const std::string ip_str = inet_ntoa(addr);
                    firewall_manager->autoBlock(ip_str, 0, 0, p.detail);
                    LOG_INFO("[FeedbackLoop] Auto-blocked: " + ip_str
                             + " reason=" + p.detail);
                    break;
                }
                case RuleProposal::Type::REDUCE_TIMEOUT:
                    LOG_INFO("[FeedbackLoop] Proposal REDUCE_TIMEOUT: "
                             + p.detail + " (pending admin review)");
                    break;
                case RuleProposal::Type::INCREASE_RATE_LIMIT:
                    LOG_INFO("[FeedbackLoop] Proposal INCREASE_RATE_LIMIT: "
                             + p.detail + " (pending admin review)");
                    break;
                case RuleProposal::Type::ADD_SIGNATURE:
                    LOG_INFO("[FeedbackLoop] Proposal ADD_SIGNATURE: "
                             + p.detail + " (pending admin review)");
                    break;
            }
        }
    );

    // ── 10. ML Engine ─────────────────────────────────────────────────────────
    MLEngine ml_engine(
        ml_job_queue,
        [&alert_manager, &feedback_loop](const MLResult& r) {
            alert_manager.addL2Alert(r);
            feedback_loop.onMLResult(r);
        });

    if (cfg.ml_enabled) {
        // ✅ cfg.ml đã là MLConfig — truyền thẳng, không cần convert
        ml_engine.start(cfg.ml);
        LOG_INFO("MLEngine started:"
                 " xgb="    + cfg.ml.xgb_model_path
               + " ae="     + (cfg.ml.ae_model_path.empty()
                               ? "disabled" : cfg.ml.ae_model_path)
               + " scaler=" + (cfg.ml.scaler_path.empty()
                               ? "disabled" : cfg.ml.scaler_path));
    } else {
        ml_engine.start(/*use_mock=*/true);
        LOG_INFO("MLEngine started in MOCK mode (ml_enabled=false in config)");
    }

    // ── 11. Dispatcher ────────────────────────────────────────────────────────
    Dispatcher dispatcher(cfg.system.num_workers, ring_buf, &ml_job_queue);
    dispatcher.setFirewallManager(firewall_manager.get());
    dispatcher.start([&alert_manager](const DetectionEvent& ev) {
        alert_manager.addL1Alert(ev);
    });

    LOG_INFO("=== All components started ==="
             " workers="  + std::to_string(cfg.system.num_workers) +
             " ml="       + (cfg.ml_enabled ? "ON" : "MOCK") +
             " firewall=" + firewall_manager->backendName() +
             " root="     + (is_root ? "yes" : "no"));

    // ── 12. UI ────────────────────────────────────────────────────────────────
    MainWindow window(
        alert_manager,
        dispatcher,
        ml_engine,
        ring_buf,
        firewall_manager.get());
    window.show();

    const int ret = app.exec();

    // ── 13. Shutdown ──────────────────────────────────────────────────────────
    LOG_INFO("=== Shutting down ==="
             " ml_jobs="   + std::to_string(ml_engine.jobsProcessed()) +
             " anomalies=" + std::to_string(ml_engine.anomaliesFound()) +
             " proposals=" + std::to_string(feedback_loop.pendingCount()));

    dispatcher.stop();
    ml_engine.stop();

    if (firewall_manager->blacklistSize() + firewall_manager->whitelistSize() > 0) {
        if (firewall_manager->saveRules(fw_rules_path))
            LOG_INFO("Firewall rules auto-saved → " + fw_rules_path);
    }

    LOG_INFO("=== Shutdown complete ===");
    return ret;
}
