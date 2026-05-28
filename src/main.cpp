// =============================================================================
//  src/main.cpp
//
//  Thay đổi so với phiên bản cũ:
//    [XÓA] 8 dòng convert MLCfg → MLConfig (duplicate)
//    [ĐỔI] ml_engine.start(cfg.ml)  ← cfg.ml đã là MLConfig
// =============================================================================

#include <iostream>
#include <iomanip>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>
#include <csignal>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <filesystem>

#include "common/logger.hpp"
#include "common/metrics.hpp"
#include "common/config_loader.hpp"
#include "common/engine_config.hpp"
#include "core/threat_types.hpp"
#include "capture/packet_capture.hpp"
#include "detection/dispatcher.hpp"
#include "ml/feature_extractor.hpp"
#include "ml/data_queue.hpp"
#include "ml/ml_engine.hpp"
#include "ml/feedback_loop.hpp"
#include "analysis/alert_manager.hpp"

// ─────────────────────────────────────────────────────────────────────────────
// Global state
// ─────────────────────────────────────────────────────────────────────────────
std::atomic<bool> g_running{true};
PacketCapture*    g_capture_ptr    = nullptr;
Dispatcher*       g_dispatcher_ptr = nullptr;
MLEngine*         g_ml_engine_ptr  = nullptr;

void signalHandler(int sig) {
    const char* msg = "\n[SIGNAL] Shutdown requested. Stopping...\n";
    write(STDOUT_FILENO, msg, strlen(msg));
    g_running = false;
    if (g_capture_ptr) g_capture_ptr->stopCapture();
}

static std::string ipToString(uint32_t ip) {
    struct in_addr addr; addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

static const char* alertColor(DetectionResult r) {
    switch (r) {
        case DetectionResult::DDOS_VOLUMETRIC: return "\033[31m";
        case DetectionResult::SLOW_DDOS:       return "\033[33m";
        case DetectionResult::PORT_SCAN:       return "\033[38;5;208m";
        case DetectionResult::OTHER_ATTACK:    return "\033[35m";
        default:                               return "\033[32m";
    }
}

void onL1Alert(const DetectionEvent& event, AlertManager& alert_manager) {
    alert_manager.addL1Alert(event);
    std::cout << alertColor(event.result)
              << "[L1] " << std::left << std::setw(18) << threatToString(event.result)
              << " | " << std::setw(6) << actionToString(event.action)
              << " | Src: " << std::setw(15) << ipToString(event.src_ip)
              << ":" << std::setw(5) << event.src_port
              << " | " << event.detail
              << "\033[0m\n";
}

void onL2Alert(const MLResult& result, AlertManager& alert_manager) {
    alert_manager.addL2Alert(result);
    std::cout << alertColor(result.final_result)
              << "[L2] " << std::left << std::setw(18) << threatToString(result.final_result)
              << " | ALERT"
              << " | Src: " << std::setw(15) << ipToString(result.src_ip)
              << ":" << std::setw(5) << result.src_port
              << " | Conf: " << std::fixed << std::setprecision(2) << result.confidence
              << " | " << result.detail
              << "\033[0m\n";
}

void statsPrinterThread(Dispatcher& dispatcher, MLEngine& ml_engine,
                        AlertManager& alert_manager) {
    while (g_running) {
        for (int i = 0; i < 10 && g_running; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (!g_running) break;
        std::cout << "\n\033[36m"
                  << "╔══════════════════════════════════════╗\n"
                  << "║         SYSTEM METRICS               ║\n"
                  << "╠══════════════════════════════════════╣\n"
                  << "║ Captured  : " << std::setw(10) << METRICS.packets_captured.load() << "              ║\n"
                  << "║ Dropped   : " << std::setw(10) << METRICS.packets_dropped.load()  << "              ║\n"
                  << "║ Passed    : " << std::setw(10) << METRICS.packets_passed.load()   << "              ║\n"
                  << "║ Alerted   : " << std::setw(10) << METRICS.packets_alerted.load()  << "              ║\n"
                  << "╠══════════════════════════════════════╣\n"
                  << "║ DDoS      : " << std::setw(10) << alert_manager.ddosAlerts()      << "              ║\n"
                  << "║ SlowDDoS  : " << std::setw(10) << alert_manager.slowDdosAlerts()  << "              ║\n"
                  << "║ PortScan  : " << std::setw(10) << alert_manager.scanAlerts()      << "              ║\n"
                  << "╠══════════════════════════════════════╣\n"
                  << "║ ActiveFlow: " << std::setw(10) << dispatcher.activeFlows()        << "              ║\n"
                  << "║ L2 Jobs   : " << std::setw(10) << ml_engine.jobsProcessed()       << "              ║\n"
                  << "║ L2 Anomaly: " << std::setw(10) << ml_engine.anomaliesFound()      << "              ║\n"
                  << "╚══════════════════════════════════════╝\n"
                  << "\033[0m\n";
    }
}

void flowCleanupThread(Dispatcher& dispatcher) {
    while (g_running) {
        for (int i = 0; i < 60 && g_running; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!g_running) break;
        dispatcher.cleanupFlows(APP_CFG.system.flow_idle_timeout_sec);
    }
}

// ─── CLI args ─────────────────────────────────────────────────────────────────
struct CliArgs {
    std::string mode;
    std::string target;
    std::string config_path;
    bool        use_mock = false;
    bool        no_l2    = false;
};

bool parseArgs(int argc, char* argv[], CliArgs& cli) {
    if (argc < 3) return false;
    cli.mode   = argv[1];
    cli.target = argv[2];
    if (cli.mode != "-i" && cli.mode != "-f") return false;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--mock")                 { cli.use_mock = true; continue; }
        if (arg == "--no-l2")                { cli.no_l2    = true; continue; }
        if (arg == "--config" && i+1 < argc) { cli.config_path = argv[++i]; continue; }
    }
    return true;
}

void printUsage(const char* prog) {
    std::cout
        << "\n\033[1mNetwork IDS/IPS System\033[0m\n"
        << "─────────────────────────────────────────\n"
        << "Usage:\n"
        << "  Live   : " << prog << " -i <interface> [options]\n"
        << "  Offline: " << prog << " -f <pcap_file>  [options]\n"
        << "\nOptions:\n"
        << "  --config PATH   Path to config.json (default: config/config.json)\n"
        << "  --mock          Force mock ML models\n"
        << "  --no-l2         Disable Layer 2 ML engine\n"
        << "\nExamples:\n"
        << "  " << prog << " -i eth0\n"
        << "  " << prog << " -i eth0 --config /etc/ids/config.json\n"
        << "  " << prog << " -f capture.pcap --mock\n\n";
}

void printBanner(const AppConfig& cfg, const CliArgs& cli) {
    std::cout << "\033[1;34m"
              << "╔══════════════════════════════════════════════╗\n"
              << "║     Network IDS/IPS — AI-Powered System      ║\n"
              << "║     Lab Prototype  |  HVKTQS 2025            ║\n"
              << "╚══════════════════════════════════════════════╝\n"
              << "\033[0m"
              << "  Mode    : " << (cli.mode == "-i" ? "LIVE" : "OFFLINE")
              << "  →  " << cli.target << "\n"
              << "  Workers : " << cfg.system.num_workers << "\n"
              << "  Layer 2 : " << (cfg.ml_enabled && !cli.no_l2 ? "ENABLED" : "DISABLED")
              << (cli.use_mock ? " (MOCK)" : "") << "\n"
              << "  Log     : " << cfg.system.log_file << "\n"
              << "  Iface   : " << cfg.capture.interface << "\n"
              << "  Press Ctrl+C to stop.\n"
              << "──────────────────────────────────────────────────\n\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {

    CliArgs cli;
    if (!parseArgs(argc, argv, cli)) {
        printUsage(argv[0]);
        return 1;
    }

    // ── 1. Load config ────────────────────────────────────────────────────────
    const std::string cfg_path = cli.config_path.empty()
        ? "/media/linhlinh/learn/nckh/network-ids/config/config.json"
        : cli.config_path;

    try {
        ConfigLoader::load(cfg_path);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << "\n";
        return 1;
    }

    const AppConfig& cfg = APP_CFG;

    // ── 2. Sync EngineConfig ──────────────────────────────────────────────────
    ENGINE_CFG.syncFromConfig();

    // ── 3. Signal handlers ────────────────────────────────────────────────────
    struct sigaction sa{};
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP,  &sa, nullptr);

    // ── 4. Logging ────────────────────────────────────────────────────────────
    std::filesystem::create_directories(
        std::filesystem::path(cfg.system.log_file).parent_path());

    Logger::instance().setLevel(Logger::Level::INFO);
    Logger::instance().setLogFile(cfg.system.log_file);

    printBanner(cfg, cli);
    LOG_INFO("=== Network IDS started ==="
             " config=" + cfg_path +
             " mode="   + cli.mode +
             " target=" + cli.target +
             " workers=" + std::to_string(cfg.system.num_workers));

    // ── 5. Shared components ──────────────────────────────────────────────────
    MLJobQueue   ml_queue(16384);  // heap-allocated, ~2.7MB
    AlertManager alert_manager(1000);
    alert_manager.setAlertLogFile(cfg.system.alert_log_file);

    // ── 6. Layer 1 Dispatcher ─────────────────────────────────────────────────
    Dispatcher dispatcher(cfg.system.num_workers);
    g_dispatcher_ptr = &dispatcher;

    dispatcher.start([&](const DetectionEvent& event) {
        onL1Alert(event, alert_manager);
    });
    LOG_INFO("Layer 1 started (" + std::to_string(cfg.system.num_workers) + " workers)");

    // ── 7. Layer 2 ML ─────────────────────────────────────────────────────────
    FeedbackLoop feedback_loop([](const RuleProposal& p) {
        LOG_INFO("[FeedbackLoop] Rule proposal: " + p.detail);
    });

    MLEngine ml_engine(ml_queue, [&](const MLResult& result) {
        onL2Alert(result, alert_manager);
        feedback_loop.onMLResult(result);
    });

    const bool run_l2 = cfg.ml_enabled && !cli.no_l2;

    if (run_l2) {
        if (cli.use_mock) {
            ml_engine.start(/*use_mock=*/true);
            LOG_INFO("Layer 2 ML started in MOCK mode");
        } else {
            // ✅ cfg.ml đã là MLConfig — truyền thẳng, không cần convert
            ml_engine.start(cfg.ml);
            LOG_INFO("Layer 2 ML started:"
                     " xgb="    + cfg.ml.xgb_model_path
                   + " ae="     + (cfg.ml.ae_model_path.empty()
                                   ? "disabled" : cfg.ml.ae_model_path)
                   + " scaler=" + (cfg.ml.scaler_path.empty()
                                   ? "disabled" : cfg.ml.scaler_path));
        }
    } else {
        LOG_INFO("Layer 2 ML DISABLED"
                 " (ml_enabled=" + std::string(cfg.ml_enabled ? "true" : "false")
               + " --no-l2="    + std::string(cli.no_l2 ? "true" : "false") + ")");
    }
    g_ml_engine_ptr = &ml_engine;

    // ── 8. PacketCapture ──────────────────────────────────────────────────────
    PacketCapture capture;
    g_capture_ptr = &capture;

    const std::string bpf    = cfg.capture.bpf_filter;
    const bool        opened = (cli.mode == "-i")
        ? capture.openLive   (cli.target, bpf)
        : capture.openOffline(cli.target, "");

    if (!opened) {
        LOG_ERROR("Failed to open capture source: " + cli.target);
        dispatcher.stop();
        if (run_l2) ml_engine.stop();
        return 1;
    }

    // ── 9. Background threads ─────────────────────────────────────────────────
    std::thread stats_thread  (statsPrinterThread,
                                std::ref(dispatcher),
                                std::ref(ml_engine),
                                std::ref(alert_manager));

    std::thread cleanup_thread(flowCleanupThread, std::ref(dispatcher));

    // ── 10. L2 feeder thread ──────────────────────────────────────────────────
    FeatureExtractor extractor;
    std::thread l2_feeder_thread([&]() {
        if (!run_l2) return;
        // NSL-KDD: jobs được push bởi WorkerThread → chỉ cần wait
        while (g_running)
            std::this_thread::sleep_for(std::chrono::seconds(1));
    });

    // ── 11. Capture loop ──────────────────────────────────────────────────────
    LOG_INFO("Capture loop started → " + cli.target);

    capture.startCapture([&](PacketInfo pkt,
                              const uint8_t* raw_bytes,
                              uint32_t       raw_len) {
        if (!g_running) return;
        pkt.raw_data = std::make_shared<std::vector<uint8_t>>(
                           raw_bytes, raw_bytes + raw_len);
        dispatcher.dispatch(std::move(pkt));
    });

    // ── 12. Shutdown ──────────────────────────────────────────────────────────
    std::cout << "\n\033[1;33m[SHUTDOWN] Stopping...\033[0m\n";
    LOG_INFO("Shutdown sequence started");

    g_running = false;
    capture.stopCapture();

    if (l2_feeder_thread.joinable()) l2_feeder_thread.join();
    if (run_l2) ml_engine.stop();
    dispatcher.stop();
    if (stats_thread.joinable())   stats_thread.join();
    if (cleanup_thread.joinable()) cleanup_thread.join();

    // ── 13. Final report ──────────────────────────────────────────────────────
    std::cout << "\n\033[1;32m"
              << "╔══════════════════════════════════════════════╗\n"
              << "║              FINAL REPORT                    ║\n"
              << "╠══════════════════════════════════════════════╣\n"
              << "║ Captured  : " << std::setw(10) << METRICS.packets_captured.load() << "                ║\n"
              << "║ Dropped   : " << std::setw(10) << METRICS.packets_dropped.load()  << "                ║\n"
              << "║ Passed    : " << std::setw(10) << METRICS.packets_passed.load()   << "                ║\n"
              << "║ Alerts    : " << std::setw(10) << alert_manager.totalAlerts()     << "                ║\n"
              << "╠══════════════════════════════════════════════╣\n"
              << "║ DDoS      : " << std::setw(10) << alert_manager.ddosAlerts()      << "                ║\n"
              << "║ SlowDDoS  : " << std::setw(10) << alert_manager.slowDdosAlerts()  << "                ║\n"
              << "║ PortScan  : " << std::setw(10) << alert_manager.scanAlerts()      << "                ║\n"
              << "╠══════════════════════════════════════════════╣\n"
              << "║ L2 Jobs   : " << std::setw(10) << ml_engine.jobsProcessed()       << "                ║\n"
              << "║ L2 Anomaly: " << std::setw(10) << ml_engine.anomaliesFound()      << "                ║\n"
              << "╚══════════════════════════════════════════════╝\n"
              << "\033[0m\n";

    LOG_INFO("=== System stopped cleanly ==="
             " total_alerts=" + std::to_string(alert_manager.totalAlerts()));
    return 0;
}
