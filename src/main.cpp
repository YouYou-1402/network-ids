#include <iostream>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>
#include <csignal>
#include <arpa/inet.h>
#include <cstring>

#include "common/logger.hpp"
#include "common/metrics.hpp"
#include "common/threat_types.hpp"
#include "capture/packet_capture.hpp"
#include "layer1/dispatcher.hpp"
#include "layer2/feature_extractor.hpp"
#include "layer2/data_queue.hpp"
#include "layer2/ml_engine.hpp"
#include "layer2/feedback_loop.hpp"
#include "dashboard/alert_manager.hpp"

// ─────────────────────────────────────────────────────────────────────────────
// Global state
// ─────────────────────────────────────────────────────────────────────────────
std::atomic<bool>   g_running{true};
PacketCapture*      g_capture_ptr    = nullptr;  // Dùng trong signal handler
Dispatcher*         g_dispatcher_ptr = nullptr;
MLEngine*           g_ml_engine_ptr  = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
// Signal handler — Ctrl+C / SIGTERM
// ─────────────────────────────────────────────────────────────────────────────
void signalHandler(int sig) {
    // Chỉ dùng async-signal-safe calls trong handler
    const char* msg = "\n[SIGNAL] Shutdown requested. Stopping...\n";
    write(STDOUT_FILENO, msg, strlen(msg));

    g_running = false;

    // Dừng pcap_loop ngay lập tức
    if (g_capture_ptr)
        g_capture_ptr->stopCapture();
}

// ─────────────────────────────────────────────────────────────────────────────
// Terminal output helpers
// ─────────────────────────────────────────────────────────────────────────────
static std::string ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

static std::string alertColor(DetectionResult r) {
    switch (r) {
        case DetectionResult::DDOS_VOLUMETRIC: return "\033[31m";       // Đỏ
        case DetectionResult::SLOW_DDOS:       return "\033[33m";       // Vàng
        case DetectionResult::PORT_SCAN:       return "\033[38;5;208m"; // Cam
        case DetectionResult::MALFORMED:       return "\033[35m";       // Tím
        default:                               return "\033[32m";       // Xanh
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 1 alert callback
// ─────────────────────────────────────────────────────────────────────────────
void onL1Alert(const DetectionEvent& event, AlertManager& alert_manager) {
    alert_manager.addL1Alert(event);

    std::cout << alertColor(event.result)
              << "[L1] "
              << std::left << std::setw(18) << threatToString(event.result)
              << " | " << std::setw(6)  << actionToString(event.action)
              << " | Src: " << std::setw(15) << ipToString(event.src_ip)
              << ":" << std::setw(5)    << event.src_port
              << " | " << event.detail
              << "\033[0m\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer 2 alert callback
// ─────────────────────────────────────────────────────────────────────────────
void onL2Alert(const MLResult& result, AlertManager& alert_manager) {
    alert_manager.addL2Alert(result);

    std::cout << alertColor(result.final_result)
              << "[L2] "
              << std::left << std::setw(18) << threatToString(result.final_result)
              << " | ALERT "
              << " | Src: " << std::setw(15) << ipToString(result.src_ip)
              << ":" << std::setw(5)    << result.src_port
              << " | Conf: " << std::fixed << std::setprecision(2)
              << result.confidence
              << " | " << result.detail
              << "\033[0m\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Background: in thống kê định kỳ
// ─────────────────────────────────────────────────────────────────────────────
void statsPrinterThread(Dispatcher&   dispatcher,
                        MLEngine&     ml_engine,
                        AlertManager& alert_manager) {
    while (g_running) {
        // Sleep ngắn để phản hồi Ctrl+C nhanh hơn
        for (int i = 0; i < 10 && g_running; i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

        if (!g_running) break;

        // In stats
        std::cout << "\n\033[36m"
                  << "╔══════════════════════════════════════╗\n"
                  << "║         SYSTEM METRICS               ║\n"
                  << "╠══════════════════════════════════════╣\n"
                  << "║ Captured  : " << std::setw(10)
                  << METRICS.packets_captured.load()  << "              ║\n"
                  << "║ Dropped   : " << std::setw(10)
                  << METRICS.packets_dropped.load()   << "              ║\n"
                  << "║ Passed    : " << std::setw(10)
                  << METRICS.packets_passed.load()    << "              ║\n"
                  << "║ Alerted   : " << std::setw(10)
                  << METRICS.packets_alerted.load()   << "              ║\n"
                  << "╠══════════════════════════════════════╣\n"
                  << "║ DDoS      : " << std::setw(10)
                  << alert_manager.ddosAlerts()       << "              ║\n"
                  << "║ SlowDDoS  : " << std::setw(10)
                  << alert_manager.slowDdosAlerts()   << "              ║\n"
                  << "║ PortScan  : " << std::setw(10)
                  << alert_manager.scanAlerts()       << "              ║\n"
                  << "╠══════════════════════════════════════╣\n"
                  << "║ ActiveFlow: " << std::setw(10)
                  << dispatcher.activeFlows()         << "              ║\n"
                  << "║ L2 Jobs   : " << std::setw(10)
                  << ml_engine.jobsProcessed()        << "              ║\n"
                  << "║ L2 Anomaly: " << std::setw(10)
                  << ml_engine.anomaliesFound()       << "              ║\n"
                  << "╚══════════════════════════════════════╝\n"
                  << "\033[0m\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Background: dọn dẹp flows idle
// ─────────────────────────────────────────────────────────────────────────────
void flowCleanupThread(Dispatcher& dispatcher) {
    while (g_running) {
        for (int i = 0; i < 60 && g_running; i++)
            std::this_thread::sleep_for(std::chrono::seconds(1));

        if (!g_running) break;
        dispatcher.cleanupFlows(300.0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Print usage
// ─────────────────────────────────────────────────────────────────────────────
void printUsage(const char* prog) {
    std::cout
        << "\n\033[1mNetwork IDS/IPS System — Lab Prototype\033[0m\n"
        << "─────────────────────────────────────────\n"
        << "Usage:\n"
        << "  Live capture  : " << prog << " -i <interface> [--mock]\n"
        << "  Offline pcap  : " << prog << " -f <pcap_file> [--mock]\n"
        << "\nOptions:\n"
        << "  --mock        Use mock ML models (no ONNX required)\n"
        << "  --no-l2       Disable Layer 2 AI/ML engine\n"
        << "  --workers N   Number of worker threads (default: 4)\n"
        << "\nExamples:\n"
        << "  " << prog << " -i eth0 --mock\n"
        << "  " << prog << " -f data/raw/cicids2017.pcap --mock\n"
        << "  " << prog << " -i lo --workers 2 --no-l2\n"
        << "\nPress Ctrl+C to stop.\n\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Parse CLI arguments
// ─────────────────────────────────────────────────────────────────────────────
struct Config {
    std::string mode;           // "-i" hoặc "-f"
    std::string target;         // interface hoặc pcap file
    bool        use_mock  = true;
    bool        enable_l2 = true;
    int         num_workers = 4;
    std::string if_model_path = "models/isolation_forest.onnx";
    std::string ae_model_path = "models/autoencoder.onnx";
};

bool parseArgs(int argc, char* argv[], Config& cfg) {
    if (argc < 3) return false;

    cfg.mode   = argv[1];
    cfg.target = argv[2];

    if (cfg.mode != "-i" && cfg.mode != "-f") return false;

    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--mock")    { cfg.use_mock  = true;  continue; }
        if (arg == "--no-l2")   { cfg.enable_l2 = false; continue; }
        if (arg == "--workers" && i + 1 < argc) {
            cfg.num_workers = std::stoi(argv[++i]);
            continue;
        }
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Print startup banner
// ─────────────────────────────────────────────────────────────────────────────
void printBanner(const Config& cfg) {
    std::cout << "\033[1;34m"
              << "╔══════════════════════════════════════════════╗\n"
              << "║     Network IDS/IPS — AI-Powered System      ║\n"
              << "║     Lab Prototype  |  HVKTQS 2025            ║\n"
              << "╚══════════════════════════════════════════════╝\n"
              << "\033[0m"
              << "  Mode    : " << (cfg.mode == "-i" ? "LIVE" : "OFFLINE")
              << "  →  " << cfg.target << "\n"
              << "  Workers : " << cfg.num_workers << "\n"
              << "  Layer 2 : " << (cfg.enable_l2 ? "ENABLED" : "DISABLED")
              << (cfg.use_mock ? " (MOCK models)" : " (ONNX models)") << "\n"
              << "  Press Ctrl+C to stop.\n"
              << "──────────────────────────────────────────────────\n\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {

    // ── Parse arguments ───────────────────────────────────────────────────────
    Config cfg;
    if (!parseArgs(argc, argv, cfg)) {
        printUsage(argv[0]);
        return 1;
    }

    // ── Signal handlers ───────────────────────────────────────────────────────
    struct sigaction sa{};
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP,  &sa, nullptr);

    // ── Logger ────────────────────────────────────────────────────────────────
    Logger::instance().setLevel(Logger::Level::INFO);
    Logger::instance().setLogFile("ids_system.log");

    printBanner(cfg);
    LOG_INFO("System starting...");

    // ── Shared components ─────────────────────────────────────────────────────
    MLJobQueue   ml_queue;
    AlertManager alert_manager(1000);

    // ── Layer 1: Dispatcher ───────────────────────────────────────────────────
    Dispatcher dispatcher(cfg.num_workers);
    g_dispatcher_ptr = &dispatcher;

    dispatcher.start([&](const DetectionEvent& event) {
        onL1Alert(event, alert_manager);
    });

    LOG_INFO("Layer 1 IPS engine started ("
             + std::to_string(cfg.num_workers) + " workers)");

    // ── Layer 2: ML Engine ────────────────────────────────────────────────────
    // FeedbackLoop: L2 → L1 rule update proposals
    FeedbackLoop feedback_loop([](const RuleProposal& p) {
        LOG_INFO("Rule update applied: " + p.detail);
        // TODO Step 5: kết nối với XDP blacklist updater
    });

    // MLEngine: nhận jobs từ queue, chạy inference
    MLEngine ml_engine(ml_queue, [&](const MLResult& result) {
        onL2Alert(result, alert_manager);
        feedback_loop.onMLResult(result);
    });

    if (cfg.enable_l2) {
        ml_engine.start(cfg.use_mock,
                        cfg.if_model_path,
                        cfg.ae_model_path);
        LOG_INFO("Layer 2 ML engine started");
    } else {
        LOG_INFO("Layer 2 ML engine DISABLED");
    }

    g_ml_engine_ptr = &ml_engine;

    // ── PacketCapture ─────────────────────────────────────────────────────────
    PacketCapture capture;
    g_capture_ptr = &capture;

    bool opened = false;
    if (cfg.mode == "-i") {
        opened = capture.openLive(cfg.target, "tcp or udp");
        LOG_INFO("Live capture on interface: " + cfg.target);
    } else {
        opened = capture.openOffline(cfg.target, "");
        LOG_INFO("Offline capture from file: " + cfg.target);
    }

    if (!opened) {
        LOG_ERROR("Failed to open capture source. Exiting.");
        dispatcher.stop();
        if (cfg.enable_l2) ml_engine.stop();
        return 1;
    }

    // ── Background threads ────────────────────────────────────────────────────
    std::thread stats_thread(
        statsPrinterThread,
        std::ref(dispatcher),
        std::ref(ml_engine),
        std::ref(alert_manager)
    );

    std::thread cleanup_thread(
        flowCleanupThread,
        std::ref(dispatcher)
    );

    // ── Feature extractor (L1 → L2 bridge) ───────────────────────────────────
    // Gửi feature vectors sang L2 queue sau mỗi flow update
    // Trong prototype: gửi định kỳ từ flow table
    FeatureExtractor extractor;

    std::thread l2_feeder_thread([&]() {
        if (!cfg.enable_l2) return;

        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            // Iterate qua tất cả flows, gửi feature vectors sang L2
            dispatcher.forEachFlow([&](FlowState& flow) {
                // Chỉ gửi flows có đủ dữ liệu (> 5 packets)
                if (flow.total_packets < 5) return;

                // Tránh gửi lại flows đã bị đánh dấu là malicious bởi L1
                // (L2 chỉ cần phân tích flows chưa bị phát hiện)
                if (flow.is_malicious) return;

                MLJob job;
                job.features  = extractor.extract(flow);
                job.flow_key  = flow.flow_key;
                job.src_ip    = flow.src_ip;
                job.dst_ip    = flow.dst_ip;
                job.src_port  = flow.src_port;
                job.dst_port  = flow.dst_port;
                job.timestamp = std::chrono::duration<double>(
                    Clock::now().time_since_epoch()).count();

                if (!ml_queue.push(job))
                    METRICS.queue_drops++;
            });
        }
    });

    // ── Packet capture loop (blocking) ────────────────────────────────────────
    LOG_INFO("Capture loop started. Press Ctrl+C to stop.");

    capture.startCapture([&](PacketInfo pkt) {
        if (g_running)
            dispatcher.dispatch(std::move(pkt));
    });

    // ── Shutdown sequence (sau khi pcap_loop trả về) ──────────────────────────
    std::cout << "\n\033[1;33m[SHUTDOWN] Stopping all components...\033[0m\n";
    LOG_INFO("Shutdown sequence started");

    g_running = false;

    // 1. Dừng capture trước
    capture.stopCapture();
    LOG_INFO("PacketCapture stopped");

    // 2. Dừng L2 feeder
    if (l2_feeder_thread.joinable())
        l2_feeder_thread.join();
    LOG_INFO("L2 feeder thread stopped");

    // 3. Dừng ML engine
    if (cfg.enable_l2) {
        ml_engine.stop();
        LOG_INFO("MLEngine stopped");
    }

    // 4. Dừng dispatcher (workers)
    dispatcher.stop();
    LOG_INFO("Dispatcher stopped");

    // 5. Dừng background threads
    if (stats_thread.joinable())   stats_thread.join();
    if (cleanup_thread.joinable()) cleanup_thread.join();

    // ── Final report ──────────────────────────────────────────────────────────
    std::cout << "\n\033[1;32m"
              << "╔══════════════════════════════════════════════╗\n"
              << "║              FINAL REPORT                    ║\n"
              << "╠══════════════════════════════════════════════╣\n"
              << "║ Total captured  : "
              << std::setw(10) << METRICS.packets_captured.load()
              << "                ║\n"
              << "║ Total dropped   : "
              << std::setw(10) << METRICS.packets_dropped.load()
              << "                ║\n"
              << "║ Total passed    : "
              << std::setw(10) << METRICS.packets_passed.load()
              << "                ║\n"
              << "║ Total alerts    : "
              << std::setw(10) << alert_manager.totalAlerts()
              << "                ║\n"
              << "╠══════════════════════════════════════════════╣\n"
              << "║ DDoS detected   : "
              << std::setw(10) << alert_manager.ddosAlerts()
              << "                ║\n"
              << "║ SlowDDoS detect : "
              << std::setw(10) << alert_manager.slowDdosAlerts()
              << "                ║\n"
              << "║ PortScan detect : "
              << std::setw(10) << alert_manager.scanAlerts()
              << "                ║\n"
              << "╠══════════════════════════════════════════════╣\n"
              << "║ L2 jobs processed: "
              << std::setw(9) << ml_engine.jobsProcessed()
              << "                ║\n"
              << "║ L2 anomalies    : "
              << std::setw(10) << ml_engine.anomaliesFound()
              << "                ║\n"
              << "╚══════════════════════════════════════════════╝\n"
              << "\033[0m\n";

    LOG_INFO("=== System stopped cleanly ===");
    return 0;
}
