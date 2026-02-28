#include <QApplication>
#include <QSplashScreen>
#include <QPixmap>
#include <QThread>
#include <atomic>
#include <thread>
#include <csignal>
#include <arpa/inet.h>

#include "common/logger.hpp"
#include "common/metrics.hpp"
#include "capture/packet_capture.hpp"
#include "layer1/dispatcher.hpp"
#include "layer2/feature_extractor.hpp"
#include "layer2/data_queue.hpp"
#include "layer2/ml_engine.hpp"
#include "layer2/feedback_loop.hpp"
#include "dashboard/alert_manager.hpp"
#include "ui/qt/main_window.hpp"

// ─── Global state ─────────────────────────────────────────────────────────────
std::atomic<bool>  g_running{true};
PacketCapture*     g_capture_ptr = nullptr;

void signalHandler(int) {
    g_running = false;
    if (g_capture_ptr)
        g_capture_ptr->stopCapture();
}

// ─── Engine thread (chạy song song với Qt) ───────────────────────────────────
void engineThread(const std::string& mode,
                  const std::string& target,
                  Dispatcher&        dispatcher,
                  MLJobQueue&        ml_queue,
                  AlertManager&      alert_manager) {

    FeatureExtractor extractor;
    PacketCapture    capture;
    g_capture_ptr = &capture;

    bool opened = (mode == "-i")
        ? capture.openLive(target, "tcp or udp")
        : capture.openOffline(target, "");

    if (!opened) {
        LOG_ERROR("Engine: Failed to open capture source");
        g_running = false;
        return;
    }

    // L2 feeder
    std::thread l2_feeder([&]() {
        while (g_running) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(500));

            dispatcher.forEachFlow([&](FlowState& flow) {
                if (flow.total_packets < 5) return;
                if (flow.is_malicious)      return;

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

    // Cleanup thread
    std::thread cleanup([&]() {
        while (g_running) {
            for (int i = 0; i < 60 && g_running; i++)
                std::this_thread::sleep_for(std::chrono::seconds(1));
            if (g_running)
                dispatcher.cleanupFlows(300.0);
        }
    });

    // Blocking capture loop
    capture.startCapture([&](PacketInfo pkt) {
        if (g_running)
            dispatcher.dispatch(std::move(pkt));
    });

    g_running = false;
    if (l2_feeder.joinable()) l2_feeder.join();
    if (cleanup.joinable())   cleanup.join();
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    // Qt app phải được tạo trước
    QApplication app(argc, argv);
    app.setApplicationName("Network IDS/IPS");
    app.setOrganizationName("HVKTQS");

    // Signal handlers
    signal(SIGINT,  signalHandler);
    signal(SIGTERM, signalHandler);

    // Logger
    Logger::instance().setLevel(Logger::Level::INFO);
    Logger::instance().setLogFile("ids_ui.log");

    // Parse args
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " -i <interface> | -f <pcap_file> [--mock]\n";
        return 1;
    }

    std::string mode   = argv[1];
    std::string target = argv[2];
    bool use_mock = true;
    for (int i = 3; i < argc; i++)
        if (std::string(argv[i]) == "--no-mock")
            use_mock = false;

    // ── Shared components ─────────────────────────────────────────────────────
    MLJobQueue   ml_queue;
    AlertManager alert_manager(1000);

    // ── Layer 1 ───────────────────────────────────────────────────────────────
    Dispatcher dispatcher(4);
    dispatcher.start([&](const DetectionEvent& event) {
        alert_manager.addL1Alert(event);
    });

    // ── Layer 2 ───────────────────────────────────────────────────────────────
    FeedbackLoop feedback_loop([](const RuleProposal& p) {
        LOG_INFO("Rule update: " + p.detail);
    });

    MLEngine ml_engine(ml_queue, [&](const MLResult& result) {
        alert_manager.addL2Alert(result);
        feedback_loop.onMLResult(result);
    });
    ml_engine.start(use_mock);

    // ── Engine thread (tách khỏi Qt main thread) ──────────────────────────────
    std::thread engine(engineThread,
                       mode, target,
                       std::ref(dispatcher),
                       std::ref(ml_queue),
                       std::ref(alert_manager));

    // ── Qt Main Window ────────────────────────────────────────────────────────
    MainWindow window(alert_manager, dispatcher, ml_engine);
    window.show();

    // Khi Qt app thoát → dừng engine
    QObject::connect(&app, &QApplication::aboutToQuit, [&]() {
        g_running = false;
        if (g_capture_ptr)
            g_capture_ptr->stopCapture();
    });

    int ret = app.exec(); // Blocking — Qt event loop

    // ── Shutdown ──────────────────────────────────────────────────────────────
    g_running = false;
    if (g_capture_ptr) g_capture_ptr->stopCapture();
    if (engine.joinable()) engine.join();

    ml_engine.stop();
    dispatcher.stop();

    return ret;
}
