// src/ui_main.cpp
#include <QApplication>
#include <QTimer>
#include <atomic>
#include <thread>
#include <chrono>
#include <csignal>
#include <arpa/inet.h>
#include <iomanip>
#include <unistd.h>

#include "common/logger.hpp"
#include "common/metrics.hpp"
#include "common/packet_info.hpp"
#include "capture/packet_capture.hpp"
#include "layer1/dispatcher.hpp"
#include "layer2/feature_extractor.hpp"
#include "layer2/data_queue.hpp"
#include "layer2/ml_engine.hpp"
#include "layer2/feedback_loop.hpp"
#include "dashboard/alert_manager.hpp"
#include "ui/qt/main_window.hpp"
#include "pcap_io/packet_ring_buffer.hpp"

// ─────────────────────────────────────────────────────────────────────────────
// Global state
// ─────────────────────────────────────────────────────────────────────────────
std::atomic<bool>  g_running { true };
PacketCapture*     g_capture_ptr = nullptr;

void signalHandler(int) {
    g_running = false;
    if (g_capture_ptr)
        g_capture_ptr->stopCapture();
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine thread — chỉ chạy khi UI gọi startEngineCapture()
// ─────────────────────────────────────────────────────────────────────────────
void engineThread(const std::string& mode,
                  const std::string& target,
                  Dispatcher&        dispatcher,
                  MLJobQueue&        ml_queue,
                  AlertManager&      alert_manager,
                  PacketRingBuffer&  ring_buf)
{
    FeatureExtractor extractor;
    PacketCapture    capture;
    g_capture_ptr = &capture;

    // ── Mở capture source ────────────────────────────────────────────────────
    const bool opened = (mode == "-i")
        ? capture.openLive(target, "tcp or udp")
        : capture.openOffline(target, "");

    if (!opened) {
        LOG_ERROR("Engine: Failed to open capture source: " + target);
        g_running = false;
        return;
    }
    LOG_INFO("Engine: capture opened → " + target);

    // ── L2 feeder thread ─────────────────────────────────────────────────────
    std::thread l2_feeder([&]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
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

    // ── Flow cleanup thread ───────────────────────────────────────────────────
    std::thread cleanup([&]() {
        while (g_running) {
            for (int i = 0; i < 60 && g_running; ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));
            if (g_running)
                dispatcher.cleanupFlows(300.0);
        }
    });

    // ── Blocking capture loop ─────────────────────────────────────────────────
    capture.startCapture([&](PacketInfo pkt) {
        if (!g_running) return;
        dispatcher.dispatch(std::move(pkt));
    });

    // ── Shutdown ──────────────────────────────────────────────────────────────
    g_running = false;
    if (l2_feeder.joinable()) l2_feeder.join();
    if (cleanup.joinable())   cleanup.join();
    LOG_INFO("Engine thread exited cleanly");
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {

    // ✅ QApplication PHẢI là object đầu tiên
    QApplication app(argc, argv);
    app.setApplicationName("Network IDS/IPS");
    app.setOrganizationName("HVKTQS");

    signal(SIGINT,  signalHandler);
    signal(SIGTERM, signalHandler);

    Logger::instance().setLevel(Logger::Level::INFO);
    Logger::instance().setLogFile("ids_ui.log");

    // ── Parse args — tất cả OPTIONAL ─────────────────────────────────────────
    // Có thể chạy không cần arg:  ./network_ids_ui
    // Hoặc truyền sẵn:            ./network_ids_ui -i eth0
    //                              ./network_ids_ui -f traffic.pcap
    std::string mode;
    std::string target;
    bool        use_mock    = true;
    bool        auto_start  = false;   // true nếu truyền arg từ CLI

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if ((arg == "-i" || arg == "-f") && i + 1 < argc) {
            mode       = arg;
            target     = argv[++i];
            auto_start = true;
        } else if (arg == "--no-mock") {
            use_mock = false;
        }
        // arg không nhận ra → bỏ qua (không crash)
    }

    // ── Khởi tạo shared objects ───────────────────────────────────────────────
    MLJobQueue       ml_queue;
    AlertManager     alert_manager(1000);
    PacketRingBuffer ring_buf(100'000, 65'535);

    // ── Layer 1 ───────────────────────────────────────────────────────────────
    Dispatcher dispatcher(4, ring_buf);
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

    // ── MainWindow ────────────────────────────────────────────────────────────
    MainWindow window(alert_manager, dispatcher, ml_engine, ring_buf);
    window.show();

    // ── Engine thread handle ──────────────────────────────────────────────────
    std::thread engine_thread;

    // ── Hàm start engine — dùng cho cả auto_start và UI-triggered ────────────
    auto startEngine = [&](const std::string& m, const std::string& t) {
        if (engine_thread.joinable()) return;   // đang chạy rồi
        g_running = true;
        engine_thread = std::thread(
            engineThread,
            m, t,
            std::ref(dispatcher),
            std::ref(ml_queue),
            std::ref(alert_manager),
            std::ref(ring_buf));
    };

    // ── Nếu truyền arg CLI → auto start sau frame đầu tiên ───────────────────
    if (auto_start) {
        QTimer::singleShot(0, [&]() {
            startEngine(mode, target);
        });
    }
    // ── Nếu KHÔNG có arg → UI idle, chờ user bấm "Start Capture" ─────────────
    // MainWindow::startLiveCapture() tự mở PacketCapture riêng (đã có sẵn)
    // engine_thread ở đây chỉ dùng khi muốn route qua IDS engine

    // ── Qt aboutToQuit ────────────────────────────────────────────────────────
    QObject::connect(&app, &QApplication::aboutToQuit, [&]() {
        g_running = false;
        if (g_capture_ptr)
            g_capture_ptr->stopCapture();
    });

    // ── Qt event loop (blocking) ──────────────────────────────────────────────
    const int ret = app.exec();

    // ── Shutdown ──────────────────────────────────────────────────────────────
    g_running = false;
    if (g_capture_ptr)
        g_capture_ptr->stopCapture();

    if (engine_thread.joinable())
        engine_thread.join();

    ml_engine.stop();
    dispatcher.stop();

    return ret;
}
