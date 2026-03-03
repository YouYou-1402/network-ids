#include <QApplication>
#include <QTimer>
#include <atomic>
#include <thread>
#include <csignal>
#include <arpa/inet.h>

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

// ─── Global state ─────────────────────────────────────────────────────────────
std::atomic<bool>  g_running { true };
PacketCapture*     g_capture_ptr = nullptr;

void signalHandler(int) {
    g_running = false;
    if (g_capture_ptr)
        g_capture_ptr->stopCapture();
}

// ─── Engine thread ────────────────────────────────────────────────────────────
// Toàn bộ blocking I/O nằm ở đây — KHÔNG bao giờ chạy trên main thread
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
    // ✅ Nằm trong thread riêng — không block Qt main thread
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
    // ✅ Block ở đây là OK — đang trong thread riêng
    capture.startCapture([&](PacketInfo pkt) {
        if (!g_running) return;

        dispatcher.dispatch(pkt);

        // Đẩy vào ring buffer cho Qt UI
        PacketRecord rec;
        rec.src_ip      = pkt.src_ip;
        rec.dst_ip      = pkt.dst_ip;
        rec.src_port    = pkt.src_port;
        rec.dst_port    = pkt.dst_port;
        rec.protocol    = pkt.protocol;
        rec.tcp_flags   = pkt.tcp_flags;
        rec.payload_len = pkt.payload_len;
        rec.cap_len     = pkt.pkt_len;
        rec.timestamp   = static_cast<double>(pkt.timestamp.tv_sec)
                        + static_cast<double>(pkt.timestamp.tv_usec) * 1e-6;
        // ✅ Không copy raw_data ở đây — lazy load khi user click
        // rec.raw_data = nullptr;  (default)
        ring_buf.push(std::move(rec));
    });

    // ── Shutdown ──────────────────────────────────────────────────────────────
    g_running = false;
    if (l2_feeder.joinable()) l2_feeder.join();
    if (cleanup.joinable())   cleanup.join();

    LOG_INFO("Engine thread exited cleanly");
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {

    // ✅ QApplication PHẢI là object đầu tiên
    QApplication app(argc, argv);
    app.setApplicationName("Network IDS/IPS");
    app.setOrganizationName("HVKTQS");

    signal(SIGINT,  signalHandler);
    signal(SIGTERM, signalHandler);

    Logger::instance().setLevel(Logger::Level::INFO);
    Logger::instance().setLogFile("ids_ui.log");

    // ── Parse args ────────────────────────────────────────────────────────────
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " -i <interface> | -f <pcap_file>\n";
        return 1;
    }
    const std::string mode   = argv[1];
    const std::string target = argv[2];
    bool use_mock = true;
    for (int i = 3; i < argc; ++i)
        if (std::string(argv[i]) == "--no-mock")
            use_mock = false;

    // ── Khởi tạo các object NHẸ (không block) ────────────────────────────────
    MLJobQueue       ml_queue;
    AlertManager     alert_manager(1000);
    PacketRingBuffer ring_buf(100'000, 65535);

    // Layer 1 — constructor nhẹ, start() chỉ spawn threads
    Dispatcher dispatcher(4);
    dispatcher.start([&](const DetectionEvent& event) {
        alert_manager.addL1Alert(event);
    });

    // Layer 2 — start(use_mock=true) không load ONNX → không block
    FeedbackLoop feedback_loop([](const RuleProposal& p) {
        LOG_INFO("Rule update: " + p.detail);
    });
    MLEngine ml_engine(ml_queue, [&](const MLResult& result) {
        alert_manager.addL2Alert(result);
        feedback_loop.onMLResult(result);
    });
    ml_engine.start(use_mock);

    // ── Tạo và hiện MainWindow ────────────────────────────────────────────────
    // ✅ Tạo TRƯỚC khi start engine thread
    // ✅ show() TRƯỚC khi app.exec() để Qt kịp paint
    MainWindow window(alert_manager, dispatcher, ml_engine, ring_buf);
    window.show();

    // ── Start engine thread SAU khi UI đã hiện ───────────────────────────────
    // ✅ QTimer::singleShot(0) = chạy ngay sau lần đầu event loop tick
    //    → UI đã render xong frame đầu tiên trước khi engine start
    std::thread engine_thread;

    QTimer::singleShot(0, [&]() {
        // ✅ Engine chạy trong std::thread riêng — không block Qt
        engine_thread = std::thread(
            engineThread,
            mode, target,
            std::ref(dispatcher),
            std::ref(ml_queue),
            std::ref(alert_manager),
            std::ref(ring_buf));
    });

    // ── Dừng engine khi Qt thoát ──────────────────────────────────────────────
    QObject::connect(&app, &QApplication::aboutToQuit, [&]() {
        g_running = false;
        if (g_capture_ptr)
            g_capture_ptr->stopCapture();
    });

    // ── Qt event loop (blocking) ──────────────────────────────────────────────
    // ✅ Chạy ngay sau window.show() — UI responsive từ frame đầu tiên
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
