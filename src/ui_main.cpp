// src/ui_main.cpp
#include "ui/qt/main_window.hpp"
#include "analysis/alert_manager.hpp"
#include "detection/dispatcher.hpp"
#include "ml/ml_engine.hpp"
#include "ml/data_queue.hpp"              // MLJobQueue = RingBuffer<MLJob,4096>
#include "capture/io/packet_ring_buffer.hpp"
#include "common/logger.hpp"
#include "common/engine_config.hpp"

#include <QApplication>
#include <csignal>
#include <memory>

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

    // ── Thứ tự khởi tạo (dependency order) ───────────────────────────────────
    //
    //  ring_buf  ──────────────────────────────► Dispatcher
    //                                                │ addL1Alert()
    //  alert_manager ◄─────────────────────────────┘
    //       ▲                                        │ push MLJob
    //       │ addL2Alert()                           ▼
    //  ml_engine ◄──── ml_job_queue ◄──────── Dispatcher (nếu có)
    //
    // ─────────────────────────────────────────────────────────────────────────

    PacketRingBuffer ring_buf(65536);

    AlertManager alert_manager(1000);

    // MLJobQueue: bridge giữa Dispatcher (producer) và MLEngine (consumer)
    // RingBuffer<MLJob,4096> — không có constructor args
    MLJobQueue ml_job_queue;

    // MLEngine: constructor(MLJobQueue&, MLAlertCallback)
    MLEngine ml_engine(
        ml_job_queue,
        [&alert_manager](const MLResult& r) {
            alert_manager.addL2Alert(r);
        }
    );
    ml_engine.start();   // use_mock=true, không cần model path

    // Dispatcher: constructor(int workers, PacketRingBuffer&)
    // Nếu Dispatcher cũng nhận MLJobQueue& → cần truyền thêm ml_job_queue
    // (xác nhận sau khi có dispatcher.hpp)
    Dispatcher dispatcher(4, ring_buf);
    dispatcher.start([&alert_manager](const DetectionEvent& ev) {
        alert_manager.addL1Alert(ev);
    });

    LOG_INFO("Backend initialized: ring_buf=65536, workers=4, ml=enabled");

    // ── UI ────────────────────────────────────────────────────────────────────
    MainWindow window(alert_manager, dispatcher, ml_engine, ring_buf);
    window.show();

    const int ret = app.exec();

    // ── Cleanup (ngược thứ tự khởi tạo) ──────────────────────────────────────
    dispatcher.stop();
    ml_engine.stop();
    LOG_INFO("Shutdown complete");

    return ret;
}
