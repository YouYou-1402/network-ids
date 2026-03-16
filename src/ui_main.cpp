#include "ui/qt/main_window.hpp"
#include "analysis/alert_manager.hpp"
#include "detection/dispatcher.hpp"
#include "ml/ml_engine.hpp"
#include "ml/data_queue.hpp"
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

    Logger::instance().setLevel(Logger::Level::INFO);
    Logger::instance().setLogFile("ids_ui.log");

    // ── Backend components (dependency order) ─────────────────────────────────
    //
    //  capture callback
    //       │ raw_bytes → copy → pkt.raw_data
    //       │ disk write → pkt.file_offset
    //       ▼
    //  ring_buf.push(pkt)          ← detection đọc raw_data
    //       │
    //       ▼
    //  Dispatcher → WorkerThread → AlertManager
    //       │
    //       ▼
    //  MLJobQueue → MLEngine → AlertManager
    //
    //  UiBridge polls ring_buf → emit newPacketInfos (metadata only)
    //  PcapTab lazy-load raw_data từ disk khi click
    // ─────────────────────────────────────────────────────────────────────────

    // ring_buf: 65536 slots — detection dùng raw_data, UI chỉ đọc metadata
    PacketRingBuffer ring_buf(65536);

    AlertManager alert_manager(1000);

    MLJobQueue ml_job_queue;

    MLEngine ml_engine(
        ml_job_queue,
        [&alert_manager](const MLResult& r) {
            alert_manager.addL2Alert(r);
        }
    );
    ml_engine.start();   // use_mock=true

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
