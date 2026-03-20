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
    LOG_INFO("=== Network IDS/IPS UI started ==="
             " euid=" + std::to_string(::geteuid()));

    // ── Kiểm tra quyền root ───────────────────────────────────────────────────
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

    // ─────────────────────────────────────────────────────────────────────────
    // BACKEND COMPONENTS — thứ tự khởi tạo quan trọng:
    //   1. ring_buf          — shared memory capture ↔ workers
    //   2. alert_manager     — nhận alert từ L1 và L2
    //   3. ml_job_queue      — channel L1 → L2 (WorkerThread → MLEngine)
    //   4. firewall_manager  — kernel rule backend (cần trước FeedbackLoop)
    //   5. feedback_loop     — nhận MLResult → tạo RuleProposal
    //   6. ml_engine         — inference thread L2
    //   7. dispatcher        — worker threads L1 (inject ml_job_queue)
    // ─────────────────────────────────────────────────────────────────────────

    // ── 1. Ring buffer ────────────────────────────────────────────────────────
    PacketRingBuffer ring_buf(65536);

    // ── 2. Alert Manager ──────────────────────────────────────────────────────
    AlertManager alert_manager(1000);
    alert_manager.setAlertLogFile(log_dir + "/alert.log");

    // ── 3. ML Job Queue ───────────────────────────────────────────────────────
    // Channel bất đồng bộ: WorkerThread (×4 producers) → MLEngine (1 consumer)
    // Capacity 4096 đủ cho lab (5K–10K pps, sampling 1/50 packets)
    MLJobQueue ml_job_queue;

    // ── 4. Firewall Manager ───────────────────────────────────────────────────
    std::unique_ptr<FirewallManager> firewall_manager;

    if (is_root) {
        firewall_manager = std::make_unique<FirewallManager>(true); // thử nftables trước
        LOG_INFO("FirewallManager backend: " + firewall_manager->backendName());
    } else {
        firewall_manager =
            std::make_unique<FirewallManager>(FirewallManager::InMemoryTag{});
        LOG_INFO("FirewallManager: in-memory mode (no root)");
    }

    const std::string config_dir    = "/media/linhlinh/learn/nckh/network-ids/config";
    const std::string fw_rules_path = config_dir + "/firewall_rules.json";
    std::filesystem::create_directories(config_dir);

    if (std::filesystem::exists(fw_rules_path)) {
        firewall_manager->loadRules(fw_rules_path);
        LOG_INFO("Firewall rules loaded: BL="
                 + std::to_string(firewall_manager->blacklistSize())
                 + " WL=" + std::to_string(firewall_manager->whitelistSize()));
    }

    // ── 5. Feedback Loop ──────────────────────────────────────────────────────
    //
    //  Nhận MLResult → tạo RuleProposal → callback xử lý:
    //    ADD_TO_BLACKLIST   → autoBlock() ngay (high confidence ≥ 0.85)
    //    REDUCE_TIMEOUT     → log, pending admin review
    //    INCREASE_RATE_LIMIT→ log, pending admin review
    //    ADD_SIGNATURE      → log, pending admin review
    // ─────────────────────────────────────────────────────────────────────────
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
                    // TODO: thêm runtime config API vào ProtocolAnomalyEngine
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

    // ── 6. ML Engine ──────────────────────────────────────────────────────────
    //
    //  on_ml_alert callback:
    //    a. addL2Alert()   → AlertManager → UI hiển thị
    //    b. onMLResult()   → FeedbackLoop → có thể tạo rule mới
    // ─────────────────────────────────────────────────────────────────────────
    MLEngine ml_engine(
        ml_job_queue,
        [&alert_manager, &feedback_loop](const MLResult& r) {
            alert_manager.addL2Alert(r);      // a. Gửi alert lên UI
            feedback_loop.onMLResult(r);      // b. Feedback loop
        });

    // use_mock=true: dùng mock models (không cần ONNX Runtime)
    // Để dùng model thật: ml_engine.start(false, "path/if.onnx", "path/ae.onnx")
    ml_engine.start(/*use_mock=*/true);

    // ── 7. Dispatcher ─────────────────────────────────────────────────────────
    // Truyền &ml_job_queue → Dispatcher → WorkerThread (×4)
    // Mỗi WorkerThread push MLJob sau khi xử lý packet (sampling 1/10/50/200)
    Dispatcher dispatcher(4, ring_buf, &ml_job_queue);
    dispatcher.setFirewallManager(firewall_manager.get());
    dispatcher.start([&alert_manager](const DetectionEvent& ev) {
        alert_manager.addL1Alert(ev);
    });

    LOG_INFO("=== All components started ==="
             " ring_buf=65536 workers=4"
             " ml=ON(mock) feedback_loop=ON"
             " firewall=" + firewall_manager->backendName()
             + " root=" + (is_root ? "yes" : "no"));

    // ── UI ────────────────────────────────────────────────────────────────────
    MainWindow window(
        alert_manager,
        dispatcher,
        ml_engine,
        ring_buf,
        firewall_manager.get());
    window.show();

    const int ret = app.exec();

    // ── Shutdown ──────────────────────────────────────────────────────────────
    LOG_INFO("=== Shutting down ==="
             " ml_jobs_processed=" + std::to_string(ml_engine.jobsProcessed())
             + " anomalies="        + std::to_string(ml_engine.anomaliesFound())
             + " pending_proposals=" + std::to_string(feedback_loop.pendingCount()));

    dispatcher.stop();
    ml_engine.stop();

    // Auto-save firewall rules khi thoát
    if (firewall_manager->blacklistSize() + firewall_manager->whitelistSize() > 0) {
        if (firewall_manager->saveRules(fw_rules_path))
            LOG_INFO("Firewall rules auto-saved → " + fw_rules_path);
    }

    LOG_INFO("=== Shutdown complete ===");
    return ret;
}
