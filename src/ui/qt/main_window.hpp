// src/ui/qt/main_window.hpp
#pragma once

#include "../../analysis/alert_manager.hpp"
#include "../../detection/dispatcher.hpp"
#include "../../ml/ml_engine.hpp"
#include "../../capture/io/packet_ring_buffer.hpp"
#include "../../firewall/firewall_manager.hpp"
#include "ui_bridge.hpp"

#include <QMainWindow>
#include <QTabWidget>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QTime>
#include <QAction>
#include <QFrame>
#include <memory>
#include <thread>
#include <atomic>

// Forward declarations — chỉ dùng các file đã có trong src/ui/qt/
class PcapTab;
class FirewallWidget;
class IpsControlWidget;   // ips_control_widget.hpp
class AlertPanel;         // alert_panel.hpp
class MetricsWidget;      // metrics_widget.hpp
class TrafficChart;       // traffic_chart.hpp
class PacketCapture;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(AlertManager&     alert_manager,
                        Dispatcher&       dispatcher,
                        MLEngine&         ml_engine,
                        PacketRingBuffer& ring_buf,
                        FirewallManager*  firewall_manager = nullptr,
                        QWidget*          parent           = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onStartCaptureClicked();
    void onStopCaptureClicked();
    void onSaveCaptureClicked();
    void onClearPacketsClicked();
    void onDetectionToggled(bool enabled);
    void onMlToggled(bool enabled);
    void updateUptime();
    void onAbout();

private:
    // ── Setup ─────────────────────────────────────────────────────────────────
    void     setupUI();
    void     setupMenuBar();
    void     setupFirewallMenu();
    void     setupStatusBar();
    void     applyTheme();

    // ── Tab builders ──────────────────────────────────────────────────────────
    QWidget* buildCaptureToolbar();
    QWidget* buildTab_LiveCapture();
    QWidget* buildTab_FileAnalysis();
    QWidget* buildTab_IPS();
    QWidget* buildTab_Firewall();
    QWidget* buildTab_Statistics();
    QWidget* buildTab_Alerts();

    void     addPcapTab(const QString& filepath = {});
    void     startLiveCapture(const QString& iface, const QString& filter);
    void     stopLiveCapture();
    void     updateIpsModeBadge();
    void     setCaptureRunningState(bool running);

    // ── Core refs ─────────────────────────────────────────────────────────────
    AlertManager&     alert_manager_;
    Dispatcher&       dispatcher_;
    MLEngine&         ml_engine_;
    PacketRingBuffer& ring_buf_;
    FirewallManager*  firewall_manager_ = nullptr;

    std::unique_ptr<UiBridge> ui_bridge_;

    // ── Main tabs ─────────────────────────────────────────────────────────────
    QTabWidget*       tab_widget_       = nullptr;

    // Tab 1 — Live Capture
    PcapTab*          live_tab_         = nullptr;

    // Tab 2 — File Analysis (inner tab widget)
    QTabWidget*       file_tab_widget_  = nullptr;

    // Tab 3 — IPS/Detection
    IpsControlWidget* ips_widget_       = nullptr;
    AlertPanel*       alert_panel_ips_  = nullptr;   // alert feed trong IPS tab

    // Tab 4 — Firewall
    FirewallWidget*   firewall_tab_     = nullptr;

    // Tab 5 — Statistics
    TrafficChart*     traffic_chart_    = nullptr;
    MetricsWidget*    metrics_widget_   = nullptr;


    // ── Toolbar widgets ───────────────────────────────────────────────────────
    QPushButton*      btn_start_cap_    = nullptr;
    QPushButton*      btn_stop_cap_     = nullptr;
    QPushButton*      btn_save_cap_     = nullptr;
    QPushButton* btn_clear_packets_     = nullptr;
    QLabel*           lbl_iface_        = nullptr;
    QLabel*           lbl_ips_badge_    = nullptr;   // toolbar IPS badge
    QLabel*           lbl_fw_badge_     = nullptr;   // toolbar FW badge

    // ── StatusBar widgets ─────────────────────────────────────────────────────
    QLabel*           status_state_     = nullptr;
    QLabel*           status_iface_     = nullptr;
    QLabel*           status_ips_mode_  = nullptr;
    QLabel*           status_fw_badge_  = nullptr;
    QLabel*           status_uptime_    = nullptr;

    // ── Menu actions ──────────────────────────────────────────────────────────
    QAction*          act_start_cap_    = nullptr;
    QAction*          act_stop_cap_     = nullptr;
    QAction*          act_save_cap_     = nullptr;
    QAction*          act_toggle_det_   = nullptr;
    QAction*          act_toggle_ml_    = nullptr;
    QAction*          act_fw_block_     = nullptr;
    QAction*          act_fw_unblock_   = nullptr;
    QAction*          act_fw_save_      = nullptr;
    QAction*         act_clear_packets_ = nullptr;

    // ── Capture state ─────────────────────────────────────────────────────────
    std::atomic<bool>              capture_running_ {false};
    QString                        capture_iface_;
    std::shared_ptr<PacketCapture> active_capture_;
    std::unique_ptr<std::thread>   capture_thread_;

    // ── Uptime ────────────────────────────────────────────────────────────────
    QTimer  uptime_timer_;
    QTime   start_time_;
};
