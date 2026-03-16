// src/ui/qt/main_window.hpp
#pragma once
#include <QMainWindow>
#include <QTabWidget>
#include <QLabel>
#include <QTimer>
#include <QTime>
#include <QAction>
#include <memory>
#include <atomic>
#include <thread>

#include "ui_bridge.hpp"
#include "../../detection/dispatcher.hpp"
#include "../../analysis/alert_manager.hpp"
#include "../../ml/ml_engine.hpp"
#include "../../capture/io/packet_ring_buffer.hpp"

class PcapTab;
class PacketCapture;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(AlertManager&     alert_manager,
                        Dispatcher&       dispatcher,
                        MLEngine&         ml_engine,
                        PacketRingBuffer& ring_buf,
                        QWidget*          parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onStartCaptureClicked();
    void onStopCaptureClicked();
    void onSaveCaptureClicked();
    void onAbout();
    void updateUptime();
    void onDetectionToggled(bool enabled);
    void onMlToggled       (bool enabled);
    void updateIpsModeBadge();

private:
    void setupUI();
    void setupMenuBar();
    void setupStatusBar();
    void applyDarkTheme();
    void addPcapTab(const QString& filepath = {});
    void startLiveCapture(const QString& iface, const QString& filter);
    void stopLiveCapture();

    // ── Backend refs ──────────────────────────────────────────────────────────
    AlertManager&     alert_manager_;
    Dispatcher&       dispatcher_;
    MLEngine&         ml_engine_;
    PacketRingBuffer& ring_buf_;

    // ── UiBridge ──────────────────────────────────────────────────────────────
    std::unique_ptr<UiBridge> ui_bridge_;

    // ── Capture state ─────────────────────────────────────────────────────────
    std::shared_ptr<PacketCapture> active_capture_;
    std::unique_ptr<std::thread>   capture_thread_;
    std::atomic<bool>              capture_running_{ false };
    QString                        capture_iface_;

    // ── Widgets ───────────────────────────────────────────────────────────────
    QTabWidget* tab_widget_  { nullptr };
    PcapTab*    live_tab_    { nullptr };

    // ── Menu actions ──────────────────────────────────────────────────────────
    QAction* act_start_cap_      { nullptr };
    QAction* act_stop_cap_       { nullptr };
    QAction* act_save_cap_       { nullptr };
    QAction* act_toggle_det_     { nullptr };   // IPS menu
    QAction* act_toggle_ml_      { nullptr };   // IPS menu

    // ── Status bar ────────────────────────────────────────────────────────────
    QLabel* status_state_    { nullptr };
    QLabel* status_iface_    { nullptr };
    QLabel* status_uptime_   { nullptr };
    QLabel* status_ips_mode_ { nullptr };   // "IPS" / "IDS" / "MONITOR"

    QTimer  uptime_timer_;
    QTime   start_time_;
};
