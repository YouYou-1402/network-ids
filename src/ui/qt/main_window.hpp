// ── main_window.hpp ───────────────────────────────────────────────────────────
#pragma once
#include <QMainWindow>
#include <QTabWidget>
#include <QLabel>
#include <QTimer>
#include <QTime>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <memory>
#include <atomic>
#include <thread>
#include <QStatusBar>

// Forward declarations — tránh MOC redefinition
class UiBridge;
class PcapTab;
class AlertPanel;
class MetricsWidget;
class TrafficChart;
class AlertManager;
class Dispatcher;
class MLEngine;
class PacketRingBuffer;
class PacketCapture;
struct MetricsSnapshot;

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
    void onMetricsUpdated     (MetricsSnapshot snapshot);
    void onSystemStatusChanged(bool running);
    void onToggleCapture      ();
    void updateUptime         ();
    void onAbout              ();

    // ── Capture control slots ─────────────────────────────────────────────────
    void onStartCaptureClicked();
    void onStopCaptureClicked ();
    void onSaveCaptureClicked ();

private:
    void setupUI        ();
    void setupMenuBar   ();
    void setupStatusBar ();
    void applyDarkTheme ();
    void addPcapTab     (const QString& filepath = {});

    // ── Capture control ───────────────────────────────────────────────────────
    void startLiveCapture(const QString& iface, const QString& filter);
    void stopLiveCapture ();

    // ── Core ──────────────────────────────────────────────────────────────────
    std::unique_ptr<UiBridge> bridge_;
    QTime                     start_time_;
    bool                      is_running_ { true };

    // ── Capture state ─────────────────────────────────────────────────────────
    std::shared_ptr<PacketCapture> active_capture_;
    std::unique_ptr<std::thread>   capture_thread_;
    std::atomic<bool>              capture_running_ { false };
    QString                        capture_iface_;

    // ── Widgets ───────────────────────────────────────────────────────────────
    QTabWidget*    tab_widget_      { nullptr };
    PcapTab*       live_tab_        { nullptr };
    AlertPanel*    alert_panel_     { nullptr };
    MetricsWidget* metrics_widget_  { nullptr };
    TrafficChart*  traffic_chart_   { nullptr };

    // ── Capture action refs — để enable/disable ───────────────────────────────
    QAction* act_start_cap_ { nullptr };
    QAction* act_stop_cap_  { nullptr };
    QAction* act_save_cap_  { nullptr };

    // ── Status bar ────────────────────────────────────────────────────────────
    QLabel* status_running_  { nullptr };
    QLabel* status_pps_      { nullptr };
    QLabel* status_uptime_   { nullptr };
    QLabel* status_iface_    { nullptr };   // ← hiện interface đang capture

    // ── Uptime timer ──────────────────────────────────────────────────────────
    QTimer uptime_timer_;
};
