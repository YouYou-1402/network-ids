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

private:
    void setupUI        ();
    void setupMenuBar   ();
    void setupStatusBar ();
    void applyDarkTheme ();
    void addPcapTab     (const QString& filepath = {});

    // Core
    std::unique_ptr<UiBridge> bridge_;
    QTime                     start_time_;
    bool                      is_running_ { true };

    // Widgets
    QTabWidget*    tab_widget_      { nullptr };
    PcapTab*       live_tab_        { nullptr };
    AlertPanel*    alert_panel_     { nullptr };
    MetricsWidget* metrics_widget_  { nullptr };
    TrafficChart*  traffic_chart_   { nullptr };

    // Status bar
    QLabel* status_running_ { nullptr };
    QLabel* status_pps_     { nullptr };
    QLabel* status_uptime_  { nullptr };

    // Uptime timer
    QTimer uptime_timer_;
};
