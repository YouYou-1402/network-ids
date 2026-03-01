#pragma once
#include <QMainWindow>
#include <QSplitter>
#include <QStatusBar>
#include <QLabel>
#include <QAction>
#include <QTimer>
#include <QTabWidget>
#include <QPushButton>
#include <memory>
#include <QTime>

#include "ui_bridge.hpp"
#include "metrics_widget.hpp"
#include "alert_panel.hpp"
#include "traffic_chart.hpp"
#include "pcap_tab.hpp"
#include "../../pcap_io/packet_ring_buffer.hpp"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(AlertManager& alert_manager,
                        Dispatcher&   dispatcher,
                        MLEngine&     ml_engine,
                        PacketRingBuffer& ring_buf,
                        QWidget*      parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onMetricsUpdated(MetricsSnapshot snapshot);
    void onSystemStatusChanged(bool running);
    void onToggleCapture();
    void onAbout();
    void updateUptime();

private:
    void setupUI();
    void setupMenuBar();
    void setupStatusBar();
    void applyDarkTheme();
    void addPcapTab(const QString& filepath = "");

    // ── Core bridge ───────────────────────────────────────────────────────────
    std::unique_ptr<UiBridge> bridge_;

    // ── Widgets ───────────────────────────────────────────────────────────────
    MetricsWidget* metrics_widget_;
    TrafficChart*  traffic_chart_;
    AlertPanel*    alert_panel_;

    // ── Tab system ────────────────────────────────────────────────────────────
    QTabWidget*    tab_widget_;
    PcapTab*       live_tab_;

    // ── Status bar ────────────────────────────────────────────────────────────
    QLabel*        status_running_;
    QLabel*        status_pps_;
    QLabel*        status_uptime_;

    // ── State ─────────────────────────────────────────────────────────────────
    QTimer         uptime_timer_;
    QTime          start_time_;
    bool           is_running_ = true;
};
