#pragma once
#include <QMainWindow>
#include <QSplitter>
#include <QStatusBar>
#include <QLabel>
#include <QAction>
#include <QTimer>
#include <memory>
#include <QTime> 

#include "ui_bridge.hpp"
#include "metrics_widget.hpp"
#include "alert_panel.hpp"
#include "traffic_chart.hpp"

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(AlertManager& alert_manager,
                        Dispatcher&   dispatcher,
                        MLEngine&     ml_engine,
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

    // Core components
    std::unique_ptr<UiBridge> bridge_;

    // Widgets
    MetricsWidget* metrics_widget_;
    AlertPanel*    alert_panel_;
    TrafficChart*  traffic_chart_;

    // Status bar
    QLabel* status_running_;
    QLabel* status_pps_;
    QLabel* status_uptime_;

    // Uptime tracking
    QTimer   uptime_timer_;
    QTime    start_time_;

    // State
    bool     is_running_ = true;
};
