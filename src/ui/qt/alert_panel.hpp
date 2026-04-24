//src/ui/qt/alert_panel.hpp
#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <vector>
#include "ui_bridge.hpp"

class AlertPanel : public QWidget {
    Q_OBJECT

public:
    explicit AlertPanel(QWidget* parent = nullptr);

public slots:
    void onNewAlerts(std::vector<UnifiedAlert> alerts);
    void onClearClicked();

private slots:
    void onFilterChanged(int index);

    void onRowClicked(int row, int col);

private:
    void setupUI();
    void addAlertRow(const UnifiedAlert& alert);
    bool matchesFilter(const UnifiedAlert& alert) const;

    QString threatColor(DetectionResult r) const;
    QString threatIcon (DetectionResult r) const;
    QString sourceTag  (UnifiedAlert::Source s) const;

    QTableWidget* table_;
    QComboBox*    filter_combo_;
    QPushButton*  clear_btn_;
    QLabel*       count_lbl_;

    // Lưu tất cả alerts để filter
    std::vector<UnifiedAlert> all_alerts_;

    static constexpr int MAX_ROWS = 500;
};
