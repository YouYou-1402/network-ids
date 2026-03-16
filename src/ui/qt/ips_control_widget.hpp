// src/ui/qt/ips_control_widget.hpp
#pragma once
#include <QWidget>
#include <QGroupBox>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include "ui_bridge.hpp"

// ─── IpsControlWidget ─────────────────────────────────────────────────────────
//
//  Panel bật/tắt Detection Engine và ML Engine
//  Hiển thị trạng thái real-time (ACTIVE / DISABLED)
//
//  Signals → UiBridge slots:
//    toggleDetection → UiBridge::setDetectionEnabled()
//    toggleMl        → UiBridge::setMlEnabled()
//
//  UiBridge signals → slots:
//    detectionStatusChanged → onDetectionStatusChanged()
//    mlStatusChanged        → onMlStatusChanged()
// ─────────────────────────────────────────────────────────────────────────────
class IpsControlWidget : public QWidget {
    Q_OBJECT

public:
    explicit IpsControlWidget(QWidget* parent = nullptr);

    void syncState(bool detection_enabled, bool ml_enabled);

signals:
    void toggleDetection(bool enabled);
    void toggleMl       (bool enabled);

public slots:
    void onDetectionStatusChanged(bool enabled);
    void onMlStatusChanged       (bool enabled);

private slots:
    void onDetectionBtnClicked();
    void onMlBtnClicked();

private:
    void setupUI();
    void setDetectionUI(bool enabled);
    void setMlUI       (bool enabled);
    void updateModeBadge();
    
    // ── Detection Engine row ──────────────────────────────────────────────────
    QLabel*      lbl_det_status_;   // "● ACTIVE" / "○ DISABLED"
    QPushButton* btn_det_toggle_;   // "Disable" / "Enable"
    QLabel*      lbl_det_desc_;

    // ── ML Engine row ─────────────────────────────────────────────────────────
    QLabel*      lbl_ml_status_;
    QPushButton* btn_ml_toggle_;
    QLabel*      lbl_ml_desc_;

    // ── Summary badge ─────────────────────────────────────────────────────────
    QLabel*      lbl_mode_badge_;   // "IPS MODE" / "IDS MODE" / "MONITOR"

    bool det_enabled_ = true;
    bool ml_enabled_  = true;
};
