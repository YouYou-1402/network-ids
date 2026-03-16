// src/ui/qt/ips_control_widget.cpp
#include "ips_control_widget.hpp"

IpsControlWidget::IpsControlWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
}

// ─── setupUI ──────────────────────────────────────────────────────────────────
void IpsControlWidget::setupUI() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(6);
    root->setContentsMargins(8, 6, 8, 8);

    // ── Header + Mode badge ───────────────────────────────────────────────────
    lbl_mode_badge_ = new QLabel("🛡️  IPS — Full Protection", this);
    lbl_mode_badge_->setAlignment(Qt::AlignCenter);
    lbl_mode_badge_->setFixedHeight(30);
    lbl_mode_badge_->setStyleSheet(
        "QLabel { background: #0d2a0d; color: #00ff88; "
        "font-size: 11px; font-weight: bold; "
        "border: 1px solid #1a5a1a; border-radius: 5px; "
        "padding: 2px 4px; }");
    root->addWidget(lbl_mode_badge_);

    // ── Helper: engine row compact ────────────────────────────────────────────
    const QString group_style =
        "QGroupBox { color: #8888aa; font-size: 10px; font-weight: bold; "
        "border: 1px solid #2a2a3e; border-radius: 5px; "
        "margin-top: 6px; padding-top: 2px; background: #0d0d1a; }"
        "QGroupBox::title { subcontrol-origin: margin; "
        "left: 8px; padding: 0 4px; }";

    auto makeEngineRow = [&](const QString& title,
                              const QString& desc,
                              QLabel*&       status_lbl,
                              QPushButton*&  toggle_btn,
                              QLabel*&       desc_lbl) -> QGroupBox*
    {
        auto* box    = new QGroupBox(title, this);
        box->setStyleSheet(group_style);
        auto* layout = new QVBoxLayout(box);
        layout->setSpacing(4);
        layout->setContentsMargins(8, 10, 8, 8);

        // Row: status dot + label + toggle button
        auto* row    = new QWidget(box);
        auto* row_ly = new QHBoxLayout(row);
        row_ly->setContentsMargins(0, 0, 0, 0);
        row_ly->setSpacing(6);

        status_lbl = new QLabel("● ACTIVE", row);
        status_lbl->setStyleSheet(
            "color: #00ff88; font-weight: bold; font-size: 11px;");

        toggle_btn = new QPushButton("Disable", row);
        toggle_btn->setFixedSize(64, 22);
        toggle_btn->setStyleSheet(
            "QPushButton { background: #2a1010; color: #ff6666; "
            "border: 1px solid #553333; border-radius: 3px; "
            "font-size: 10px; font-weight: bold; }"
            "QPushButton:hover { background: #3a1818; }");

        row_ly->addWidget(status_lbl);
        row_ly->addStretch();
        row_ly->addWidget(toggle_btn);
        layout->addWidget(row);

        // Description
        desc_lbl = new QLabel(desc, box);
        desc_lbl->setWordWrap(true);
        desc_lbl->setStyleSheet(
            "color: #555577; font-size: 9px; padding: 0;");
        layout->addWidget(desc_lbl);

        return box;
    };

    // ── Detection Engine ──────────────────────────────────────────────────────
    auto* det_box = makeEngineRow(
        "🔍 Detection (L1)",
        "Signature · Protocol Anomaly · Behavioral",
        lbl_det_status_, btn_det_toggle_, lbl_det_desc_);
    root->addWidget(det_box);

    // ── ML Engine ─────────────────────────────────────────────────────────────
    auto* ml_box = makeEngineRow(
        "🤖 ML Engine (L2)",
        "Isolation Forest · Autoencoder",
        lbl_ml_status_, btn_ml_toggle_, lbl_ml_desc_);
    root->addWidget(ml_box);

    // ── Quick Actions ─────────────────────────────────────────────────────────
    auto* qa_group  = new QGroupBox("⚡ Quick Actions", this);
    qa_group->setStyleSheet(group_style);
    auto* qa_layout = new QHBoxLayout(qa_group);
    qa_layout->setSpacing(6);
    qa_layout->setContentsMargins(8, 10, 8, 8);

    auto* btn_enable_all = new QPushButton("✅ Enable All", qa_group);
    btn_enable_all->setFixedHeight(24);
    btn_enable_all->setStyleSheet(
        "QPushButton { background: #0d2a0d; color: #00ff88; "
        "border: 1px solid #1a5a1a; border-radius: 3px; font-size: 10px; }"
        "QPushButton:hover { background: #1a3a1a; }");

    auto* btn_disable_all = new QPushButton("⛔ Disable All", qa_group);
    btn_disable_all->setFixedHeight(24);
    btn_disable_all->setStyleSheet(
        "QPushButton { background: #2a0d0d; color: #ff4444; "
        "border: 1px solid #5a1a1a; border-radius: 3px; font-size: 10px; }"
        "QPushButton:hover { background: #3a1a1a; }");

    qa_layout->addWidget(btn_enable_all);
    qa_layout->addWidget(btn_disable_all);
    root->addWidget(qa_group);

    // ── Connections ───────────────────────────────────────────────────────────
    connect(btn_det_toggle_, &QPushButton::clicked,
            this, &IpsControlWidget::onDetectionBtnClicked);
    connect(btn_ml_toggle_,  &QPushButton::clicked,
            this, &IpsControlWidget::onMlBtnClicked);

    connect(btn_enable_all, &QPushButton::clicked, this, [this]() {
        if (!det_enabled_) onDetectionBtnClicked();
        if (!ml_enabled_)  onMlBtnClicked();
    });
    connect(btn_disable_all, &QPushButton::clicked, this, [this]() {
        if (det_enabled_)  onDetectionBtnClicked();
        if (ml_enabled_)   onMlBtnClicked();
    });
}
// ─── Slots từ button ──────────────────────────────────────────────────────────
void IpsControlWidget::onDetectionBtnClicked() {
    emit toggleDetection(!det_enabled_);
}

void IpsControlWidget::onMlBtnClicked() {
    emit toggleMl(!ml_enabled_);
}

// ─── Slots từ UiBridge ────────────────────────────────────────────────────────
void IpsControlWidget::onDetectionStatusChanged(bool enabled) {
    det_enabled_ = enabled;
    setDetectionUI(enabled);
    updateModeBadge();
}

void IpsControlWidget::onMlStatusChanged(bool enabled) {
    ml_enabled_ = enabled;
    setMlUI(enabled);
    updateModeBadge();
}

// ─── syncState — gọi khi khởi tạo ────────────────────────────────────────────
void IpsControlWidget::syncState(bool detection_enabled, bool ml_enabled) {
    det_enabled_ = detection_enabled;
    ml_enabled_  = ml_enabled;
    setDetectionUI(detection_enabled);
    setMlUI(ml_enabled);
    updateModeBadge();
}

// ─── UI update helpers ────────────────────────────────────────────────────────
void IpsControlWidget::setDetectionUI(bool enabled) {
    if (enabled) {
        lbl_det_status_->setText("● ACTIVE");
        lbl_det_status_->setStyleSheet(
            "color: #00ff88; font-weight: bold; font-size: 12px;");
        btn_det_toggle_->setText("Disable");
        btn_det_toggle_->setStyleSheet(
            "QPushButton { background: #3a1a1a; color: #ff6666; "
            "border: 1px solid #664444; border-radius: 4px; "
            "font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: #4a2a2a; }");
    } else {
        lbl_det_status_->setText("○ DISABLED");
        lbl_det_status_->setStyleSheet(
            "color: #666666; font-weight: bold; font-size: 12px;");
        btn_det_toggle_->setText("Enable");
        btn_det_toggle_->setStyleSheet(
            "QPushButton { background: #1a3a1a; color: #00ff88; "
            "border: 1px solid #336633; border-radius: 4px; "
            "font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: #2a4a2a; }");
    }
}

void IpsControlWidget::setMlUI(bool enabled) {
    if (enabled) {
        lbl_ml_status_->setText("● ACTIVE");
        lbl_ml_status_->setStyleSheet(
            "color: #00ff88; font-weight: bold; font-size: 12px;");
        btn_ml_toggle_->setText("Disable");
        btn_ml_toggle_->setStyleSheet(
            "QPushButton { background: #3a1a1a; color: #ff6666; "
            "border: 1px solid #664444; border-radius: 4px; "
            "font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: #4a2a2a; }");
    } else {
        lbl_ml_status_->setText("○ DISABLED");
        lbl_ml_status_->setStyleSheet(
            "color: #666666; font-weight: bold; font-size: 12px;");
        btn_ml_toggle_->setText("Enable");
        btn_ml_toggle_->setStyleSheet(
            "QPushButton { background: #1a3a1a; color: #00ff88; "
            "border: 1px solid #336633; border-radius: 4px; "
            "font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: #2a4a2a; }");
    }
}

void IpsControlWidget::updateModeBadge() {
    if (det_enabled_ && ml_enabled_) {
        lbl_mode_badge_->setText("🛡️  IPS MODE  —  Full Protection");
        lbl_mode_badge_->setStyleSheet(
            "QLabel { background: #1a3a1a; color: #00ff88; "
            "font-size: 13px; font-weight: bold; "
            "border: 1px solid #00aa55; border-radius: 6px; "
            "padding: 4px; }");
    } else if (det_enabled_ && !ml_enabled_) {
        lbl_mode_badge_->setText("🔍  IDS MODE  —  L1 Detection Only");
        lbl_mode_badge_->setStyleSheet(
            "QLabel { background: #1a2a3a; color: #44aaff; "
            "font-size: 13px; font-weight: bold; "
            "border: 1px solid #2266aa; border-radius: 6px; "
            "padding: 4px; }");
    } else if (!det_enabled_ && ml_enabled_) {
        lbl_mode_badge_->setText("🤖  ML ONLY  —  L2 Detection Only");
        lbl_mode_badge_->setStyleSheet(
            "QLabel { background: #2a1a3a; color: #aa66ff; "
            "font-size: 13px; font-weight: bold; "
            "border: 1px solid #6633aa; border-radius: 6px; "
            "padding: 4px; }");
    } else {
        lbl_mode_badge_->setText("⛔  MONITOR ONLY  —  No Detection");
        lbl_mode_badge_->setStyleSheet(
            "QLabel { background: #2a2a2a; color: #888888; "
            "font-size: 13px; font-weight: bold; "
            "border: 1px solid #555555; border-radius: 6px; "
            "padding: 4px; }");
    }
}
