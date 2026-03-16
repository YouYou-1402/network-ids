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
    root->setSpacing(8);
    root->setContentsMargins(8, 8, 8, 8);

    // ── Mode badge ────────────────────────────────────────────────────────────
    lbl_mode_badge_ = new QLabel("🛡️  IPS MODE", this);
    lbl_mode_badge_->setAlignment(Qt::AlignCenter);
    lbl_mode_badge_->setFixedHeight(36);
    lbl_mode_badge_->setStyleSheet(
        "QLabel { background: #1a3a1a; color: #00ff88; "
        "font-size: 14px; font-weight: bold; "
        "border: 1px solid #00aa55; border-radius: 6px; "
        "padding: 4px; }");
    root->addWidget(lbl_mode_badge_);

    // ── Helper: tạo engine row ────────────────────────────────────────────────
    auto makeEngineRow = [&](const QString& title,
                              const QString& desc,
                              QLabel*&       status_lbl,
                              QPushButton*&  toggle_btn,
                              QLabel*&       desc_lbl) -> QGroupBox*
    {
        auto* box    = new QGroupBox(title, this);
        auto* layout = new QVBoxLayout(box);
        layout->setSpacing(6);
        layout->setContentsMargins(10, 12, 10, 10);

        // Row 1: status + toggle button
        auto* row1    = new QWidget(box);
        auto* row1_ly = new QHBoxLayout(row1);
        row1_ly->setContentsMargins(0, 0, 0, 0);

        status_lbl = new QLabel("● ACTIVE", row1);
        status_lbl->setStyleSheet(
            "color: #00ff88; font-weight: bold; font-size: 12px;");

        toggle_btn = new QPushButton("Disable", row1);
        toggle_btn->setFixedWidth(80);
        toggle_btn->setFixedHeight(26);
        toggle_btn->setStyleSheet(
            "QPushButton { background: #3a1a1a; color: #ff6666; "
            "border: 1px solid #664444; border-radius: 4px; "
            "font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: #4a2a2a; }");

        row1_ly->addWidget(status_lbl);
        row1_ly->addStretch();
        row1_ly->addWidget(toggle_btn);
        layout->addWidget(row1);

        // Row 2: description
        desc_lbl = new QLabel(desc, box);
        desc_lbl->setWordWrap(true);
        desc_lbl->setStyleSheet(
            "color: #666688; font-size: 10px; "
            "padding: 2px 0;");
        layout->addWidget(desc_lbl);

        box->setStyleSheet(
            "QGroupBox { color: #aaaacc; font-weight: bold; "
            "border: 1px solid #444; border-radius: 6px; "
            "margin-top: 8px; padding-top: 4px; }"
            "QGroupBox::title { subcontrol-origin: margin; "
            "left: 8px; padding: 0 4px; }");
        return box;
    };

    // ── Detection Engine ──────────────────────────────────────────────────────
    auto* det_box = makeEngineRow(
        "🔍 Detection Engine (Layer 1)",
        "Signature · Protocol Anomaly · Behavioral\n"
        "Phát hiện: DDoS · Slow DDoS · Port Scan",
        lbl_det_status_,
        btn_det_toggle_,
        lbl_det_desc_);
    root->addWidget(det_box);

    // ── ML Engine ─────────────────────────────────────────────────────────────
    auto* ml_box = makeEngineRow(
        "🤖 ML Engine (Layer 2)",
        "Isolation Forest · Autoencoder\n"
        "Phân tích bất thường dựa trên AI",
        lbl_ml_status_,
        btn_ml_toggle_,
        lbl_ml_desc_);
    root->addWidget(ml_box);

    // ── Separator ─────────────────────────────────────────────────────────────
    auto* sep = new QFrame(this);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("color: #333;");
    root->addWidget(sep);

    // ── Quick actions ─────────────────────────────────────────────────────────
    auto* quick_group  = new QGroupBox("⚡ Quick Actions", this);
    auto* quick_layout = new QVBoxLayout(quick_group);
    quick_layout->setSpacing(6);
    quick_layout->setContentsMargins(10, 12, 10, 10);

    auto makeQuickBtn = [&](const QString& label,
                             const QString& style) -> QPushButton* {
        auto* btn = new QPushButton(label, quick_group);
        btn->setFixedHeight(28);
        btn->setStyleSheet(style);
        return btn;
    };

    // Enable All
    auto* btn_enable_all = makeQuickBtn(
        "✅  Enable All Engines",
        "QPushButton { background: #1a3a1a; color: #00ff88; "
        "border: 1px solid #336633; border-radius: 4px; "
        "font-size: 11px; font-weight: bold; }"
        "QPushButton:hover { background: #2a4a2a; }");

    // Disable All
    auto* btn_disable_all = makeQuickBtn(
        "⛔  Disable All Engines",
        "QPushButton { background: #3a1a1a; color: #ff4444; "
        "border: 1px solid #663333; border-radius: 4px; "
        "font-size: 11px; font-weight: bold; }"
        "QPushButton:hover { background: #4a2a2a; }");

    quick_layout->addWidget(btn_enable_all);
    quick_layout->addWidget(btn_disable_all);
    quick_group->setStyleSheet(
        "QGroupBox { color: #aaaacc; font-weight: bold; "
        "border: 1px solid #444; border-radius: 6px; "
        "margin-top: 8px; padding-top: 4px; }"
        "QGroupBox::title { subcontrol-origin: margin; "
        "left: 8px; padding: 0 4px; }");
    root->addWidget(quick_group);
    root->addStretch();

    // ── Connections ───────────────────────────────────────────────────────────
    connect(btn_det_toggle_,  &QPushButton::clicked,
            this, &IpsControlWidget::onDetectionBtnClicked);
    connect(btn_ml_toggle_,   &QPushButton::clicked,
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
