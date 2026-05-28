// src/ui/qt/ips_control_widget.cpp
#include "ips_control_widget.hpp"

// ─── Palette ──────────────────────────────────────────────────────────────────
//  BG_PAGE      #f5f6fa    nền tổng
//  BG_GROUP     #ffffff    nền groupbox
//  BORDER       #d0d4e8    viền
//  TEXT_PRI     #1a1a3e    chữ chính
//  TEXT_SEC     #666688    chữ phụ / mô tả
//  GREEN_FG     #227744    active / enable
//  GREEN_BG     #f0fff4    nền pastel xanh lá
//  GREEN_BD     #a5d6a7    viền xanh lá
//  RED_FG       #cc2222    disable / danger
//  RED_BG       #fff0f0    nền pastel đỏ
//  RED_BD       #f0b8b8    viền đỏ
//  BLUE_FG      #3355cc    IDS mode
//  BLUE_BG      #eef0ff    nền pastel xanh
//  BLUE_BD      #b0b8e8    viền xanh
//  PURPLE_FG    #6633cc    ML only
//  PURPLE_BG    #f5f0ff    nền pastel tím
//  PURPLE_BD    #c8b0e8    viền tím
//  GRAY_FG      #888899    disabled / off
//  GRAY_BG      #f0f0f8    nền pastel xám
//  GRAY_BD      #c8c8d8    viền xám
// ─────────────────────────────────────────────────────────────────────────────

IpsControlWidget::IpsControlWidget(QWidget* parent)
    : QWidget(parent)
{
    setStyleSheet("QWidget { background: #f5f6fa; color: #1a1a3e; }");
    setupUI();
}

// ─── setupUI ──────────────────────────────────────────────────────────────────
void IpsControlWidget::setupUI() {
    auto* root = new QVBoxLayout(this);
    root->setSpacing(8);
    root->setContentsMargins(8, 8, 8, 8);

    // RESPONSIVE: tính kích thước theo font metrics
    const int em = fontMetrics().height();

    // ── Mode badge ────────────────────────────────────────────────────────────
    lbl_mode_badge_ = new QLabel("🛡️  IPS — Full Protection", this);
    lbl_mode_badge_->setAlignment(Qt::AlignCenter);
    // RESPONSIVE: bỏ setFixedHeight(32) → dùng setMinimumHeight theo em
    lbl_mode_badge_->setMinimumHeight(em * 2);
    lbl_mode_badge_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    lbl_mode_badge_->setStyleSheet(
        "QLabel {"
        "  background: #f0fff4; color: #227744;"
        "  font-weight: bold;"
        "  border: 1px solid #a5d6a7; border-radius: 6px;"
        "  padding: 2px 8px; }");
    root->addWidget(lbl_mode_badge_);

    // ── GroupBox style ────────────────────────────────────────────────────────
    const QString group_style =
        "QGroupBox {"
        "  background: #ffffff;"
        "  border: 1px solid #d0d4e8; border-radius: 6px;"
        "  margin-top: 8px; padding-top: 4px; }"
        "QGroupBox::title {"
        "  subcontrol-origin: margin;"
        "  left: 10px; padding: 0 4px;"
        "  color: #3355cc; font-size: 10px; font-weight: bold; }";

    // ── Helper: engine row ────────────────────────────────────────────────────
    auto makeEngineRow = [&](const QString& title,
                              const QString& desc,
                              QLabel*&       status_lbl,
                              QPushButton*&  toggle_btn,
                              QLabel*&       desc_lbl) -> QGroupBox*
    {
        auto* box    = new QGroupBox(title, this);
        box->setStyleSheet(group_style);
        auto* layout = new QVBoxLayout(box);
        layout->setSpacing(5);
        layout->setContentsMargins(10, 12, 10, 10);

        // Row: status dot + toggle button
        auto* row    = new QWidget(box);
        row->setStyleSheet("QWidget { background: transparent; }");
        auto* row_ly = new QHBoxLayout(row);
        row_ly->setContentsMargins(0, 0, 0, 0);
        row_ly->setSpacing(6);

        status_lbl = new QLabel("● ACTIVE", row);
        status_lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #227744; font-weight: bold; }");

        toggle_btn = new QPushButton("Disable", row);
        // RESPONSIVE: bỏ setFixedSize(68, 24) → tự co dãn theo nội dung
        toggle_btn->setMinimumWidth(em * 5);
        toggle_btn->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
        toggle_btn->setStyleSheet(
            "QPushButton {"
            "  background: #fff0f0; color: #cc2222;"
            "  border: 1px solid #f0b8b8; border-radius: 4px;"
            "  padding: 2px 8px; font-weight: bold; }"
            "QPushButton:hover { background: #ffe0e0; border-color: #cc2222; }"
            "QPushButton:pressed { background: #ffd0d0; }");

        row_ly->addWidget(status_lbl);
        row_ly->addStretch();
        row_ly->addWidget(toggle_btn);
        layout->addWidget(row);

        // Description
        desc_lbl = new QLabel(desc, box);
        desc_lbl->setWordWrap(true);
        desc_lbl->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #666688; font-size: 9px; }");
        layout->addWidget(desc_lbl);

        return box;
    };

    // ── Detection Engine ──────────────────────────────────────────────────────
    auto* det_box = makeEngineRow(
        "Detection (L1)",
        "Signature · Protocol Anomaly · Behavioral",
        lbl_det_status_, btn_det_toggle_, lbl_det_desc_);
    root->addWidget(det_box);

    // ── ML Engine ─────────────────────────────────────────────────────────────
    auto* ml_box = makeEngineRow(
        "ML Engine (L2)",
        "XGBoost · Autoencoder",
        lbl_ml_status_, btn_ml_toggle_, lbl_ml_desc_);
    root->addWidget(ml_box);

    // ── Quick Actions ─────────────────────────────────────────────────────────
    auto* qa_group  = new QGroupBox("Quick Actions", this);
    qa_group->setStyleSheet(group_style);
    auto* qa_layout = new QHBoxLayout(qa_group);
    qa_layout->setSpacing(8);
    qa_layout->setContentsMargins(10, 12, 10, 10);

    auto* btn_enable_all = new QPushButton("Enable All", qa_group);
    // RESPONSIVE: bỏ setFixedHeight(26) → tự co dãn
    btn_enable_all->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    btn_enable_all->setStyleSheet(
        "QPushButton {"
        "  background: #f0fff4; color: #227744;"
        "  border: 1px solid #a5d6a7; border-radius: 4px;"
        "  padding: 3px 8px; font-weight: bold; }"
        "QPushButton:hover   { background: #c8e6c9; border-color: #388e3c; }"
        "QPushButton:pressed { background: #b2dfdb; }");

    auto* btn_disable_all = new QPushButton("Disable All", qa_group);
    // RESPONSIVE: bỏ setFixedHeight(26) → tự co dãn
    btn_disable_all->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    btn_disable_all->setStyleSheet(
        "QPushButton {"
        "  background: #fff0f0; color: #cc2222;"
        "  border: 1px solid #f0b8b8; border-radius: 4px;"
        "  padding: 3px 8px; font-weight: bold; }"
        "QPushButton:hover   { background: #ffe0e0; border-color: #cc2222; }"
        "QPushButton:pressed { background: #ffd0d0; }");

    qa_layout->addWidget(btn_enable_all);
    qa_layout->addWidget(btn_disable_all);
    root->addWidget(qa_group);

    root->addStretch();

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

// ─── syncState ────────────────────────────────────────────────────────────────
void IpsControlWidget::syncState(bool detection_enabled, bool ml_enabled) {
    det_enabled_ = detection_enabled;
    ml_enabled_  = ml_enabled;
    setDetectionUI(detection_enabled);
    setMlUI(ml_enabled);
    updateModeBadge();
}

// ─── setDetectionUI ───────────────────────────────────────────────────────────
void IpsControlWidget::setDetectionUI(bool enabled) {
    if (enabled) {
        lbl_det_status_->setText("● ACTIVE");
        lbl_det_status_->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #227744; font-weight: bold; font-size: 12px; }");
        btn_det_toggle_->setText("Disable");
        btn_det_toggle_->setStyleSheet(
            "QPushButton {"
            "  background: #fff0f0; color: #cc2222;"
            "  border: 1px solid #f0b8b8; border-radius: 4px;"
            "  font-size: 11px; font-weight: bold; }"
            "QPushButton:hover   { background: #ffe0e0; border-color: #cc2222; }"
            "QPushButton:pressed { background: #ffd0d0; }");
    } else {
        lbl_det_status_->setText("○ DISABLED");
        lbl_det_status_->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #888899; font-weight: bold; font-size: 12px; }");
        btn_det_toggle_->setText("Enable");
        btn_det_toggle_->setStyleSheet(
            "QPushButton {"
            "  background: #f0fff4; color: #227744;"
            "  border: 1px solid #a5d6a7; border-radius: 4px;"
            "  font-size: 11px; font-weight: bold; }"
            "QPushButton:hover   { background: #c8e6c9; border-color: #388e3c; }"
            "QPushButton:pressed { background: #b2dfdb; }");
    }
}

// ─── setMlUI ──────────────────────────────────────────────────────────────────
void IpsControlWidget::setMlUI(bool enabled) {
    if (enabled) {
        lbl_ml_status_->setText("● ACTIVE");
        lbl_ml_status_->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #227744; font-weight: bold; font-size: 12px; }");
        btn_ml_toggle_->setText("Disable");
        btn_ml_toggle_->setStyleSheet(
            "QPushButton {"
            "  background: #fff0f0; color: #cc2222;"
            "  border: 1px solid #f0b8b8; border-radius: 4px;"
            "  font-size: 11px; font-weight: bold; }"
            "QPushButton:hover   { background: #ffe0e0; border-color: #cc2222; }"
            "QPushButton:pressed { background: #ffd0d0; }");
    } else {
        lbl_ml_status_->setText("○ DISABLED");
        lbl_ml_status_->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #888899; font-weight: bold; font-size: 12px; }");
        btn_ml_toggle_->setText("Enable");
        btn_ml_toggle_->setStyleSheet(
            "QPushButton {"
            "  background: #f0fff4; color: #227744;"
            "  border: 1px solid #a5d6a7; border-radius: 4px;"
            "  font-size: 11px; font-weight: bold; }"
            "QPushButton:hover   { background: #c8e6c9; border-color: #388e3c; }"
            "QPushButton:pressed { background: #b2dfdb; }");
    }
}

// ─── updateModeBadge ──────────────────────────────────────────────────────────
void IpsControlWidget::updateModeBadge() {
    if (det_enabled_ && ml_enabled_) {
        lbl_mode_badge_->setText("🛡️  IPS MODE  —  Full Protection");
        lbl_mode_badge_->setStyleSheet(
            "QLabel {"
            "  background: #f0fff4; color: #227744;"
            "  font-size: 13px; font-weight: bold;"
            "  border: 1px solid #a5d6a7; border-radius: 6px;"
            "  padding: 4px 8px; }");
    } else if (det_enabled_ && !ml_enabled_) {
        lbl_mode_badge_->setText("IDS MODE  —  L1 Detection Only");
        lbl_mode_badge_->setStyleSheet(
            "QLabel {"
            "  background: #eef0ff; color: #3355cc;"
            "  font-size: 13px; font-weight: bold;"
            "  border: 1px solid #b0b8e8; border-radius: 6px;"
            "  padding: 4px 8px; }");
    } else if (!det_enabled_ && ml_enabled_) {
        lbl_mode_badge_->setText("ML ONLY  —  L2 Detection Only");
        lbl_mode_badge_->setStyleSheet(
            "QLabel {"
            "  background: #f5f0ff; color: #6633cc;"
            "  font-size: 13px; font-weight: bold;"
            "  border: 1px solid #c8b0e8; border-radius: 6px;"
            "  padding: 4px 8px; }");
    } else {
        lbl_mode_badge_->setText("MONITOR ONLY  —  No Detection");
        lbl_mode_badge_->setStyleSheet(
            "QLabel {"
            "  background: #f0f0f8; color: #888899;"
            "  font-size: 13px; font-weight: bold;"
            "  border: 1px solid #c8c8d8; border-radius: 6px;"
            "  padding: 4px 8px; }");
    }
}
