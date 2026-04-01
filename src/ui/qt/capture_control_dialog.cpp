// src/ui/qt/capture_control_dialog.cpp
#include "capture_control_dialog.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QIcon>
#include <pcap.h>

// ─── Constructor ──────────────────────────────────────────────────────────────
CaptureControlDialog::CaptureControlDialog(QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle("Start Capture");
    setMinimumWidth(480);
    setModal(true);
    setupUI();
    loadInterfaces();
}

// ─── setupUI ──────────────────────────────────────────────────────────────────
void CaptureControlDialog::setupUI() {
    setStyleSheet(
        // ── Base ────────────────────────────────────────────────────────────
        "QDialog   { background: #f5f6fa; color: #1a1a3e; }"
        "QLabel    { color: #555577; font-size: 11px; background: transparent; }"

        // ── GroupBox ────────────────────────────────────────────────────────
        "QGroupBox {"
        "  background: #ffffff;"
        "  border: 1px solid #d0d4e8; border-radius: 6px;"
        "  margin-top: 10px;"
        "  font-size: 11px; font-weight: bold; color: #3355cc; }"
        "QGroupBox::title {"
        "  subcontrol-origin: margin; subcontrol-position: top left;"
        "  left: 10px; padding: 0 4px; }"

        // ── ComboBox ────────────────────────────────────────────────────────
        "QComboBox {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #b0b8d8; border-radius: 4px;"
        "  padding: 4px 8px; font-size: 12px; }"
        "QComboBox:focus { border-color: #3355cc; }"
        "QComboBox::drop-down { border: none; width: 20px; }"
        "QComboBox QAbstractItemView {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #d0d4e8;"
        "  selection-background-color: #dce3ff;"
        "  selection-color: #0a0a6e; }"

        // ── LineEdit ────────────────────────────────────────────────────────
        "QLineEdit {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #b0b8d8; border-radius: 4px;"
        "  padding: 4px 8px; font-size: 12px; }"
        "QLineEdit:focus { border-color: #3355cc; }"
        "QLineEdit::placeholder { color: #aaaacc; }"

        // ── Button base ─────────────────────────────────────────────────────
        "QPushButton {"
        "  background: #eef0f7; color: #1a1a3e;"
        "  border: 1px solid #b0b8d8; border-radius: 4px;"
        "  padding: 5px 16px; font-size: 12px; }"
        "QPushButton:hover   { background: #dce3ff; border-color: #3355cc; }"
        "QPushButton:pressed { background: #c8d0f8; }"
        "QPushButton:disabled { background: #f0f0f8; color: #aaaacc;"
        "                       border-color: #d8d8ee; }"

        // ── Start button ────────────────────────────────────────────────────
        "QPushButton#start {"
        "  background: #e8f5e9; color: #1a6e2e;"
        "  border: 1px solid #a5d6a7; font-weight: bold; }"
        "QPushButton#start:hover   { background: #c8e6c9; border-color: #388e3c; }"
        "QPushButton#start:pressed { background: #b2dfdb; }"
        "QPushButton#start:disabled { background: #f0f4f0; color: #aaccaa;"
        "                             border-color: #ccdacc; }"

        // ── Cancel button ───────────────────────────────────────────────────
        "QPushButton#cancel {"
        "  background: #fff0f0; color: #cc2222;"
        "  border: 1px solid #f0b8b8; }"
        "QPushButton#cancel:hover   { background: #ffe0e0; border-color: #cc2222; }"
        "QPushButton#cancel:pressed { background: #ffd0d0; }"
    );

    auto* root = new QVBoxLayout(this);
    root->setSpacing(12);
    root->setContentsMargins(16, 16, 16, 16);

    // ── Interface group ───────────────────────────────────────────────────────
    auto* iface_group  = new QGroupBox("Network Interface", this);
    auto* iface_layout = new QVBoxLayout(iface_group);
    iface_layout->setSpacing(6);
    iface_layout->setContentsMargins(10, 14, 10, 10);

    auto* combo_row = new QHBoxLayout();
    iface_combo_ = new QComboBox(iface_group);
    iface_combo_->setMinimumWidth(300);

    refresh_btn_ = new QPushButton("⟳", iface_group);
    refresh_btn_->setFixedSize(30, 30);
    refresh_btn_->setToolTip("Refresh interface list");
    refresh_btn_->setStyleSheet(
        "QPushButton {"
        "  background: #eef0f7; color: #3355cc;"
        "  border: 1px solid #b0b8d8; border-radius: 4px;"
        "  font-size: 14px; padding: 0; }"
        "QPushButton:hover { background: #dce3ff; }");

    combo_row->addWidget(iface_combo_, 1);
    combo_row->addWidget(refresh_btn_);
    iface_layout->addLayout(combo_row);

    iface_detail_ = new QLabel("", iface_group);
    iface_detail_->setStyleSheet(
        "QLabel { color: #666688; font-size: 10px;"
        "         background: transparent; padding: 2px 4px; }");
    iface_detail_->setWordWrap(true);
    iface_layout->addWidget(iface_detail_);

    root->addWidget(iface_group);

    // ── BPF Filter group ──────────────────────────────────────────────────────
    auto* filter_group  = new QGroupBox("Capture Filter (BPF)", this);
    auto* filter_layout = new QVBoxLayout(filter_group);
    filter_layout->setSpacing(8);
    filter_layout->setContentsMargins(10, 14, 10, 10);

    filter_edit_ = new QLineEdit(filter_group);
    filter_edit_->setPlaceholderText(
        "e.g.  tcp port 80   |   not arp   |   host 192.168.1.1");
    filter_layout->addWidget(filter_edit_);

    // Quick filter buttons
    auto* quick_row = new QHBoxLayout();
    quick_row->setSpacing(4);
    const QStringList quick_filters = {
        "tcp", "udp", "icmp", "port 80", "port 443", "not arp"
    };
    for (const auto& f : quick_filters) {
        auto* btn = new QPushButton(f, filter_group);
        btn->setFixedHeight(24);
        btn->setStyleSheet(
            "QPushButton {"
            "  background: #eef0f7; color: #3355cc;"
            "  border: 1px solid #c0c8e8; border-radius: 3px;"
            "  padding: 1px 8px; font-size: 10px; }"
            "QPushButton:hover {"
            "  background: #dce3ff; border-color: #3355cc; }");
        connect(btn, &QPushButton::clicked,
                this, [this, f]() {
                    const QString cur = filter_edit_->text().trimmed();
                    filter_edit_->setText(
                        cur.isEmpty() ? f : cur + " and " + f);
                });
        quick_row->addWidget(btn);
    }
    quick_row->addStretch();
    filter_layout->addLayout(quick_row);
    root->addWidget(filter_group);

    // ── Divider ───────────────────────────────────────────────────────────────
    auto* divider = new QFrame(this);
    divider->setFrameShape(QFrame::HLine);
    divider->setStyleSheet("QFrame { color: #d0d4e8; }");
    root->addWidget(divider);

    // ── Buttons ───────────────────────────────────────────────────────────────
    auto* btn_row = new QHBoxLayout();
    btn_row->setSpacing(8);
    btn_row->addStretch();

    cancel_btn_ = new QPushButton("✕  Cancel", this);
    cancel_btn_->setObjectName("cancel");
    cancel_btn_->setMinimumWidth(100);

    start_btn_ = new QPushButton("▶  Start Capture", this);
    start_btn_->setObjectName("start");
    start_btn_->setMinimumWidth(130);
    start_btn_->setDefault(true);

    btn_row->addWidget(cancel_btn_);
    btn_row->addWidget(start_btn_);
    root->addLayout(btn_row);

    // ── Connections ───────────────────────────────────────────────────────────
    connect(refresh_btn_, &QPushButton::clicked,
            this, &CaptureControlDialog::onRefreshInterfaces);
    connect(iface_combo_,
            QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &CaptureControlDialog::onInterfaceSelected);
    connect(start_btn_,  &QPushButton::clicked, this, &QDialog::accept);
    connect(cancel_btn_, &QPushButton::clicked, this, &QDialog::reject);
}

// ─── loadInterfaces ───────────────────────────────────────────────────────────
void CaptureControlDialog::loadInterfaces() {
    interfaces_.clear();
    iface_combo_->clear();

    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        iface_detail_->setText(
            QString("⚠ pcap_findalldevs failed: %1\n"
                    "Try running as root / with CAP_NET_RAW")
                .arg(errbuf));
        return;
    }

    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        InterfaceInfo info;
        info.name        = dev->name        ? dev->name        : "";
        info.description = dev->description ? dev->description : "";
        info.is_loopback = (dev->flags & PCAP_IF_LOOPBACK) != 0;
        info.is_up       = (dev->flags & PCAP_IF_UP)       != 0;
        interfaces_.push_back(std::move(info));
    }
    pcap_freealldevs(alldevs);

    int preferred_idx = 0;
    for (size_t i = 0; i < interfaces_.size(); ++i) {
        const auto& iface = interfaces_[i];
        iface_combo_->addItem(formatIfaceLabel(iface),
                              QString::fromStdString(iface.name));
        if (iface.is_up && !iface.is_loopback && preferred_idx == 0)
            preferred_idx = static_cast<int>(i);
    }

    if (!interfaces_.empty())
        iface_combo_->setCurrentIndex(preferred_idx);
}

// ─── formatIfaceLabel ─────────────────────────────────────────────────────────
QString CaptureControlDialog::formatIfaceLabel(const InterfaceInfo& i) const {
    QString label = QString::fromStdString(i.name);
    QStringList tags;
    if (i.is_up)       tags << "UP";
    if (i.is_loopback) tags << "lo";
    if (!tags.isEmpty())
        label += "  [" + tags.join(", ") + "]";
    if (!i.description.empty())
        label += "  —  " + QString::fromStdString(i.description);
    return label;
}

// ─── onRefreshInterfaces ──────────────────────────────────────────────────────
void CaptureControlDialog::onRefreshInterfaces() {
    const QString cur = iface_combo_->currentData().toString();
    loadInterfaces();
    for (int i = 0; i < iface_combo_->count(); ++i) {
        if (iface_combo_->itemData(i).toString() == cur) {
            iface_combo_->setCurrentIndex(i);
            break;
        }
    }
}

// ─── onInterfaceSelected ──────────────────────────────────────────────────────
void CaptureControlDialog::onInterfaceSelected(int index) {
    if (index < 0 || index >= static_cast<int>(interfaces_.size())) {
        iface_detail_->clear();
        return;
    }
    const auto& iface = interfaces_[static_cast<size_t>(index)];

    QString detail;
    if (!iface.is_up)
        detail += "Interface is DOWN  ";
    if (iface.is_loopback)
        detail += "Loopback  ";
    if (detail.isEmpty())
        detail = "Ready to capture";

    // Màu detail theo trạng thái
    const QString color = iface.is_up ? "#227744" : "#cc4400";
    iface_detail_->setStyleSheet(
        QString("QLabel { color: %1; font-size: 10px;"
                "         background: transparent; padding: 2px 4px; }")
            .arg(color));
    iface_detail_->setText(detail);

    start_btn_->setEnabled(iface.is_up);
}

// ─── Getters ──────────────────────────────────────────────────────────────────
QString CaptureControlDialog::selectedInterface() const {
    return iface_combo_->currentData().toString();
}

QString CaptureControlDialog::bpfFilter() const {
    return filter_edit_->text().trimmed();
}
