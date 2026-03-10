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
    setWindowTitle("🎛  Start Capture");
    setMinimumWidth(480);
    setModal(true);
    setupUI();
    loadInterfaces();
}

// ─── setupUI ──────────────────────────────────────────────────────────────────
void CaptureControlDialog::setupUI() {
    setStyleSheet(
        "QDialog    { background: #0f0f1a; color: #cccccc; }"
        "QGroupBox  { border: 1px solid #333; border-radius: 4px; "
        "             margin-top: 8px; color: #8888aa; font-size: 11px; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 8px; }"
        "QComboBox  { background: #1a1a2e; color: #cccccc; "
        "             border: 1px solid #444; border-radius: 3px; "
        "             padding: 4px 8px; }"
        "QComboBox::drop-down { border: none; }"
        "QComboBox QAbstractItemView { background: #1a1a2e; "
        "             color: #cccccc; selection-background-color: #2a2a5a; }"
        "QLineEdit  { background: #1a1a2e; color: #cccccc; "
        "             border: 1px solid #444; border-radius: 3px; "
        "             padding: 4px 8px; }"
        "QLabel     { color: #aaaaaa; font-size: 11px; }"
        "QPushButton { background: #2a2a3e; color: #cccccc; "
        "              border: 1px solid #444; border-radius: 3px; "
        "              padding: 5px 16px; }"
        "QPushButton:hover   { background: #3a3a5a; }"
        "QPushButton#start   { background: #1a3a1a; color: #44ff88; "
        "                      border-color: #2a6a2a; }"
        "QPushButton#start:hover { background: #2a5a2a; }"
        "QPushButton#cancel  { background: #2a1a1a; color: #ff6644; "
        "                      border-color: #5a2a2a; }"
    );

    auto* root = new QVBoxLayout(this);
    root->setSpacing(10);
    root->setContentsMargins(16, 16, 16, 16);

    // ── Interface group ───────────────────────────────────────────────────────
    auto* iface_group  = new QGroupBox("Network Interface", this);
    auto* iface_layout = new QVBoxLayout(iface_group);

    auto* combo_row = new QHBoxLayout();
    iface_combo_ = new QComboBox(iface_group);
    iface_combo_->setMinimumWidth(300);

    refresh_btn_ = new QPushButton("⟳", iface_group);
    refresh_btn_->setFixedSize(28, 28);
    refresh_btn_->setToolTip("Refresh interface list");

    combo_row->addWidget(iface_combo_, 1);
    combo_row->addWidget(refresh_btn_);
    iface_layout->addLayout(combo_row);

    iface_detail_ = new QLabel("", iface_group);
    iface_detail_->setStyleSheet(
        "color: #666688; font-size: 10px; padding: 2px 4px;");
    iface_detail_->setWordWrap(true);
    iface_layout->addWidget(iface_detail_);

    root->addWidget(iface_group);

    // ── BPF Filter group ──────────────────────────────────────────────────────
    auto* filter_group  = new QGroupBox("Capture Filter (BPF)", this);
    auto* filter_layout = new QVBoxLayout(filter_group);

    filter_edit_ = new QLineEdit(filter_group);
    filter_edit_->setPlaceholderText(
        "e.g.  tcp port 80   |   not arp   |   host 192.168.1.1");
    filter_layout->addWidget(filter_edit_);

    // Quick filter buttons
    auto* quick_row = new QHBoxLayout();
    const QStringList quick_filters = {
        "tcp", "udp", "icmp", "port 80", "port 443", "not arp"
    };
    for (const auto& f : quick_filters) {
        auto* btn = new QPushButton(f, filter_group);
        btn->setFixedHeight(22);
        btn->setStyleSheet(
            "QPushButton { background: #1a1a2e; color: #6688aa; "
            "border: 1px solid #333; border-radius: 2px; "
            "padding: 1px 6px; font-size: 10px; }"
            "QPushButton:hover { background: #2a2a4a; color: #88aacc; }");
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

    // ── Buttons ───────────────────────────────────────────────────────────────
    auto* btn_row = new QHBoxLayout();
    btn_row->addStretch();

    cancel_btn_ = new QPushButton("✕  Cancel", this);
    cancel_btn_->setObjectName("cancel");

    start_btn_  = new QPushButton("▶  Start Capture", this);
    start_btn_->setObjectName("start");
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
        info.name        = dev->name ? dev->name : "";
        info.description = dev->description ? dev->description : "";
        info.is_loopback = (dev->flags & PCAP_IF_LOOPBACK)  != 0;
        info.is_up       = (dev->flags & PCAP_IF_UP)        != 0;
        interfaces_.push_back(std::move(info));
    }
    pcap_freealldevs(alldevs);

    // Populate combo — ưu tiên interface đang UP, không loopback
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

    // Khôi phục selection cũ nếu còn tồn tại
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
        detail += "⚠ Interface is DOWN  ";
    if (iface.is_loopback)
        detail += "🔄 Loopback  ";
    if (detail.isEmpty())
        detail = "✅ Ready to capture";
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
