// src/ui/qt/capture_control_dialog.hpp
#pragma once
#include <QDialog>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <vector>
#include <string>

struct InterfaceInfo {
    std::string name;        // "eth0", "wlan0"
    std::string description; // human-readable
    bool        is_loopback = false;
    bool        is_up       = false;
};

class CaptureControlDialog : public QDialog {
    Q_OBJECT

public:
    explicit CaptureControlDialog(QWidget* parent = nullptr);

    // Kết quả sau khi user nhấn Start
    QString   selectedInterface() const;
    QString   bpfFilter()         const;

private slots:
    void onRefreshInterfaces();
    void onInterfaceSelected(int index);

private:
    void setupUI();
    void loadInterfaces();           // pcap_findalldevs
    QString formatIfaceLabel(const InterfaceInfo& i) const;

    QComboBox*   iface_combo_   { nullptr };
    QLineEdit*   filter_edit_   { nullptr };
    QLabel*      iface_detail_  { nullptr };
    QPushButton* start_btn_     { nullptr };
    QPushButton* cancel_btn_    { nullptr };
    QPushButton* refresh_btn_   { nullptr };

    std::vector<InterfaceInfo> interfaces_;
};
