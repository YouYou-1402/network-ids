#pragma once
#include <QWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QTimer>
#include <QComboBox>
#include <QCheckBox>
#include <QSpinBox>
#include <QFrame>
#include <vector>
#include "../../firewall/firewall_manager.hpp"

class FirewallWidget : public QWidget {
    Q_OBJECT

public:
    explicit FirewallWidget(QWidget* parent = nullptr);
    void             setFirewallManager(FirewallManager* fw);
    FirewallManager* firewallManager() const { return fw_; }

public slots:
    void refresh();

signals:
    void statusMessage(const QString& msg);

private slots:
    void onBlockClicked();
    void onAllowClicked();
    void onFlushBlacklist();
    void onSaveRules();
    void onLoadRules();
    void onBlSearchChanged(const QString& text);
    void onWlSearchChanged(const QString& text);
    void onTtlTimerTick();
    void onRemoveBlacklistRow(int row);
    void onRemoveWhitelistRow(int row);

private:
    void setupUI();
    void buildHeaderBar  (QVBoxLayout* root);
    void buildBlacklistTab(QWidget* parent);
    void buildWhitelistTab(QWidget* parent);
    void buildQuickBar   (QVBoxLayout* root);

    void refreshBlacklist();
    void refreshWhitelist();
    void updateStatsBadge();
    void applyBlSearch(const QString& text);
    void applyWlSearch(const QString& text);
    void setControlsEnabled(bool enabled);

    static QString           protocolName(uint8_t proto);
    static QString           formatTtl   (uint32_t ttl_sec, uint64_t created_at);
    static QTableWidgetItem* cell        (const QString& text,
                                          Qt::Alignment  align
                                              = Qt::AlignLeft | Qt::AlignVCenter);
    static QPushButton*      makeIconBtn (QWidget*       parent,
                                          const QString& label,
                                          const QString& bg,
                                          const QString& fg,
                                          const QString& border,
                                          const QString& hover);

    // ── State ─────────────────────────────────────────────────────────────────
    FirewallManager*          fw_       = nullptr;
    std::vector<FirewallRule> bl_cache_;
    std::vector<FirewallRule> wl_cache_;

    // ── Header ────────────────────────────────────────────────────────────────
    QLabel* lbl_stats_   = nullptr;
    QLabel* lbl_backend_ = nullptr;

    // ── Tabs ──────────────────────────────────────────────────────────────────
    QTabWidget*   tabs_ = nullptr;

    // Blacklist tab
    QLineEdit*    bl_search_ = nullptr;
    QTableWidget* bl_table_  = nullptr;
    QLineEdit*    bl_ip_     = nullptr;
    QLineEdit*    bl_cmt_    = nullptr;
    QComboBox*    bl_proto_  = nullptr;
    QCheckBox*    bl_perm_   = nullptr;
    QSpinBox*     bl_ttl_    = nullptr;
    QPushButton*  btn_block_ = nullptr;

    // Whitelist tab
    QLineEdit*    wl_search_ = nullptr;
    QTableWidget* wl_table_  = nullptr;
    QLineEdit*    wl_ip_     = nullptr;
    QLineEdit*    wl_cmt_    = nullptr;
    QPushButton*  btn_allow_ = nullptr;

    // Quick bar
    QPushButton*  btn_refresh_ = nullptr;
    QPushButton*  btn_flush_   = nullptr;
    QPushButton*  btn_load_    = nullptr;
    QPushButton*  btn_save_    = nullptr;

    QTimer* ttl_timer_ = nullptr;

    // Table columns
    enum BlCol { BL_IP=0, BL_PROTO, BL_CMT, BL_TTL, BL_SRC, BL_DEL, BL_NCOLS };
    enum WlCol { WL_IP=0, WL_CMT,   WL_DEL, WL_NCOLS };

    // ── Config path ───────────────────────────────────────────────────────────
    static constexpr const char* RULES_PATH =
        "/media/linhlinh/learn/nckh/network-ids/config/firewall_rules.json";

    static constexpr const char* RULES_DIR =
        "/media/linhlinh/learn/nckh/network-ids/config";
};
