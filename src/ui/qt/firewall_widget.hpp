// src/ui/qt/firewall_widget.hpp
#pragma once
#include <QWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QTimer>
#include <vector>
#include "../../firewall/firewall_manager.hpp"

// ─── FirewallWidget ───────────────────────────────────────────────────────────
//
//  Layout (QVBoxLayout):
//    ┌─ Stats badge ──────────────────────────────────────────────────┐
//    │  🔴 Blacklist: N   🟢 Whitelist: N                             │
//    └────────────────────────────────────────────────────────────────┘
//    ┌─ QTabWidget ───────────────────────────────────────────────────┐
//    │  Tab 0: 🔴 Blacklist                                           │
//    │    [IP] [Protocol] [Reason] [TTL] [Source] [Actions]          │
//    │    ── Add row: [ip input] [comment] [Permanent ☐] [Block]     │
//    │                                                                │
//    │  Tab 1: 🟢 Whitelist                                           │
//    │    [IP] [Comment] [Actions]                                    │
//    │    ── Add row: [ip input] [comment] [Allow]                    │
//    └────────────────────────────────────────────────────────────────┘
//    ┌─ Quick Actions ────────────────────────────────────────────────┐
//    │  [🔄 Refresh]  [🗑 Flush Blacklist]  [💾 Save Rules]          │
//    └────────────────────────────────────────────────────────────────┘
//
//  Thread safety:
//    - FirewallManager* không own, lifetime do caller quản lý
//    - Tất cả call vào FirewallManager từ Qt main thread
//    - refresh() được gọi từ QTimer (main thread) hoặc RuleChangeCallback
//      (worker thread) → dùng QMetaObject::invokeMethod để marshal
// ─────────────────────────────────────────────────────────────────────────────
class FirewallWidget : public QWidget {
    Q_OBJECT

public:
    explicit FirewallWidget(QWidget* parent = nullptr);

    // Inject FirewallManager — gọi trước khi widget hiển thị
    // nullptr = disable toàn bộ controls
    void setFirewallManager(FirewallManager* fw);

    FirewallManager* firewallManager() const { return fw_; }

public slots:
    // Gọi từ UiBridge khi có rule thay đổi (thread-safe via invokeMethod)
    void refresh();

    // Gọi từ WorkerThread callback → phải marshal về main thread
    void onRuleChanged(const FirewallRule& rule, bool added);

signals:
    void ruleAdded  (const FirewallRule& rule);
    void ruleRemoved(uint64_t rule_id);
    void statusMessage(const QString& msg);

private slots:
    void onBlockClicked    ();
    void onAllowClicked    ();
    void onFlushBlacklist  ();
    void onSaveRules       ();
    void onRemoveBlacklistRow(int row);
    void onRemoveWhitelistRow(int row);

private:
    void setupUI();
    void setupBlacklistTab(QWidget* parent);
    void setupWhitelistTab(QWidget* parent);
    void setupQuickActions(QVBoxLayout* root);

    void refreshBlacklist();
    void refreshWhitelist();
    void updateStatsBadge();
    void setControlsEnabled(bool enabled);

    // ── Helpers ───────────────────────────────────────────────────────────────
    static QString protocolName(uint8_t proto);
    static QString formatTtl(uint32_t ttl_sec, uint64_t created_at);
    static QTableWidgetItem* makeItem(const QString& text,
                                      Qt::Alignment  align = Qt::AlignLeft
                                                           | Qt::AlignVCenter);

    FirewallManager* fw_ = nullptr;

    // ── Stats ─────────────────────────────────────────────────────────────────
    QLabel*      lbl_stats_badge_ = nullptr;

    // ── Tabs ──────────────────────────────────────────────────────────────────
    QTabWidget*  tab_widget_      = nullptr;

    // Blacklist tab
    QTableWidget* bl_table_       = nullptr;
    QLineEdit*    bl_ip_input_    = nullptr;
    QLineEdit*    bl_comment_     = nullptr;
    QPushButton*  bl_perm_btn_    = nullptr;   // toggle: Permanent / TTL 10m
    QPushButton*  btn_block_      = nullptr;
    bool          bl_permanent_   = false;

    // Whitelist tab
    QTableWidget* wl_table_       = nullptr;
    QLineEdit*    wl_ip_input_    = nullptr;
    QLineEdit*    wl_comment_     = nullptr;
    QPushButton*  btn_allow_      = nullptr;

    // ── Quick actions ─────────────────────────────────────────────────────────
    QPushButton*  btn_refresh_    = nullptr;
    QPushButton*  btn_flush_      = nullptr;
    QPushButton*  btn_save_       = nullptr;

    // Blacklist table columns
    enum BlCol {
        BL_IP      = 0,
        BL_PROTO   = 1,
        BL_COMMENT = 2,   
        BL_TTL     = 3,
        BL_SOURCE  = 4,
        BL_ACTION  = 5,
        BL_COL_COUNT
    };
    // Whitelist table columns
    enum WlCol { WL_IP=0, WL_COMMENT, WL_ACTION, WL_COL_COUNT };

    static constexpr const char* RULES_PATH = "/etc/ids/firewall_rules.json";
};
