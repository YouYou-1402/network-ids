// src/ui/qt/filter_bar.hpp
#pragma once
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QCompleter>
#include <QTimer>
#include <string>
#include <vector>
#include "../../capture/io/packet_ring_buffer.hpp"

// ─── DisplayFilter ────────────────────────────────────────────────────────────
struct DisplayFilter {
    enum class Proto {
        ANY, TCP, UDP, ICMP, HTTP, DNS, ARP
    };

    enum class Field {
        NONE,
        SRC_IP, DST_IP,
        SRC_PORT, DST_PORT,
        PROTOCOL,
        TCP_FLAGS,
        THREAT,
        FRAME_LEN
    };

    enum class Op {
        EQ, NEQ, GT, LT, GTE, LTE, CONTAINS
    };

    struct Condition {
        Field       field = Field::NONE;
        Op          op    = Op::EQ;
        std::string value;
    };

    bool                   valid        = false;
    std::string            raw_expr;
    std::vector<Condition> conditions;      // AND logic
    Proto                  proto_filter = Proto::ANY;
    std::string            error_msg;

    // Kiểm tra một packet có khớp filter không
    // (dùng bởi filter_bar.cpp — DisplayFilter::matches)
    bool matches(const PacketInfo& record) const;
};

// ─── FilterBar ────────────────────────────────────────────────────────────────
// Wireshark-style display filter bar với:
//   • Autocomplete suggestions
//   • Real-time syntax validation (debounced 300 ms)
//   • Apply chỉ khi nhấn Enter hoặc nút Apply
class FilterBar : public QWidget {
    Q_OBJECT

public:
    explicit FilterBar(QWidget* parent = nullptr);

    // Lấy filter đang active
    const DisplayFilter& currentFilter() const { return current_filter_; }

    // Set filter từ code (ví dụ: click vào IP trong packet list)
    void setFilter(const QString& expr);

    // Xóa filter → show all
    void clearFilter();

signals:
    // Phát ra khi filter được Apply hoặc Clear
    void filterChanged(DisplayFilter filter);

private slots:
    void onApply();
    void onClear();
    void onTextChanged(const QString& text);
    void onDebounceTimeout();

private:
    // ── Parser ────────────────────────────────────────────────────────────────
    DisplayFilter parseFilter   (const QString& expr)                     const;
    bool          parseCondition(const QString& token,
                                  DisplayFilter::Condition& cond)          const;

    // ── UI helpers ────────────────────────────────────────────────────────────
    void setValidStyle(bool valid);
    void setStatusOk  (const QString& msg = "✅ Filter active");
    void setStatusErr (const QString& msg);

    // ── Widgets ───────────────────────────────────────────────────────────────
    QLineEdit*   input_;
    QPushButton* apply_btn_;
    QPushButton* clear_btn_;
    QLabel*      status_lbl_;
    QCompleter*  completer_;
    QTimer*      debounce_timer_;   // 300 ms debounce cho real-time validation

    // ── State ─────────────────────────────────────────────────────────────────
    DisplayFilter current_filter_;

    // ── Autocomplete list ─────────────────────────────────────────────────────
    static const QStringList SUGGESTIONS;
};