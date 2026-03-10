//src/ui/qt/filter_bar.hpp
#pragma once
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QCompleter>
#include <QStringListModel>
#include <functional>
#include "../../capture/io/packet_ring_buffer.hpp"

// Compiled display filter
struct DisplayFilter {
    enum class Proto  { ANY, TCP, UDP, ICMP, HTTP, DNS, ARP };
    enum class Field  { NONE, SRC_IP, DST_IP, SRC_PORT, DST_PORT,
                        PROTOCOL, TCP_FLAGS, THREAT };
    enum class Op     { EQ, NEQ, GT, LT, GTE, LTE, CONTAINS };

    struct Condition {
        Field       field  = Field::NONE;
        Op          op     = Op::EQ;
        std::string value;
    };

    bool                    valid     = false;
    std::string             raw_expr;
    std::vector<Condition>  conditions;  // AND logic
    Proto                   proto_filter = Proto::ANY;
    std::string             error_msg;

    // Kiểm tra một packet có khớp filter không
    bool matches(const PacketRecord& record) const;
};

// Wireshark-style display filter bar
class FilterBar : public QWidget {
    Q_OBJECT

public:
    explicit FilterBar(QWidget* parent = nullptr);

    // Lấy filter hiện tại
    const DisplayFilter& currentFilter() const { return current_filter_; }

    // Set filter từ code (ví dụ: click vào IP trong packet list)
    void setFilter(const QString& expr);

    // Xóa filter
    void clearFilter();

signals:
    // Phát ra khi filter thay đổi (kể cả khi xóa)
    void filterChanged(DisplayFilter filter);

private slots:
    void onApply();
    void onClear();
    void onTextChanged(const QString& text);

private:
    DisplayFilter parseFilter(const QString& expr) const;
    bool          parseCondition(const QString&         token,
                                  DisplayFilter::Condition& cond) const;
    void          setValidStyle(bool valid);

    QLineEdit*    input_;
    QPushButton*  apply_btn_;
    QPushButton*  clear_btn_;
    QLabel*       status_lbl_;
    QCompleter*   completer_;

    DisplayFilter current_filter_;

    // Autocomplete suggestions
    static const QStringList SUGGESTIONS;
};
