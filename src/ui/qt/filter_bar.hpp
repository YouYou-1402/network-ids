// src/ui/qt/filter_bar.hpp
#pragma once
#include "../../core/packet_info.hpp"
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QTimer>
#include <QCompleter>
#include <QString>
#include <QStringList>
#include <string>
#include <vector>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <algorithm>
#include <cctype>

// ─── DisplayFilter ────────────────────────────────────────────────────────────
//  Định nghĩa duy nhất — packet_list_model.hpp include filter_bar.hpp
//  thay vì tự định nghĩa lại
// ─────────────────────────────────────────────────────────────────────────────
struct DisplayFilter {

    enum class Proto { ANY, TCP, UDP, ICMP, HTTP, DNS, ARP };

    enum class Field {
        SRC_IP,
        DST_IP,
        SRC_PORT,
        DST_PORT,
        PROTOCOL,
        TCP_FLAGS,
        FRAME_LEN,
        THREAT,
    };

    enum class Op {
        EQ,
        NEQ,
        GT,
        LT,
        GTE,
        LTE,
        CONTAINS,
    };

    struct Condition {
        Field       field;
        Op          op    = Op::EQ;
        std::string value;
    };

    bool                   valid        = false;
    Proto                  proto_filter = Proto::ANY;
    std::vector<Condition> conditions;
    std::string            raw_expr;
    std::string            error_msg;

    // ── matches() inline ──────────────────────────────────────────────────────
    bool matches(const PacketInfo& record) const {
        if (!valid) return true;

        // Protocol filter
        if (proto_filter != Proto::ANY) {
            bool ok = false;
            switch (proto_filter) {
                case Proto::TCP:
                    ok = (record.protocol == IPPROTO_TCP);
                    break;
                case Proto::UDP:
                    ok = (record.protocol == IPPROTO_UDP);
                    break;
                case Proto::ICMP:
                    ok = (record.protocol == IPPROTO_ICMP);
                    break;
                case Proto::HTTP:
                    ok = (record.protocol == IPPROTO_TCP) &&
                         (record.dst_port == 80   || record.src_port == 80   ||
                          record.dst_port == 8080  || record.src_port == 8080);
                    break;
                case Proto::DNS:
                    ok = (record.dst_port == 53 || record.src_port == 53);
                    break;
                case Proto::ARP:
                    ok = (record.eth_type == 0x0806);
                    break;
                default:
                    ok = true;
                    break;
            }
            if (!ok) return false;
            if (conditions.empty()) return true;
        }

        // Conditions (AND logic)
        for (const auto& cond : conditions) {
            switch (cond.field) {

                case Field::SRC_IP: {
                    struct in_addr a{};
                    inet_pton(AF_INET, cond.value.c_str(), &a);
                    const bool eq = (record.src_ip == a.s_addr);
                    if (cond.op == Op::EQ  && !eq) return false;
                    if (cond.op == Op::NEQ &&  eq) return false;
                    break;
                }

                case Field::DST_IP: {
                    struct in_addr a{};
                    inet_pton(AF_INET, cond.value.c_str(), &a);
                    const bool eq = (record.dst_ip == a.s_addr);
                    if (cond.op == Op::EQ  && !eq) return false;
                    if (cond.op == Op::NEQ &&  eq) return false;
                    break;
                }

                case Field::SRC_PORT: {
                    try {
                        const auto p =
                            static_cast<uint16_t>(std::stoul(cond.value));
                        if (!evalOp(cond.op, record.src_port, p))
                            return false;
                    } catch (...) { return false; }
                    break;
                }

                case Field::DST_PORT: {
                    try {
                        const auto p =
                            static_cast<uint16_t>(std::stoul(cond.value));
                        if (!evalOp(cond.op, record.dst_port, p))
                            return false;
                    } catch (...) { return false; }
                    break;
                }

                case Field::TCP_FLAGS: {
                    uint8_t mask = 0;
                    if      (cond.value == "SYN") mask = 0x02;
                    else if (cond.value == "ACK") mask = 0x10;
                    else if (cond.value == "RST") mask = 0x04;
                    else if (cond.value == "FIN") mask = 0x01;
                    else if (cond.value == "PSH") mask = 0x08;
                    else if (cond.value == "URG") mask = 0x20;
                    if (mask == 0) return false;
                    const bool has = (record.tcp_flags & mask) != 0;
                    if (cond.op == Op::EQ  && !has) return false;
                    if (cond.op == Op::NEQ &&  has) return false;
                    break;
                }

                case Field::FRAME_LEN: {
                    try {
                        const auto len =
                            static_cast<uint32_t>(std::stoul(cond.value));
                        if (!evalOp(cond.op, record.orig_len, len))
                            return false;
                    } catch (...) { return false; }
                    break;
                }

                case Field::THREAT: {
                    std::string threat = record.threat_type;
                    std::transform(threat.begin(), threat.end(),
                                   threat.begin(), ::tolower);
                    const bool has = !threat.empty() &&
                                      threat.find(cond.value) != std::string::npos;
                    if (cond.op == Op::EQ  && !has) return false;
                    if (cond.op == Op::NEQ &&  has) return false;
                    break;
                }

                default: break;
            }
        }
        return true;
    }

private:
    // Helper dùng trong matches() — template để dùng cho cả uint16_t và uint32_t
    template<typename T>
    static bool evalOp(Op op, T lhs, T rhs) {
        switch (op) {
            case Op::EQ:  return lhs == rhs;
            case Op::NEQ: return lhs != rhs;
            case Op::GT:  return lhs >  rhs;
            case Op::LT:  return lhs <  rhs;
            case Op::GTE: return lhs >= rhs;
            case Op::LTE: return lhs <= rhs;
            default:      return true;
        }
    }
};

// ─── FilterBar ────────────────────────────────────────────────────────────────
class FilterBar : public QWidget {
    Q_OBJECT
public:
    explicit FilterBar(QWidget* parent = nullptr);

    void setFilter  (const QString& expr);
    void clearFilter();

    DisplayFilter currentFilter() const { return current_filter_; }

signals:
    void filterChanged(const DisplayFilter& filter);

private slots:
    void onApply();
    void onClear();
    void onTextChanged      (const QString& text);
    void onDebounceTimeout  ();

private:
    DisplayFilter parseFilter    (const QString& expr)  const;
    bool          parseCondition (const QString& token,
                                   DisplayFilter::Condition& cond) const;

    void setValidStyle (bool valid);
    void setStatusOk   (const QString& msg = "  ✔ OK");
    void setStatusErr  (const QString& msg);

    // ── Widgets ───────────────────────────────────────────────────────────────
    QLineEdit*   input_       = nullptr;
    QPushButton* apply_btn_   = nullptr;
    QPushButton* clear_btn_   = nullptr;
    QLabel*      status_lbl_  = nullptr;
    QCompleter*  completer_   = nullptr;
    QTimer*      debounce_timer_ = nullptr;

    // ── State ─────────────────────────────────────────────────────────────────
    DisplayFilter current_filter_;

    static const QStringList SUGGESTIONS;
};
