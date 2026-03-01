#include "filter_bar.hpp"
#include <QHBoxLayout>
#include <QKeyEvent>
#include <arpa/inet.h>
#include <sstream>

// Autocomplete gợi ý (giống Wireshark)
const QStringList FilterBar::SUGGESTIONS = {
    "tcp", "udp", "icmp", "arp", "http", "dns",
    "ip.src == ", "ip.dst == ",
    "ip.src != ", "ip.dst != ",
    "tcp.port == ", "udp.port == ",
    "tcp.srcport == ", "tcp.dstport == ",
    "tcp.flags.syn == 1", "tcp.flags.rst == 1",
    "tcp.flags.fin == 1", "tcp.flags.ack == 1",
    "frame.len > ", "frame.len < ",
    "threat == ddos", "threat == slow_ddos",
    "threat == port_scan", "threat != normal",
};

FilterBar::FilterBar(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(4);

    // ── Filter icon label ─────────────────────────────────────────────────────
    auto* icon_lbl = new QLabel("🔍", this);
    icon_lbl->setFixedWidth(20);

    // ── Input ─────────────────────────────────────────────────────────────────
    input_ = new QLineEdit(this);
    input_->setPlaceholderText(
        "Display filter  (e.g.  tcp  |  ip.src == 10.0.0.1  |  threat == ddos)");
    input_->setStyleSheet(
        "QLineEdit { background: #1a1a2e; color: #cccccc; "
        "border: 2px solid #444; border-radius: 4px; "
        "padding: 4px 8px; font-family: monospace; font-size: 12px; }"
        "QLineEdit:focus { border-color: #4488ff; }");

    // Autocomplete
    completer_ = new QCompleter(SUGGESTIONS, this);
    completer_->setCaseSensitivity(Qt::CaseInsensitive);
    completer_->setFilterMode(Qt::MatchContains);
    input_->setCompleter(completer_);

    // ── Buttons ───────────────────────────────────────────────────────────────
    apply_btn_ = new QPushButton("Apply", this);
    apply_btn_->setFixedWidth(60);
    apply_btn_->setStyleSheet(
        "QPushButton { background: #2a3a5a; color: #88aaff; "
        "border: 1px solid #446; border-radius: 4px; padding: 4px; }"
        "QPushButton:hover { background: #3a4a6a; }");

    clear_btn_ = new QPushButton("✕", this);
    clear_btn_->setFixedWidth(28);
    clear_btn_->setStyleSheet(
        "QPushButton { background: #3a2a2a; color: #ff8888; "
        "border: 1px solid #644; border-radius: 4px; padding: 4px; }"
        "QPushButton:hover { background: #4a3a3a; }");

    // ── Status label ──────────────────────────────────────────────────────────
    status_lbl_ = new QLabel("", this);
    status_lbl_->setFixedWidth(120);
    status_lbl_->setStyleSheet("font-size: 10px;");

    layout->addWidget(icon_lbl);
    layout->addWidget(input_);
    layout->addWidget(apply_btn_);
    layout->addWidget(clear_btn_);
    layout->addWidget(status_lbl_);

    // ── Connections ───────────────────────────────────────────────────────────
    connect(apply_btn_, &QPushButton::clicked,
            this, &FilterBar::onApply);
    connect(clear_btn_, &QPushButton::clicked,
            this, &FilterBar::onClear);
    connect(input_, &QLineEdit::returnPressed,
            this, &FilterBar::onApply);
    connect(input_, &QLineEdit::textChanged,
            this, &FilterBar::onTextChanged);
}

void FilterBar::onApply() {
    QString expr = input_->text().trimmed();
    if (expr.isEmpty()) {
        onClear();
        return;
    }

    current_filter_ = parseFilter(expr);

    if (current_filter_.valid) {
        setValidStyle(true);
        status_lbl_->setText("✅ Filter active");
        status_lbl_->setStyleSheet(
            "color: #44ff88; font-size: 10px;");
    } else {
        setValidStyle(false);
        status_lbl_->setText("❌ " + QString::fromStdString(
            current_filter_.error_msg));
        status_lbl_->setStyleSheet(
            "color: #ff4444; font-size: 10px;");
    }

    emit filterChanged(current_filter_);
}

void FilterBar::onClear() {
    input_->clear();
    current_filter_ = DisplayFilter{};
    current_filter_.valid = true; // Empty filter = match all
    setValidStyle(true);
    status_lbl_->setText("");
    emit filterChanged(current_filter_);
}

void FilterBar::onTextChanged(const QString& text) {
    // Real-time validation (không apply)
    if (text.isEmpty()) {
        setValidStyle(true);
        status_lbl_->setText("");
        return;
    }

    DisplayFilter test = parseFilter(text);
    if (test.valid) {
        input_->setStyleSheet(
            "QLineEdit { background: #1a2a1a; color: #cccccc; "
            "border: 2px solid #44aa44; border-radius: 4px; "
            "padding: 4px 8px; font-family: monospace; font-size: 12px; }");
    } else {
        input_->setStyleSheet(
            "QLineEdit { background: #2a1a1a; color: #cccccc; "
            "border: 2px solid #aa4444; border-radius: 4px; "
            "padding: 4px 8px; font-family: monospace; font-size: 12px; }");
    }
}

void FilterBar::setFilter(const QString& expr) {
    input_->setText(expr);
    onApply();
}

void FilterBar::clearFilter() {
    onClear();
}

void FilterBar::setValidStyle(bool valid) {
    QString border_color = valid ? "#4488ff" : "#ff4444";
    input_->setStyleSheet(
        "QLineEdit { background: #1a1a2e; color: #cccccc; "
        "border: 2px solid " + border_color + "; border-radius: 4px; "
        "padding: 4px 8px; font-family: monospace; font-size: 12px; }");
}

// ─── Parser ───────────────────────────────────────────────────────────────────
DisplayFilter FilterBar::parseFilter(const QString& expr) const {
    DisplayFilter f;
    f.raw_expr = expr.toStdString();
    f.valid    = true;

    QString e = expr.trimmed().toLower();

    // ── Protocol shortcuts ────────────────────────────────────────────────────
    if (e == "tcp")  { f.proto_filter = DisplayFilter::Proto::TCP;  return f; }
    if (e == "udp")  { f.proto_filter = DisplayFilter::Proto::UDP;  return f; }
    if (e == "icmp") { f.proto_filter = DisplayFilter::Proto::ICMP; return f; }
    if (e == "http") { f.proto_filter = DisplayFilter::Proto::HTTP; return f; }
    if (e == "dns")  { f.proto_filter = DisplayFilter::Proto::DNS;  return f; }
    if (e == "arp")  { f.proto_filter = DisplayFilter::Proto::ARP;  return f; }

    // ── Compound filter (split by "&&" hoặc "and") ────────────────────────────
    QStringList tokens;
    if (e.contains("&&"))
        tokens = e.split("&&");
    else if (e.contains(" and "))
        tokens = e.split(" and ");
    else
        tokens = {e};

    for (const auto& token : tokens) {
        DisplayFilter::Condition cond;
        if (!parseCondition(token.trimmed(), cond)) {
            f.valid     = false;
            f.error_msg = "Invalid expression: " + token.toStdString();
            return f;
        }
        f.conditions.push_back(cond);
    }

    return f;
}

bool FilterBar::parseCondition(const QString&            token,
                                 DisplayFilter::Condition& cond) const {
    // Tìm operator
    struct OpToken { QString str; DisplayFilter::Op op; };
    static const std::vector<OpToken> OPS = {
        {"!=", DisplayFilter::Op::NEQ},
        {">=", DisplayFilter::Op::GTE},
        {"<=", DisplayFilter::Op::LTE},
        {">",  DisplayFilter::Op::GT},
        {"<",  DisplayFilter::Op::LT},
        {"==", DisplayFilter::Op::EQ},
        {"contains", DisplayFilter::Op::CONTAINS},
    };

    for (const auto& op_tok : OPS) {
        int idx = token.indexOf(op_tok.str);
        if (idx < 0) continue;

        QString field_str = token.left(idx).trimmed();
        QString value_str = token.mid(idx + op_tok.str.length()).trimmed();
        cond.op    = op_tok.op;
        cond.value = value_str.toStdString();

        // Map field string → enum
        if (field_str == "ip.src")        cond.field = DisplayFilter::Field::SRC_IP;
        else if (field_str == "ip.dst")   cond.field = DisplayFilter::Field::DST_IP;
        else if (field_str == "tcp.srcport" ||
                 field_str == "udp.srcport") cond.field = DisplayFilter::Field::SRC_PORT;
        else if (field_str == "tcp.dstport" ||
                 field_str == "udp.dstport") cond.field = DisplayFilter::Field::DST_PORT;
        else if (field_str == "tcp.port" ||
                 field_str == "udp.port")  {
            // port == X → src OR dst
            cond.field = DisplayFilter::Field::DST_PORT;
        }
        else if (field_str == "frame.len") cond.field = DisplayFilter::Field::NONE;
        else if (field_str == "threat")    cond.field = DisplayFilter::Field::THREAT;
        else return false;

        return true;
    }

    // TCP flag shortcuts: tcp.flags.syn == 1
    if (token.startsWith("tcp.flags.")) {
        cond.field = DisplayFilter::Field::TCP_FLAGS;
        cond.op    = DisplayFilter::Op::CONTAINS;
        if (token.contains("syn"))  cond.value = "SYN";
        else if (token.contains("ack")) cond.value = "ACK";
        else if (token.contains("rst")) cond.value = "RST";
        else if (token.contains("fin")) cond.value = "FIN";
        else if (token.contains("psh")) cond.value = "PSH";
        else return false;
        return true;
    }

    return false;
}

// ─── Filter matching ──────────────────────────────────────────────────────────
bool DisplayFilter::matches(const PacketRecord& record) const {
    if (!valid) return true; // Invalid filter = show all

    // Protocol filter
    if (proto_filter != Proto::ANY) {
        switch (proto_filter) {
            case Proto::TCP:
                if (record.protocol != IPPROTO_TCP)  return false; break;
            case Proto::UDP:
                if (record.protocol != IPPROTO_UDP)  return false; break;
            case Proto::ICMP:
                if (record.protocol != IPPROTO_ICMP) return false; break;
            case Proto::HTTP:
                if (record.protocol != IPPROTO_TCP)  return false;
                if (record.dst_port != 80 && record.src_port != 80 &&
                    record.dst_port != 8080 && record.src_port != 8080)
                    return false;
                break;
            case Proto::DNS:
                if (record.dst_port != 53 && record.src_port != 53)
                    return false;
                break;
            default: break;
        }
    }

    // Conditions (AND logic)
    for (const auto& cond : conditions) {
        struct in_addr addr;
        std::string record_val;

        switch (cond.field) {
            case Field::SRC_IP:
                addr.s_addr = record.src_ip;
                record_val  = inet_ntoa(addr);
                break;
            case Field::DST_IP:
                addr.s_addr = record.dst_ip;
                record_val  = inet_ntoa(addr);
                break;
            case Field::SRC_PORT:
                record_val = std::to_string(record.src_port);
                break;
            case Field::DST_PORT:
                record_val = std::to_string(record.dst_port);
                break;
            case Field::THREAT:
                record_val = record.threat_type.empty()
                           ? "normal" : record.threat_type;
                // Lowercase
                std::transform(record_val.begin(), record_val.end(),
                               record_val.begin(), ::tolower);
                break;
            case Field::TCP_FLAGS:
                if (cond.value == "SYN" &&
                    !(record.tcp_flags & 0x02)) return false;
                if (cond.value == "ACK" &&
                    !(record.tcp_flags & 0x10)) return false;
                if (cond.value == "RST" &&
                    !(record.tcp_flags & 0x04)) return false;
                if (cond.value == "FIN" &&
                    !(record.tcp_flags & 0x01)) return false;
                continue;
            default:
                continue;
        }

        // Compare
        bool match = false;
        switch (cond.op) {
            case Op::EQ:       match = (record_val == cond.value); break;
            case Op::NEQ:      match = (record_val != cond.value); break;
            case Op::CONTAINS: match = (record_val.find(cond.value)
                                        != std::string::npos);     break;
            default:           match = true; break;
        }

        if (!match) return false;
    }

    return true;
}
