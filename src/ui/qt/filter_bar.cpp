// src/ui/qt/filter_bar.cpp
#include "filter_bar.hpp"
#include <QHBoxLayout>
#include <QAbstractItemView>
#include <arpa/inet.h>
#include <algorithm>

// ─── Autocomplete suggestions ─────────────────────────────────────────────────
const QStringList FilterBar::SUGGESTIONS = {
    "tcp", "udp", "icmp", "arp", "http", "https", "dns",
    "ssh", "ftp", "smtp", "ntp", "snmp", "dhcp",
    "ip.src == ",      "ip.dst == ",
    "ip.src != ",      "ip.dst != ",
    "tcp.port == ",    "udp.port == ",
    "tcp.srcport == ", "tcp.dstport == ",
    "udp.srcport == ", "udp.dstport == ",
    "tcp.flags.syn == 1", "tcp.flags.ack == 1",
    "tcp.flags.rst == 1", "tcp.flags.fin == 1",
    "tcp.flags.psh == 1", "tcp.flags.urg == 1",
    "frame.len > ",    "frame.len < ",
    "frame.len >= ",   "frame.len <= ",
    "threat == ddos",       "threat == slow_ddos",
    "threat == port_scan",  "threat != normal",
};

// ─── Stylesheet constants — light theme ──────────────────────────────────────
static const char* STYLE_INPUT_NORMAL =
    "QLineEdit {"
    "  background: #ffffff; color: #1a1a3e;"
    "  border: 1px solid #b0b8d8; border-radius: 4px;"
    "  padding: 1px 8px;"
    "  font-family: 'Consolas', 'Courier New', monospace;"
    "  font-size: 11px; }"
    "QLineEdit:focus { border-color: #3355cc; }";

static const char* STYLE_INPUT_OK =
    "QLineEdit {"
    "  background: #f0fff4; color: #1a1a3e;"
    "  border: 1px solid #52c07a; border-radius: 4px;"
    "  padding: 1px 8px;"
    "  font-family: 'Consolas', 'Courier New', monospace;"
    "  font-size: 11px; }";

static const char* STYLE_INPUT_ERR =
    "QLineEdit {"
    "  background: #fff5f5; color: #1a1a3e;"
    "  border: 1px solid #e05555; border-radius: 4px;"
    "  padding: 1px 8px;"
    "  font-family: 'Consolas', 'Courier New', monospace;"
    "  font-size: 11px; }";

// ─── Constructor ──────────────────────────────────────────────────────────────
FilterBar::FilterBar(QWidget* parent)
    : QWidget(parent)
{
    setFixedHeight(32);
    setStyleSheet("QWidget { background: #eef0f7; }");

    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(6, 3, 6, 3);
    layout->setSpacing(5);

    // Icon
    auto* icon_lbl = new QLabel("🔍", this);
    icon_lbl->setFixedSize(18, 18);
    icon_lbl->setStyleSheet(
        "QLabel { background: transparent; font-size: 12px; }");

    // Input
    input_ = new QLineEdit(this);
    input_->setFixedHeight(24);
    input_->setPlaceholderText(
        "Display filter  "
        "(e.g.  tcp  |  ip.src == 10.0.0.1  |  tcp.flags.syn == 1  |  threat == ddos)");
    input_->setStyleSheet(STYLE_INPUT_NORMAL);

    // Completer
    completer_ = new QCompleter(SUGGESTIONS, this);
    completer_->setCaseSensitivity(Qt::CaseInsensitive);
    completer_->setFilterMode(Qt::MatchContains);
    completer_->popup()->setStyleSheet(
        "QAbstractItemView {"
        "  background: #ffffff; color: #1a1a3e;"
        "  border: 1px solid #d0d4e8;"
        "  selection-background-color: #dce3ff;"
        "  selection-color: #0a0a6e;"
        "  font-size: 11px; }");
    input_->setCompleter(completer_);

    // Apply button
    apply_btn_ = new QPushButton("Apply", this);
    apply_btn_->setFixedSize(56, 24);
    apply_btn_->setStyleSheet(
        "QPushButton {"
        "  background: #3355cc; color: #ffffff;"
        "  border: none; border-radius: 4px;"
        "  font-size: 11px; font-weight: bold; }"
        "QPushButton:hover   { background: #2244bb; }"
        "QPushButton:pressed { background: #1133aa; }");

    // Clear button
    clear_btn_ = new QPushButton("✕", this);
    clear_btn_->setFixedSize(24, 24);
    clear_btn_->setToolTip("Clear filter");
    clear_btn_->setStyleSheet(
        "QPushButton {"
        "  background: #fff0f0; color: #cc2222;"
        "  border: 1px solid #f0b8b8; border-radius: 4px;"
        "  font-size: 11px; }"
        "QPushButton:hover   { background: #ffe0e0; border-color: #cc2222; }"
        "QPushButton:pressed { background: #ffd0d0; }");

    // Status label
    status_lbl_ = new QLabel("", this);
    status_lbl_->setFixedWidth(72);
    status_lbl_->setStyleSheet(
        "QLabel { background: transparent; font-size: 9px; }");

    layout->addWidget(icon_lbl);
    layout->addWidget(input_, 1);
    layout->addWidget(apply_btn_);
    layout->addWidget(clear_btn_);
    layout->addWidget(status_lbl_);

    // Debounce timer
    debounce_timer_ = new QTimer(this);
    debounce_timer_->setSingleShot(true);
    debounce_timer_->setInterval(300);

    connect(apply_btn_,      &QPushButton::clicked,
            this,            &FilterBar::onApply);
    connect(clear_btn_,      &QPushButton::clicked,
            this,            &FilterBar::onClear);
    connect(input_,          &QLineEdit::returnPressed,
            this,            &FilterBar::onApply);
    connect(input_,          &QLineEdit::textChanged,
            this,            &FilterBar::onTextChanged);
    connect(debounce_timer_, &QTimer::timeout,
            this,            &FilterBar::onDebounceTimeout);
}

// ─── onApply ──────────────────────────────────────────────────────────────────
void FilterBar::onApply() {
    debounce_timer_->stop();

    const QString expr = input_->text().trimmed();
    if (expr.isEmpty()) {
        onClear();
        return;
    }

    current_filter_ = parseFilter(expr);

    if (current_filter_.valid) {
        setValidStyle(true);
        setStatusOk();
    } else {
        setValidStyle(false);
        setStatusErr(QString::fromStdString(current_filter_.error_msg));
    }

    emit filterChanged(current_filter_);
}

// ─── onClear ──────────────────────────────────────────────────────────────────
void FilterBar::onClear() {
    debounce_timer_->stop();
    input_->clear();
    input_->setStyleSheet(STYLE_INPUT_NORMAL);
    status_lbl_->setText("");

    current_filter_              = DisplayFilter{};
    current_filter_.valid        = true;
    current_filter_.proto_filter = DisplayFilter::Proto::ANY;

    emit filterChanged(current_filter_);
}

// ─── onTextChanged ────────────────────────────────────────────────────────────
void FilterBar::onTextChanged(const QString& text) {
    if (text.trimmed().isEmpty()) {
        debounce_timer_->stop();
        input_->setStyleSheet(STYLE_INPUT_NORMAL);
        status_lbl_->setText("");
        return;
    }
    debounce_timer_->start();
}

// ─── onDebounceTimeout ────────────────────────────────────────────────────────
void FilterBar::onDebounceTimeout() {
    const QString text = input_->text().trimmed();
    if (text.isEmpty()) {
        input_->setStyleSheet(STYLE_INPUT_NORMAL);
        status_lbl_->setText("");
        return;
    }

    const DisplayFilter test = parseFilter(text);
    if (test.valid) {
        input_->setStyleSheet(STYLE_INPUT_OK);
        status_lbl_->setText("✔ OK");
        status_lbl_->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #227744; font-size: 9px; }");
    } else {
        input_->setStyleSheet(STYLE_INPUT_ERR);
        status_lbl_->setText(QString::fromStdString(test.error_msg));
        status_lbl_->setStyleSheet(
            "QLabel { background: transparent;"
            "         color: #cc2222; font-size: 9px; }");
    }
}

// ─── setFilter / clearFilter ──────────────────────────────────────────────────
void FilterBar::setFilter(const QString& expr) {
    input_->setText(expr);
    onApply();
}

void FilterBar::clearFilter() {
    onClear();
}

// ─── setValidStyle ────────────────────────────────────────────────────────────
void FilterBar::setValidStyle(bool valid) {
    input_->setStyleSheet(valid ? STYLE_INPUT_OK : STYLE_INPUT_ERR);
}

// ─── setStatusOk ─────────────────────────────────────────────────────────────
void FilterBar::setStatusOk(const QString& msg) {
    status_lbl_->setText(msg.isEmpty() ? "✔ OK" : msg);
    status_lbl_->setStyleSheet(
        "QLabel { background: transparent;"
        "         color: #227744; font-size: 9px; }");
}

// ─── setStatusErr ─────────────────────────────────────────────────────────────
void FilterBar::setStatusErr(const QString& msg) {
    status_lbl_->setText("✕ " + msg);
    status_lbl_->setStyleSheet(
        "QLabel { background: transparent;"
        "         color: #cc2222; font-size: 9px; }");
}

// ─── parseFilter ─────────────────────────────────────────────────────────────
DisplayFilter FilterBar::parseFilter(const QString& expr) const {
    DisplayFilter f;
    f.raw_expr = expr.toStdString();
    f.valid    = true;

    const QString e = expr.trimmed().toLower();

    if (e == "tcp")   { f.proto_filter = DisplayFilter::Proto::TCP;  return f; }
    if (e == "udp")   { f.proto_filter = DisplayFilter::Proto::UDP;  return f; }
    if (e == "icmp")  { f.proto_filter = DisplayFilter::Proto::ICMP; return f; }
    if (e == "http")  { f.proto_filter = DisplayFilter::Proto::HTTP; return f; }
    if (e == "https") { f.proto_filter = DisplayFilter::Proto::HTTP; return f; }
    if (e == "dns")   { f.proto_filter = DisplayFilter::Proto::DNS;  return f; }
    if (e == "arp")   { f.proto_filter = DisplayFilter::Proto::ARP;  return f; }

    QStringList tokens;
    if (e.contains("&&"))
        tokens = e.split("&&");
    else if (e.contains(" and "))
        tokens = e.split(" and ");
    else
        tokens = { e };

    for (const auto& token : tokens) {
        const QString t = token.trimmed();
        if (t.isEmpty()) continue;

        DisplayFilter::Condition cond;
        if (!parseCondition(t, cond)) {
            f.valid     = false;
            f.error_msg = "Invalid: \"" + t.toStdString() + "\"";
            return f;
        }
        f.conditions.push_back(cond);
    }

    return f;
}

// ─── parseCondition ──────────────────────────────────────────────────────────
bool FilterBar::parseCondition(const QString&            token,
                                 DisplayFilter::Condition& cond) const {
    if (token.startsWith("tcp.flags.")) {
        cond.field = DisplayFilter::Field::TCP_FLAGS;
        cond.op    = DisplayFilter::Op::EQ;

        if      (token.contains("syn")) cond.value = "SYN";
        else if (token.contains("ack")) cond.value = "ACK";
        else if (token.contains("rst")) cond.value = "RST";
        else if (token.contains("fin")) cond.value = "FIN";
        else if (token.contains("psh")) cond.value = "PSH";
        else if (token.contains("urg")) cond.value = "URG";
        else return false;

        if (token.contains("!= 1") || token.contains("== 0"))
            cond.op = DisplayFilter::Op::NEQ;

        return true;
    }

    struct OpToken { QString str; DisplayFilter::Op op; };
    static const std::vector<OpToken> OPS = {
        {"!=",       DisplayFilter::Op::NEQ},
        {">=",       DisplayFilter::Op::GTE},
        {"<=",       DisplayFilter::Op::LTE},
        {">",        DisplayFilter::Op::GT},
        {"<",        DisplayFilter::Op::LT},
        {"==",       DisplayFilter::Op::EQ},
        {"contains", DisplayFilter::Op::CONTAINS},
    };

    for (const auto& op_tok : OPS) {
        const int idx = token.indexOf(op_tok.str);
        if (idx < 0) continue;

        const QString field_str = token.left(idx).trimmed();
        const QString value_str = token.mid(idx + op_tok.str.length()).trimmed();

        if (value_str.isEmpty()) return false;

        cond.op    = op_tok.op;
        cond.value = value_str.toStdString();

        if      (field_str == "ip.src")
            cond.field = DisplayFilter::Field::SRC_IP;
        else if (field_str == "ip.dst")
            cond.field = DisplayFilter::Field::DST_IP;
        else if (field_str == "tcp.srcport" || field_str == "udp.srcport")
            cond.field = DisplayFilter::Field::SRC_PORT;
        else if (field_str == "tcp.dstport" || field_str == "udp.dstport")
            cond.field = DisplayFilter::Field::DST_PORT;
        else if (field_str == "tcp.port"    || field_str == "udp.port")
            cond.field = DisplayFilter::Field::DST_PORT;
        else if (field_str == "frame.len")
            cond.field = DisplayFilter::Field::FRAME_LEN;
        else if (field_str == "threat")
            cond.field = DisplayFilter::Field::THREAT;
        else
            return false;

        return true;
    }

    return false;
}
