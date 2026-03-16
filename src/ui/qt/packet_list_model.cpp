// src/ui/qt/packet_list_model.cpp
#include "packet_list_model.hpp"
#include <QFont>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <algorithm>
#include <cctype>

static const QStringList HEADERS = {
    "No.", "Time", "Source", "Destination",
    "Protocol", "Length", "Info", "Threat"
};

// ─── Constructor ──────────────────────────────────────────────────────────────
PacketListModel::PacketListModel(PacketRingBuffer& ring_buf, QObject* parent)
    : QAbstractTableModel(parent)
    , ring_buf_(ring_buf)
{}

// ─── rowCount / columnCount ───────────────────────────────────────────────────
int PacketListModel::rowCount(const QModelIndex&) const {
    return static_cast<int>(row_cache_.size());
}
int PacketListModel::columnCount(const QModelIndex&) const {
    return COL_COUNT;
}

// ─── headerData ───────────────────────────────────────────────────────────────
QVariant PacketListModel::headerData(int section,
                                      Qt::Orientation orientation,
                                      int role) const {
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
        return (section < HEADERS.size()) ? HEADERS[section] : QVariant{};
    return {};
}

// ─── data ─────────────────────────────────────────────────────────────────────
QVariant PacketListModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid()) return {};
    const int row = index.row();
    if (row < 0 || row >= static_cast<int>(row_cache_.size())) return {};

    const RowCache& c = row_cache_[static_cast<size_t>(row)];

    if (role == Qt::BackgroundRole)    return c.bg_color;
    if (role == Qt::ForegroundRole)    return QColor("#dddddd");
    if (role == Qt::FontRole)          return QFont("Monospace", 10);
    if (role == Qt::TextAlignmentRole) {
        const int col = index.column();
        if (col == COL_NO || col == COL_LEN || col == COL_PROTO)
            return int(Qt::AlignCenter);
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    }
    if (role != Qt::DisplayRole) return {};

    switch (index.column()) {
        case COL_NO:     return QString::number(c.frame_no);
        case COL_TIME:   return c.time_str;
        case COL_SRC_IP: return c.src;
        case COL_DST_IP: return c.dst;
        case COL_PROTO:  return c.proto;
        case COL_LEN:    return QString::number(c.orig_len);
        case COL_INFO:   return c.info;
        case COL_THREAT: return c.threat;
        default:         return {};
    }
}

// ─── appendRecords ────────────────────────────────────────────────────────────
void PacketListModel::appendRecords(const std::vector<PacketInfo>& batch) {
    if (batch.empty()) return;

    std::vector<RowCache> incoming;
    incoming.reserve(batch.size());

    for (const auto& pkt : batch) {
        if (base_ts_ < 0.0) base_ts_ = pkt.timestamp_d;
        if (!matchRecord(pkt, current_filter_)) continue;
        incoming.push_back(buildRowCache(pkt));
    }
    if (incoming.empty()) return;

    if (static_cast<int>(incoming.size()) > MAX_DISPLAY_ROWS) {
        const size_t keep_from = incoming.size()
                               - static_cast<size_t>(MAX_DISPLAY_ROWS);
        incoming.erase(incoming.begin(),
                       incoming.begin() + static_cast<ptrdiff_t>(keep_from));
        if (!row_cache_.empty()) {
            beginRemoveRows({}, 0, static_cast<int>(row_cache_.size()) - 1);
            row_cache_.clear(); pkt_indices_.clear();
            endRemoveRows();
        }
    } else {
        const int total_after = static_cast<int>(row_cache_.size())
                              + static_cast<int>(incoming.size());
        if (total_after > MAX_DISPLAY_ROWS) {
            const int drop = std::min(total_after - MAX_DISPLAY_ROWS,
                                      static_cast<int>(row_cache_.size()));
            if (drop > 0) {
                beginRemoveRows({}, 0, drop - 1);
                for (int i = 0; i < drop; ++i) {
                    pkt_indices_.pop_front();
                    row_cache_.pop_front();
                }
                endRemoveRows();
            }
        }
    }

    const int first = static_cast<int>(row_cache_.size());
    const int last  = first + static_cast<int>(incoming.size()) - 1;
    beginInsertRows({}, first, last);
    for (auto& c : incoming) {
        pkt_indices_.push_back(c.pkt_idx);
        row_cache_.push_back(std::move(c));
    }
    endInsertRows();
}

// ─── applyFilter ──────────────────────────────────────────────────────────────
void PacketListModel::applyFilter(const DisplayFilter& filter) {
    beginResetModel();
    current_filter_ = filter;
    row_cache_.clear();
    pkt_indices_.clear();
    base_ts_ = -1.0;

    const uint64_t total   = ring_buf_.totalPushed();
    const uint64_t oldest  = ring_buf_.oldestIndex();
    const uint64_t max_row = static_cast<uint64_t>(MAX_DISPLAY_ROWS);
    const uint64_t from    = (total > max_row)
                           ? std::max(total - max_row, oldest)
                           : oldest;
    const uint64_t count   = (total > from) ? (total - from) : 0;

    // FIX: dùng pollRange thay vì pollNew để không thay đổi state ngoài ý muốn
    const auto snapshot = ring_buf_.pollRange(from, count);

    for (const auto& pkt : snapshot) {
        if (base_ts_ < 0.0) base_ts_ = pkt.timestamp_d;
        if (!matchRecord(pkt, filter)) continue;
        pkt_indices_.push_back(pkt.index);
        row_cache_.push_back(buildRowCache(pkt));
    }

    endResetModel();
}

// ─── clear ────────────────────────────────────────────────────────────────────
void PacketListModel::clear() {
    beginResetModel();
    row_cache_.clear();
    pkt_indices_.clear();
    base_ts_ = -1.0;
    endResetModel();
}

// ─── getRecord ────────────────────────────────────────────────────────────────
// FIX: ưu tiên dùng cached_pkt — không phụ thuộc raw_data còn sống
// trong ring buffer. Fallback về ring buffer chỉ khi cache không có.
bool PacketListModel::getRecord(int row, PacketInfo& out) const {
    if (row < 0 || row >= static_cast<int>(row_cache_.size()))
        return false;
    out = row_cache_[static_cast<size_t>(row)].meta;
    return true;
}

void PacketListModel::updateRawData(
    int row,
    std::shared_ptr<std::vector<uint8_t>> raw_data)
{
    if (row < 0 || row >= static_cast<int>(row_cache_.size())) return;
    row_cache_[static_cast<size_t>(row)].meta.raw_data = std::move(raw_data);
}
// ─── ipv4Str ──────────────────────────────────────────────────────────────────
QString PacketListModel::ipv4Str(uint32_t ip_net) {
    if (ip_net == 0) return {};
    char buf[INET_ADDRSTRLEN]{};
    struct in_addr a{};
    a.s_addr = ip_net;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return QString::fromLatin1(buf);
}

// ─── ipv6Str ──────────────────────────────────────────────────────────────────
QString PacketListModel::ipv6Str(const std::array<uint8_t, 16>& ip6) {
    const bool all_zero = std::all_of(ip6.begin(), ip6.end(),
                                       [](uint8_t b){ return b == 0; });
    if (all_zero) return {};
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, ip6.data(), buf, sizeof(buf));
    return QString::fromLatin1(buf);
}

// ─── addrStr ──────────────────────────────────────────────────────────────────
QString PacketListModel::addrStr(const PacketInfo& pkt, bool is_src) {
    QString ip;

    if (pkt.is_ipv6) {
        ip = ipv6Str(is_src ? pkt.src_ip6 : pkt.dst_ip6);
    } else if (pkt.eth_type == EtherType::IPv4) {
        ip = ipv4Str(is_src ? pkt.src_ip : pkt.dst_ip);
    } else {
        switch (pkt.eth_type) {
            case EtherType::ARP:  return "ARP";
            case EtherType::VLAN: return "VLAN";
            default:
                if (pkt.eth_type != 0)
                    return QString("0x%1").arg(pkt.eth_type, 4, 16, QChar('0'));
                return {};
        }
    }

    if (ip.isEmpty()) return {};

    const uint16_t port = is_src ? pkt.src_port : pkt.dst_port;
    if (port != 0)
        ip += ':' + QString::number(port);
    return ip;
}

// ─── buildRowCache ────────────────────────────────────────────────────────────
// FIX: cache toàn bộ PacketInfo vào cached_pkt
// → shared_ptr giữ raw_data alive ngay cả khi ring buffer evict slot đó
PacketListModel::RowCache
PacketListModel::buildRowCache(const PacketInfo& pkt) const {
    RowCache c;
    c.frame_no = pkt.capture_seq + 1;
    c.pkt_idx  = pkt.index;
    c.orig_len = pkt.orig_len;
    c.bg_color = computeRowColor(pkt);
    c.proto    = computeProto(pkt);
    c.info     = computeInfo(pkt);
    c.threat   = QString::fromStdString(pkt.threat_type);
    c.src      = addrStr(pkt, true);
    c.dst      = addrStr(pkt, false);

    const double base = (base_ts_ >= 0.0) ? base_ts_ : pkt.timestamp_d;
    c.time_str = QString::number(pkt.timestamp_d - base, 'f', 6);

    // Lưu metadata — raw_data bị drop ở đây (reset nếu có)
    c.meta          = pkt;
    c.meta.raw_data.reset();   // ← không giữ raw bytes trong model

    return c;
}
// ─── matchRecord ──────────────────────────────────────────────────────────────
bool PacketListModel::matchRecord(const PacketInfo& pkt,
                                   const DisplayFilter& f) const {
    if (!f.valid) return true;

    if (f.proto_filter != DisplayFilter::Proto::ANY) {
        const QString proto = computeProto(pkt);
        bool ok = false;
        switch (f.proto_filter) {
            case DisplayFilter::Proto::TCP:  ok = (proto == "TCP");  break;
            case DisplayFilter::Proto::UDP:  ok = (proto == "UDP");  break;
            case DisplayFilter::Proto::ICMP: ok = (proto == "ICMP"); break;
            case DisplayFilter::Proto::HTTP: ok = (proto == "HTTP"); break;
            case DisplayFilter::Proto::DNS:  ok = (proto == "DNS");  break;
            case DisplayFilter::Proto::ARP:
                ok = (pkt.eth_type == EtherType::ARP); break;
            default: ok = true; break;
        }
        if (!ok) return false;
        if (f.conditions.empty()) return true;
    }

    for (const auto& cond : f.conditions) {
        switch (cond.field) {

            case DisplayFilter::Field::SRC_IP: {
                bool eq = false;
                if (cond.value.find(':') != std::string::npos) {
                    eq = (ipv6Str(pkt.src_ip6).toStdString() == cond.value);
                } else {
                    struct in_addr a{};
                    if (inet_pton(AF_INET, cond.value.c_str(), &a) == 1)
                        eq = (pkt.src_ip == a.s_addr);
                }
                if (!applyOp(cond.op, eq)) return false;
                break;
            }

            case DisplayFilter::Field::DST_IP: {
                bool eq = false;
                if (cond.value.find(':') != std::string::npos) {
                    eq = (ipv6Str(pkt.dst_ip6).toStdString() == cond.value);
                } else {
                    struct in_addr a{};
                    if (inet_pton(AF_INET, cond.value.c_str(), &a) == 1)
                        eq = (pkt.dst_ip == a.s_addr);
                }
                if (!applyOp(cond.op, eq)) return false;
                break;
            }

            case DisplayFilter::Field::SRC_PORT: {
                try {
                    const auto port = static_cast<uint16_t>(
                        std::stoul(cond.value));
                    if (!evalOp(cond.op, pkt.src_port, port)) return false;
                } catch (...) { return false; }
                break;
            }

            case DisplayFilter::Field::DST_PORT: {
                try {
                    const auto port = static_cast<uint16_t>(
                        std::stoul(cond.value));
                    if (!evalOp(cond.op, pkt.dst_port, port)) return false;
                } catch (...) { return false; }
                break;
            }

            case DisplayFilter::Field::PROTOCOL: {
                const bool eq =
                    computeProto(pkt).toLower().toStdString() == cond.value;
                if (!applyOp(cond.op, eq)) return false;
                break;
            }

            case DisplayFilter::Field::TCP_FLAGS: {
                uint8_t mask = 0;
                if      (cond.value == "SYN") mask = TCPFlags::SYN;
                else if (cond.value == "ACK") mask = TCPFlags::ACK;
                else if (cond.value == "RST") mask = TCPFlags::RST;
                else if (cond.value == "FIN") mask = TCPFlags::FIN;
                else if (cond.value == "PSH") mask = TCPFlags::PSH;
                else if (cond.value == "URG") mask = TCPFlags::URG;
                if (mask == 0) return false;
                if (!applyOp(cond.op, (pkt.tcp_flags & mask) != 0))
                    return false;
                break;
            }

            case DisplayFilter::Field::THREAT: {
                std::string t = pkt.threat_type;
                std::transform(t.begin(), t.end(), t.begin(), ::tolower);
                const bool has = !t.empty() &&
                                  t.find(cond.value) != std::string::npos;
                if (!applyOp(cond.op, has)) return false;
                break;
            }

            default: break;
        }
    }
    return true;
}

// ─── computeProto ─────────────────────────────────────────────────────────────
QString PacketListModel::computeProto(const PacketInfo& pkt) const {
    switch (pkt.eth_type) {
        case EtherType::ARP:  return "ARP";
        case EtherType::VLAN: return "VLAN";
        case EtherType::IPv6:
            if (pkt.protocol == 0) return "IPv6";
            break;
        case EtherType::IPv4:
            break;
        default:
            if (pkt.eth_type != 0)
                return QString("ETH 0x%1").arg(pkt.eth_type, 4, 16, QChar('0'));
            return "UNKNOWN";
    }

    switch (pkt.protocol) {
        case IPPROTO_TCP: {
            if (pkt.src_port == 80   || pkt.dst_port == 80   ||
                pkt.src_port == 8080 || pkt.dst_port == 8080) return "HTTP";
            if (pkt.src_port == 443  || pkt.dst_port == 443)  return "HTTPS";
            if (pkt.src_port == 22   || pkt.dst_port == 22)   return "SSH";
            if (pkt.src_port == 21   || pkt.dst_port == 21)   return "FTP";
            if (pkt.src_port == 25   || pkt.dst_port == 25)   return "SMTP";
            if (pkt.src_port == 3306 || pkt.dst_port == 3306) return "MySQL";
            return "TCP";
        }
        case IPPROTO_UDP: {
            if (pkt.src_port == 53  || pkt.dst_port == 53)  return "DNS";
            if (pkt.src_port == 67  || pkt.dst_port == 67  ||
                pkt.src_port == 68  || pkt.dst_port == 68)  return "DHCP";
            if (pkt.src_port == 123 || pkt.dst_port == 123) return "NTP";
            if (pkt.src_port == 161 || pkt.dst_port == 161) return "SNMP";
            return "UDP";
        }
        case IPPROTO_ICMP:   return "ICMP";
        case IPPROTO_ICMPV6: return "ICMPv6";
        case IPPROTO_IGMP:   return "IGMP";
        default:
            return QString("IP(%1)").arg(pkt.protocol);
    }
}

// ─── computeInfo ──────────────────────────────────────────────────────────────
QString PacketListModel::computeInfo(const PacketInfo& pkt) const {
    if (pkt.eth_type == EtherType::ARP)
        return "ARP";

    switch (pkt.protocol) {
        case IPPROTO_TCP: {
            QStringList flags;
            if (pkt.hasSYN()) flags << "SYN";
            if (pkt.hasACK()) flags << "ACK";
            if (pkt.hasRST()) flags << "RST";
            if (pkt.hasFIN()) flags << "FIN";
            if (pkt.hasPSH()) flags << "PSH";
            if (pkt.hasURG()) flags << "URG";
            const QString fs = flags.isEmpty()
                ? QString{} : '[' + flags.join(", ") + "] ";
            return QString("%1%2 \u2192 %3  len=%4")
                .arg(fs).arg(pkt.src_port).arg(pkt.dst_port)
                .arg(pkt.payload_len);
        }
        case IPPROTO_UDP:
            return QString("UDP %1 \u2192 %2  len=%3")
                .arg(pkt.src_port).arg(pkt.dst_port).arg(pkt.payload_len);
        case IPPROTO_ICMP:   return "ICMP message";
        case IPPROTO_ICMPV6: return "ICMPv6 message";
        default:
            return QString("len=%1").arg(pkt.orig_len);
    }
}

// ─── computeRowColor ──────────────────────────────────────────────────────────
QColor PacketListModel::computeRowColor(const PacketInfo& pkt) const {
    if (!pkt.threat_type.empty()) {
        if (pkt.threat_type.find("DDOS_VOLUMETRIC") != std::string::npos)
            return {60, 15, 15};
        if (pkt.threat_type.find("SLOW_DDOS")       != std::string::npos)
            return {55, 50, 10};
        if (pkt.threat_type.find("PORT_SCAN")        != std::string::npos)
            return {60, 38, 10};
        return {50, 10, 10};
    }
    if (pkt.eth_type == EtherType::ARP)  return {25, 25, 10};
    if (pkt.eth_type == EtherType::IPv6) return {10, 25, 25};

    switch (pkt.protocol) {
        case IPPROTO_TCP:
            if (pkt.hasRST()) return {40, 10, 10};
            if (pkt.hasSYN()) return {15, 35, 15};
            if (pkt.src_port == 80   || pkt.dst_port == 80   ||
                pkt.src_port == 8080 || pkt.dst_port == 8080) return {15, 25, 45};
            if (pkt.src_port == 443  || pkt.dst_port == 443)  return {20, 30, 50};
            return {15, 15, 30};
        case IPPROTO_UDP:
            if (pkt.src_port == 53 || pkt.dst_port == 53) return {35, 20, 45};
            return {20, 20, 35};
        case IPPROTO_ICMP:   return {10, 35, 35};
        case IPPROTO_ICMPV6: return {10, 30, 30};
        default:             return {15, 15, 15};
    }
}

// ─── evalOp / applyOp ─────────────────────────────────────────────────────────
bool PacketListModel::evalOp(DisplayFilter::Op op,
                               uint16_t lhs, uint16_t rhs) {
    switch (op) {
        case DisplayFilter::Op::EQ:  return lhs == rhs;
        case DisplayFilter::Op::NEQ: return lhs != rhs;
        case DisplayFilter::Op::GT:  return lhs >  rhs;
        case DisplayFilter::Op::LT:  return lhs <  rhs;
        case DisplayFilter::Op::GTE: return lhs >= rhs;
        case DisplayFilter::Op::LTE: return lhs <= rhs;
        default:                     return false;
    }
}

bool PacketListModel::applyOp(DisplayFilter::Op op, bool eq) {
    if (op == DisplayFilter::Op::EQ)  return  eq;
    if (op == DisplayFilter::Op::NEQ) return !eq;
    return true;
}
