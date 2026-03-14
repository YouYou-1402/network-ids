// src/ui/qt/packet_list_model.cpp
#include "packet_list_model.hpp"
#include <QFont>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <algorithm>
#include <stdexcept>

// ─── Column headers ───────────────────────────────────────────────────────────
static const QStringList HEADERS = {
    "No.", "Time", "Source", "Destination",
    "Protocol", "Length", "Info", "Threat"
};

// ─────────────────────────────────────────────────────────────────────────────
// File-scope helpers
// ─────────────────────────────────────────────────────────────────────────────

static QString ipv4ToString(uint32_t ip_host) {
    // PacketInfo::src_ip / dst_ip được lưu dạng HOST byte order
    // (sau ntohl() trong decodeIPv4) → cần hton lại trước khi inet_ntoa
    if (ip_host == 0) return {};
    struct in_addr a{};
    a.s_addr = htonl(ip_host);   // ← host → network để inet_ntoa đúng
    return QString::fromLatin1(inet_ntoa(a));
}

static QString ipv6FromRaw(const PacketInfo& r, bool is_src) {
    if (!r.raw_data) return {};
    const auto& raw = *r.raw_data;

    constexpr size_t ETH_HDR = 14;
    constexpr size_t IP6_MIN = ETH_HDR + 40;
    if (raw.size() < IP6_MIN) return {};

    const uint16_t eth_type =
        (static_cast<uint16_t>(raw[12]) << 8) | raw[13];
    if (eth_type != 0x86DD) return {};

    const uint8_t* ip6  = raw.data() + ETH_HDR;
    const uint8_t* addr = is_src ? (ip6 + 8) : (ip6 + 24);

    char buf[INET6_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET6, addr, buf, sizeof(buf)))
        return QString::fromLatin1(buf);
    return {};
}

static QString buildAddrString(const PacketInfo& r, bool is_src) {
    // 1. IPv4 (host byte order)
    const uint32_t ip4 = is_src ? r.src_ip : r.dst_ip;
    QString ip_str = ipv4ToString(ip4);

    // 2. IPv6 từ struct field
    if (ip_str.isEmpty() && r.eth_type == 0x86DD) {
        const auto& ip6arr = is_src ? r.src_ip6 : r.dst_ip6;
        const bool has_ip6 = std::any_of(ip6arr.begin(), ip6arr.end(),
                                          [](uint8_t b){ return b != 0; });
        if (has_ip6) {
            char buf[INET6_ADDRSTRLEN]{};
            if (inet_ntop(AF_INET6, ip6arr.data(), buf, sizeof(buf)))
                ip_str = QString::fromLatin1(buf);
        }
    }

    // 3. IPv6 từ raw_data (fallback)
    if (ip_str.isEmpty() && r.eth_type == 0x86DD)
        ip_str = ipv6FromRaw(r, is_src);

    // 4. Thêm port nếu có
    if (!ip_str.isEmpty()) {
        const uint16_t port = is_src ? r.src_port : r.dst_port;
        if (port != 0)
            ip_str += ':' + QString::number(port);
        return ip_str;
    }

    // 5. Fallback label
    switch (r.eth_type) {
        case 0x0806: return "ARP";
        case 0x8100: return "VLAN";
        default:
            if (r.eth_type != 0 && r.eth_type != 0x0800)
                return QString("0x%1").arg(r.eth_type, 4, 16, QChar('0'));
            return {};
    }
}

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
QVariant PacketListModel::headerData(int             section,
                                      Qt::Orientation orientation,
                                      int             role) const {
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
        return (section < HEADERS.size()) ? HEADERS[section] : QVariant{};
    return {};
}

// ─── data ─────────────────────────────────────────────────────────────────────
QVariant PacketListModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid()) return {};

    const int row = index.row();
    if (row < 0 || row >= static_cast<int>(row_cache_.size()))
        return {};

    const RowCache& c = row_cache_[static_cast<size_t>(row)];

    if (role == Qt::BackgroundRole)    return c.bg_color;
    if (role == Qt::ForegroundRole)    return QColor("#dddddd");
    if (role == Qt::FontRole)          return QFont("Monospace", 10);

    if (role == Qt::TextAlignmentRole) {
        const int col = index.column();
        if (col == COL_NO || col == COL_LEN || col == COL_PROTO)
            return Qt::AlignCenter;
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    }

    if (role != Qt::DisplayRole) return {};

    switch (index.column()) {
        // ✅ frame_no = r.index + 1, cố định, không đổi khi filter
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

// ─── buildRowCache ────────────────────────────────────────────────────────────
PacketListModel::RowCache
PacketListModel::buildRowCache(const PacketInfo& r) const {
    RowCache c;
    // frame_no = index + 1 (1-based), gán 1 lần, bất biến
    c.frame_no = r.index + 1;
    c.pkt_idx  = r.index;
    c.orig_len = r.orig_len;
    c.bg_color = computeRowColor(r);
    c.proto    = computeProto(r);
    c.info     = computeInfo(r);
    c.threat   = QString::fromStdString(r.threat_type);
    c.src      = buildAddrString(r, /*is_src=*/true);
    c.dst      = buildAddrString(r, /*is_src=*/false);

    const double base = (base_timestamp_ >= 0.0) ? base_timestamp_
                                                  : r.timestamp_d;
    c.time_str = QString::number(r.timestamp_d - base, 'f', 6);
    return c;
}

// ─── appendRecords ────────────────────────────────────────────────────────────
void PacketListModel::appendRecords(const std::vector<PacketInfo>& batch) {
    if (batch.empty()) return;

    std::vector<RowCache> new_cache;
    new_cache.reserve(batch.size());

    for (const auto& r : batch) {
        if (base_timestamp_ < 0.0)
            base_timestamp_ = r.timestamp_d;
        if (!matchRecord(r, current_filter_)) continue;
        new_cache.push_back(buildRowCache(r));
    }

    if (new_cache.empty()) return;

    if (new_cache.size() > static_cast<size_t>(SCROLL_CHUNK))
        new_cache.resize(static_cast<size_t>(SCROLL_CHUNK));

    const int overflow = static_cast<int>(row_cache_.size())
                       + static_cast<int>(new_cache.size())
                       - MAX_DISPLAY_ROWS;
    if (overflow > 0) {
        beginRemoveRows(QModelIndex{}, 0, overflow - 1);
        for (int i = 0; i < overflow; ++i) {
            filtered_indices_.pop_front();
            row_cache_.pop_front();
        }
        endRemoveRows();
    }

    const int first = static_cast<int>(row_cache_.size());
    const int last  = first + static_cast<int>(new_cache.size()) - 1;

    beginInsertRows(QModelIndex{}, first, last);
    for (auto& c : new_cache) {
        filtered_indices_.push_back(c.pkt_idx);
        row_cache_.push_back(std::move(c));
    }
    endInsertRows();
}

// ─── applyFilter ──────────────────────────────────────────────────────────────
void PacketListModel::applyFilter(const DisplayFilter& filter) {
    beginResetModel();

    current_filter_ = filter;
    filtered_indices_.clear();
    row_cache_.clear();
    base_timestamp_ = -1.0;

    const uint64_t total  = ring_buf_.totalReceived();
    const uint64_t oldest = ring_buf_.oldestIndex();
    const uint64_t from   = (total > static_cast<uint64_t>(MAX_DISPLAY_ROWS))
                          ? total - static_cast<uint64_t>(MAX_DISPLAY_ROWS)
                          : oldest;

    const auto snapshot = ring_buf_.getSnapshot(from, total);

    for (const auto& r : snapshot) {
        if (!matchRecord(r, filter)) continue;
        if (base_timestamp_ < 0.0) base_timestamp_ = r.timestamp_d;
        filtered_indices_.push_back(r.index);
        row_cache_.push_back(buildRowCache(r));
        // frame_no = r.index + 1 → cố định, không phụ thuộc thứ tự filter
    }

    endResetModel();
}

// ─── clear ────────────────────────────────────────────────────────────────────
void PacketListModel::clear() {
    beginResetModel();
    filtered_indices_.clear();
    row_cache_.clear();
    base_timestamp_ = -1.0;
    endResetModel();
}

// ─── recordAt ─────────────────────────────────────────────────────────────────
std::shared_ptr<PacketInfo> PacketListModel::recordAt(int row) const {
    if (row < 0 || row >= static_cast<int>(filtered_indices_.size()))
        return nullptr;
    return ring_buf_.getByIndex(filtered_indices_[static_cast<size_t>(row)]);
}

// ─── evalOp ───────────────────────────────────────────────────────────────────
/*static*/
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

// ─── applyOp ──────────────────────────────────────────────────────────────────
/*static*/
bool PacketListModel::applyOp(DisplayFilter::Op op, bool eq) {
    if (op == DisplayFilter::Op::EQ)  return  eq;
    if (op == DisplayFilter::Op::NEQ) return !eq;
    return true;
}

// ─── matchRecord ──────────────────────────────────────────────────────────────
bool PacketListModel::matchRecord(const PacketInfo&  pkt,
                                   const DisplayFilter& f) const {
    if (!f.valid) return true;

    // ── Protocol shortcut ─────────────────────────────────────────────────────
    if (f.proto_filter != DisplayFilter::Proto::ANY) {
        const QString proto = computeProto(pkt);
        bool proto_match = false;
        switch (f.proto_filter) {
            case DisplayFilter::Proto::TCP:
                proto_match = (proto == "TCP");         break;
            case DisplayFilter::Proto::UDP:
                proto_match = (proto == "UDP");         break;
            case DisplayFilter::Proto::ICMP:
                proto_match = (proto == "ICMP");        break;
            case DisplayFilter::Proto::HTTP:
                proto_match = (proto == "HTTP");        break;
            case DisplayFilter::Proto::DNS:
                proto_match = (proto == "DNS");         break;
            case DisplayFilter::Proto::ARP:
                proto_match = (pkt.eth_type == 0x0806); break;
            default:
                proto_match = true;                     break;
        }
        if (!proto_match) return false;
        if (f.conditions.empty()) return true;
    }

    // ── Conditions — AND logic ────────────────────────────────────────────────
    for (const auto& cond : f.conditions) {
        switch (cond.field) {

            // ── ip.src ────────────────────────────────────────────────────────
            case DisplayFilter::Field::SRC_IP: {
                bool eq = false;
                if (cond.value.find(':') != std::string::npos) {
                    // IPv6
                    char buf[INET6_ADDRSTRLEN]{};
                    inet_ntop(AF_INET6, pkt.src_ip6.data(), buf, sizeof(buf));
                    eq = (std::string(buf) == cond.value);
                } else {
                    // IPv4: pkt.src_ip là HOST byte order (sau ntohl trong decoder)
                    // inet_pton trả về NETWORK byte order → cần htonl để so sánh
                    struct in_addr a{};
                    if (inet_pton(AF_INET, cond.value.c_str(), &a) == 1)
                        eq = (pkt.src_ip == ntohl(a.s_addr));  // ✅ fix byte order
                }
                if (!applyOp(cond.op, eq)) return false;
                break;
            }

            // ── ip.dst ────────────────────────────────────────────────────────
            case DisplayFilter::Field::DST_IP: {
                bool eq = false;
                if (cond.value.find(':') != std::string::npos) {
                    char buf[INET6_ADDRSTRLEN]{};
                    inet_ntop(AF_INET6, pkt.dst_ip6.data(), buf, sizeof(buf));
                    eq = (std::string(buf) == cond.value);
                } else {
                    struct in_addr a{};
                    if (inet_pton(AF_INET, cond.value.c_str(), &a) == 1)
                        eq = (pkt.dst_ip == ntohl(a.s_addr));  // ✅ fix byte order
                }
                if (!applyOp(cond.op, eq)) return false;
                break;
            }

            // ── src port ──────────────────────────────────────────────────────
            case DisplayFilter::Field::SRC_PORT: {
                try {
                    const uint16_t port =
                        static_cast<uint16_t>(std::stoul(cond.value));
                    if (!evalOp(cond.op, pkt.src_port, port)) return false;
                } catch (const std::exception&) { return false; }
                break;
            }

            // ── dst port ──────────────────────────────────────────────────────
            case DisplayFilter::Field::DST_PORT: {
                try {
                    const uint16_t port =
                        static_cast<uint16_t>(std::stoul(cond.value));
                    if (!evalOp(cond.op, pkt.dst_port, port)) return false;
                } catch (const std::exception&) { return false; }
                break;
            }

            // ── protocol ──────────────────────────────────────────────────────
            case DisplayFilter::Field::PROTOCOL: {
                const bool eq =
                    (computeProto(pkt).toLower().toStdString() == cond.value);
                if (!applyOp(cond.op, eq)) return false;
                break;
            }

            // ── tcp.flags.* ───────────────────────────────────────────────────
            case DisplayFilter::Field::TCP_FLAGS: {
                uint8_t mask = 0;
                if      (cond.value == "SYN") mask = 0x02;
                else if (cond.value == "ACK") mask = 0x10;
                else if (cond.value == "RST") mask = 0x04;
                else if (cond.value == "FIN") mask = 0x01;
                else if (cond.value == "PSH") mask = 0x08;
                else if (cond.value == "URG") mask = 0x20;
                if (mask == 0) return false;
                const bool has = (pkt.tcp_flags & mask) != 0;
                if (!applyOp(cond.op, has)) return false;
                break;
            }

            // ── threat ────────────────────────────────────────────────────────
            case DisplayFilter::Field::THREAT: {
                std::string threat = pkt.threat_type;
                std::transform(threat.begin(), threat.end(),
                               threat.begin(), ::tolower);
                const bool has = !threat.empty() &&
                                  threat.find(cond.value) != std::string::npos;
                if (!applyOp(cond.op, has)) return false;
                break;
            }

            default: break;
        }
    }
    return true;
}

// ─── computeProto ─────────────────────────────────────────────────────────────
QString PacketListModel::computeProto(const PacketInfo& r) const {
    if (r.protocol == 0) {
        switch (r.eth_type) {
            case 0x0806: return "ARP";
            case 0x86DD: return "IPv6";
            case 0x8100: return "VLAN";
            case 0x0800: break;
            default:
                if (r.eth_type != 0)
                    return QString("ETH(0x%1)")
                               .arg(r.eth_type, 4, 16, QChar('0'));
                return "UNKNOWN";
        }
    }

    // ARP sentinel từ decoder
    if (r.protocol == 0xFE) return "ARP";
    // IPv6 sentinel từ decoder
    if (r.protocol == 0xFF) return "IPv6";

    if (r.eth_type == 0x86DD && r.protocol == 58)
        return "ICMPv6";

    switch (r.protocol) {
        case IPPROTO_TCP: {
            if (r.src_port == 80   || r.dst_port == 80   ||
                r.src_port == 8080 || r.dst_port == 8080)  return "HTTP";
            if (r.src_port == 443  || r.dst_port == 443)   return "HTTPS";
            if (r.src_port == 22   || r.dst_port == 22)    return "SSH";
            if (r.src_port == 21   || r.dst_port == 21)    return "FTP";
            if (r.src_port == 25   || r.dst_port == 25)    return "SMTP";
            if (r.src_port == 3306 || r.dst_port == 3306)  return "MySQL";
            return "TCP";
        }
        case IPPROTO_UDP: {
            if (r.src_port == 53  || r.dst_port == 53)    return "DNS";
            if (r.src_port == 67  || r.dst_port == 67 ||
                r.src_port == 68  || r.dst_port == 68)    return "DHCP";
            if (r.src_port == 123 || r.dst_port == 123)   return "NTP";
            if (r.src_port == 161 || r.dst_port == 161)   return "SNMP";
            return "UDP";
        }
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        default:
            return QString("IP(%1)").arg(r.protocol);
    }
}

// ─── computeInfo ──────────────────────────────────────────────────────────────
QString PacketListModel::computeInfo(const PacketInfo& r) const {
    if (r.eth_type == 0x0806 || r.protocol == 0xFE)
        return "ARP";

    if (r.protocol == IPPROTO_TCP) {
        QStringList flags;
        if (r.tcp_flags & 0x02) flags << "SYN";
        if (r.tcp_flags & 0x10) flags << "ACK";
        if (r.tcp_flags & 0x04) flags << "RST";
        if (r.tcp_flags & 0x01) flags << "FIN";
        if (r.tcp_flags & 0x08) flags << "PSH";
        if (r.tcp_flags & 0x20) flags << "URG";

        const QString flag_str = flags.isEmpty()
            ? QString{} : '[' + flags.join(", ") + "] ";
        return QString("%1%2 \u2192 %3  len=%4")
            .arg(flag_str)
            .arg(r.src_port)
            .arg(r.dst_port)
            .arg(r.payload_len);
    }
    if (r.protocol == IPPROTO_UDP)
        return QString("UDP  %1 \u2192 %2  len=%3")
            .arg(r.src_port).arg(r.dst_port).arg(r.payload_len);
    if (r.protocol == IPPROTO_ICMP)
        return "ICMP message";
    if (r.protocol == 58)
        return "ICMPv6 message";

    return QString("len=%1").arg(r.orig_len);
}

// ─── computeRowColor ──────────────────────────────────────────────────────────
QColor PacketListModel::computeRowColor(const PacketInfo& r) const {
    if (!r.threat_type.empty()) {
        if (r.threat_type.find("DDOS_VOLUMETRIC") != std::string::npos)
            return QColor(60, 15, 15);
        if (r.threat_type.find("SLOW_DDOS")       != std::string::npos)
            return QColor(55, 50, 10);
        if (r.threat_type.find("PORT_SCAN")        != std::string::npos)
            return QColor(60, 38, 10);
        return QColor(50, 10, 10);
    }

    if (r.eth_type == 0x0806) return QColor(25, 25, 10);
    if (r.eth_type == 0x86DD) return QColor(10, 25, 25);

    switch (r.protocol) {
        case IPPROTO_TCP: {
            if (r.tcp_flags & 0x04) return QColor(40, 10, 10);
            if (r.tcp_flags & 0x02) return QColor(15, 35, 15);
            if (r.src_port == 80   || r.dst_port == 80   ||
                r.src_port == 8080 || r.dst_port == 8080)
                return QColor(15, 25, 45);
            if (r.src_port == 443  || r.dst_port == 443)
                return QColor(20, 30, 50);
            return QColor(15, 15, 30);
        }
        case IPPROTO_UDP:
            if (r.src_port == 53 || r.dst_port == 53)
                return QColor(35, 20, 45);
            return QColor(20, 20, 35);
        case IPPROTO_ICMP: return QColor(10, 35, 35);
        case 58:           return QColor(10, 30, 30);
        default:           return QColor(15, 15, 15);
    }
}