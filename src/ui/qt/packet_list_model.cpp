// src/ui/qt/packet_list_model.cpp
#include "packet_list_model.hpp"
#include <QFont>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>   // struct ip6_hdr
#include <net/ethernet.h>  // ETH_HLEN

static const QStringList HEADERS = {
    "No.", "Time", "Source", "Destination",
    "Protocol", "Length", "Info", "Threat"
};

// ─── evalOp ───────────────────────────────────────────────────────────────────
static bool evalOp(DisplayFilter::Op op, uint16_t lhs, uint16_t rhs) {
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

// ─── ipv4ToString ─────────────────────────────────────────────────────────────
static QString ipv4ToString(uint32_t ip_net) {
    if (ip_net == 0) return {};
    struct in_addr a{};
    a.s_addr = ip_net;
    return QString::fromLatin1(inet_ntoa(a));
}

// ─── ipv6ToString ─────────────────────────────────────────────────────────────
// Đọc trực tiếp từ raw_data nếu src_ip6 chưa được parse
static QString ipv6FromRaw(const PacketRecord& r, bool is_src) {
    // Cần raw_data và đủ dài để chứa Ethernet + IPv6 header
    if (!r.raw_data) return {};
    const auto& raw = *r.raw_data;

    // Ethernet header = 14 bytes, IPv6 header = 40 bytes → tối thiểu 54 bytes
    constexpr size_t ETH_HDR  = 14;
    constexpr size_t IP6_HDR  = 40;
    constexpr size_t MIN_SIZE = ETH_HDR + IP6_HDR;

    if (raw.size() < MIN_SIZE) return {};

    // Kiểm tra eth_type = 0x86DD tại offset 12-13
    const uint16_t eth_type =
        (static_cast<uint16_t>(raw[12]) << 8) | raw[13];
    if (eth_type != 0x86DD) return {};

    // IPv6 header bắt đầu tại offset 14
    const uint8_t* ip6 = raw.data() + ETH_HDR;

    // src = offset 8..23, dst = offset 24..39 (trong IPv6 header)
    const uint8_t* addr = is_src ? (ip6 + 8) : (ip6 + 24);

    char buf[INET6_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET6, addr, buf, sizeof(buf)))
        return QString::fromLatin1(buf);
    return {};
}

// ─── buildAddrString ──────────────────────────────────────────────────────────
// Ưu tiên: IPv4 → IPv6 (từ raw_data) → fallback label
static QString buildAddrString(const PacketRecord& r,
                                bool                is_src) {
    // 1. IPv4
    const uint32_t ip4 = is_src ? r.src_ip : r.dst_ip;
    QString ip_str = ipv4ToString(ip4);

    // 2. IPv6 — đọc từ raw_data (không cần thêm field mới vào PacketRecord)
    if (ip_str.isEmpty() && r.eth_type == 0x86DD)
        ip_str = ipv6FromRaw(r, is_src);

    // 3. Có địa chỉ → thêm port nếu có
    if (!ip_str.isEmpty()) {
        const uint16_t port = is_src ? r.src_port : r.dst_port;
        if (port != 0)
            ip_str += ':' + QString::number(port);
        return ip_str;
    }

    // 4. Fallback label theo eth_type
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

    if (role == Qt::BackgroundRole)  return c.bg_color;
    if (role == Qt::ForegroundRole)  return QColor("#dddddd");
    if (role == Qt::FontRole)        return QFont("Monospace", 10);

    if (role == Qt::TextAlignmentRole) {
        const int col = index.column();
        if (col == COL_NO || col == COL_LEN || col == COL_PROTO)
            return Qt::AlignCenter;
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    }

    if (role != Qt::DisplayRole) return {};

    switch (index.column()) {
        case COL_NO:     return QString::number(c.pkt_idx + 1);
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
PacketListModel::buildRowCache(const PacketRecord& r) const {
    RowCache c;
    c.pkt_idx  = r.index;
    c.orig_len = r.orig_len;
    c.bg_color = computeRowColor(r);
    c.proto    = computeProto(r);
    c.info     = computeInfo(r);
    c.threat   = QString::fromStdString(r.threat_type);

    // ✅ Dùng buildAddrString — tự động IPv4 → IPv6(raw) → fallback
    c.src = buildAddrString(r, /*is_src=*/true);
    c.dst = buildAddrString(r, /*is_src=*/false);

    // ── Relative timestamp ────────────────────────────────────────────────────
    const double base = (base_timestamp_ >= 0.0) ? base_timestamp_
                                                  : r.timestamp;
    c.time_str = QString::number(r.timestamp - base, 'f', 6);

    return c;
}

// ─── appendRecords ────────────────────────────────────────────────────────────
void PacketListModel::appendRecords(const std::vector<PacketRecord>& batch) {
    if (batch.empty()) return;

    std::vector<RowCache> new_cache;
    new_cache.reserve(batch.size());

    for (const auto& r : batch) {
        if (base_timestamp_ < 0.0)
            base_timestamp_ = r.timestamp;

        bool pass = true;
        if (current_filter_.valid && !current_filter_.conditions.empty())
            pass = matchFilter(r.index, current_filter_);
        if (!pass) continue;

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

    const uint64_t total     = ring_buf_.totalReceived();
    const uint64_t oldest    = ring_buf_.oldestIndex();
    const uint64_t scan_from = (total > static_cast<uint64_t>(MAX_DISPLAY_ROWS))
                             ? total - static_cast<uint64_t>(MAX_DISPLAY_ROWS)
                             : oldest;

    for (uint64_t i = scan_from; i < total; ++i) {
        ring_buf_.withRecord(i, [&](const PacketRecord& r) {
            if (!matchFilter(i, filter)) return;
            if (base_timestamp_ < 0.0) base_timestamp_ = r.timestamp;
            filtered_indices_.push_back(i);
            row_cache_.push_back(buildRowCache(r));
        });
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
std::shared_ptr<PacketRecord> PacketListModel::recordAt(int row) const {
    if (row < 0 || row >= static_cast<int>(filtered_indices_.size()))
        return nullptr;
    return ring_buf_.getByIndex(filtered_indices_[static_cast<size_t>(row)]);
}

// ─── matchFilter ──────────────────────────────────────────────────────────────
bool PacketListModel::matchFilter(uint64_t             idx,
                                   const DisplayFilter& f) const {
    if (!f.valid || f.conditions.empty()) return true;

    bool result = false;
    ring_buf_.withRecord(idx, [&](const PacketRecord& rec) {
        if (f.proto_filter != DisplayFilter::Proto::ANY) {
            const QString proto = computeProto(rec);
            switch (f.proto_filter) {
                case DisplayFilter::Proto::TCP:
                    if (proto != "TCP")  return; break;
                case DisplayFilter::Proto::UDP:
                    if (proto != "UDP")  return; break;
                case DisplayFilter::Proto::ICMP:
                    if (proto != "ICMP") return; break;
                case DisplayFilter::Proto::HTTP:
                    if (proto != "HTTP") return; break;
                case DisplayFilter::Proto::DNS:
                    if (proto != "DNS")  return; break;
                default: break;
            }
        }

        for (const auto& cond : f.conditions) {
            switch (cond.field) {
                case DisplayFilter::Field::SRC_IP: {
                    // ✅ Tự detect IPv4 vs IPv6 từ chuỗi filter
                    if (cond.value.find(':') != std::string::npos) {
                        // IPv6 filter — so sánh với raw_data
                        const QString rec_ip6 = ipv6FromRaw(rec, true);
                        const bool eq = (rec_ip6.toStdString() == cond.value);
                        if (cond.op == DisplayFilter::Op::EQ  && !eq) return;
                        if (cond.op == DisplayFilter::Op::NEQ &&  eq) return;
                    } else {
                        // IPv4 filter
                        struct in_addr a{};
                        inet_pton(AF_INET, cond.value.c_str(), &a);
                        const bool eq = (rec.src_ip == a.s_addr);
                        if (cond.op == DisplayFilter::Op::EQ  && !eq) return;
                        if (cond.op == DisplayFilter::Op::NEQ &&  eq) return;
                    }
                    break;
                }
                case DisplayFilter::Field::DST_IP: {
                    if (cond.value.find(':') != std::string::npos) {
                        const QString rec_ip6 = ipv6FromRaw(rec, false);
                        const bool eq = (rec_ip6.toStdString() == cond.value);
                        if (cond.op == DisplayFilter::Op::EQ  && !eq) return;
                        if (cond.op == DisplayFilter::Op::NEQ &&  eq) return;
                    } else {
                        struct in_addr a{};
                        inet_pton(AF_INET, cond.value.c_str(), &a);
                        const bool eq = (rec.dst_ip == a.s_addr);
                        if (cond.op == DisplayFilter::Op::EQ  && !eq) return;
                        if (cond.op == DisplayFilter::Op::NEQ &&  eq) return;
                    }
                    break;
                }
                case DisplayFilter::Field::SRC_PORT: {
                    const uint16_t port = static_cast<uint16_t>(
                        std::stoul(cond.value));
                    if (!evalOp(cond.op, rec.src_port, port)) return;
                    break;
                }
                case DisplayFilter::Field::DST_PORT: {
                    const uint16_t port = static_cast<uint16_t>(
                        std::stoul(cond.value));
                    if (!evalOp(cond.op, rec.dst_port, port)) return;
                    break;
                }
                case DisplayFilter::Field::PROTOCOL: {
                    const bool eq = (computeProto(rec).toStdString()
                                     == cond.value);
                    if (cond.op == DisplayFilter::Op::EQ  && !eq) return;
                    if (cond.op == DisplayFilter::Op::NEQ &&  eq) return;
                    break;
                }
                case DisplayFilter::Field::TCP_FLAGS: {
                    const uint8_t mask = static_cast<uint8_t>(
                        std::stoul(cond.value, nullptr, 16));
                    const bool has = (rec.tcp_flags & mask) != 0;
                    if (cond.op == DisplayFilter::Op::EQ  && !has) return;
                    if (cond.op == DisplayFilter::Op::NEQ &&  has) return;
                    break;
                }
                case DisplayFilter::Field::THREAT: {
                    const bool has = !rec.threat_type.empty() &&
                                     rec.threat_type.find(cond.value)
                                         != std::string::npos;
                    if (cond.op == DisplayFilter::Op::EQ  && !has) return;
                    if (cond.op == DisplayFilter::Op::NEQ &&  has) return;
                    break;
                }
                default: break;
            }
        }
        result = true;
    });

    return result;
}

// ─── computeProto ─────────────────────────────────────────────────────────────
QString PacketListModel::computeProto(const PacketRecord& r) const {
    // ── Non-IP / special frames ───────────────────────────────────────────────
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

    // ── IPv6 với next-header ──────────────────────────────────────────────────
    // ✅ ICMPv6 (next header = 58) phân biệt với ICMP (1)
    if (r.eth_type == 0x86DD) {
        if (r.protocol == 58) return "ICMPv6";
    }

    // ── IPv4 / IPv6 transport ─────────────────────────────────────────────────
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
            if (r.src_port == 53  || r.dst_port == 53)   return "DNS";
            if (r.src_port == 67  || r.dst_port == 67 ||
                r.src_port == 68  || r.dst_port == 68)   return "DHCP";
            if (r.src_port == 123 || r.dst_port == 123)  return "NTP";
            if (r.src_port == 161 || r.dst_port == 161)  return "SNMP";
            return "UDP";
        }
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        default:
            return QString("IP(%1)").arg(r.protocol);
    }
}

// ─── computeInfo ──────────────────────────────────────────────────────────────
QString PacketListModel::computeInfo(const PacketRecord& r) const {
    if (r.eth_type == 0x0806)
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
        return QString("%1%2 → %3  len=%4")
            .arg(flag_str)
            .arg(r.src_port)
            .arg(r.dst_port)
            .arg(r.payload_len);
    }
    if (r.protocol == IPPROTO_UDP)
        return QString("UDP  %1 → %2  len=%3")
            .arg(r.src_port).arg(r.dst_port).arg(r.payload_len);
    if (r.protocol == IPPROTO_ICMP)
        return "ICMP message";
    if (r.protocol == 58)
        return "ICMPv6 message";

    return QString("len=%1").arg(r.orig_len);
}

// ─── computeRowColor ──────────────────────────────────────────────────────────
QColor PacketListModel::computeRowColor(const PacketRecord& r) const {
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
        case 58:           return QColor(10, 30, 30);  // ICMPv6
        default:           return QColor(15, 15, 15);
    }
}
