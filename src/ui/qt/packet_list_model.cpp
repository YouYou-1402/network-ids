#include "packet_list_model.hpp"
#include <QFont>
#include <arpa/inet.h>
#include <netinet/in.h>

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

// ─── Constructor ──────────────────────────────────────────────────────────────
PacketListModel::PacketListModel(PacketRingBuffer& ring_buf, QObject* parent)
    : QAbstractTableModel(parent)
    , ring_buf_(ring_buf)
{}

// ─── rowCount / columnCount ───────────────────────────────────────────────────
// ✅ Gọi từ main thread — không cần lock
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

// ─── data — KHÔNG lock, KHÔNG alloc, KHÔNG tính toán ────────────────────────
// ✅ Qt gọi data() từ main thread
// ✅ row_cache_ chỉ bị modify bởi appendRecords/applyFilter/clear
//    — tất cả đều từ main thread → zero contention
QVariant PacketListModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid()) return {};

    const int row = index.row();
    if (row < 0 || row >= static_cast<int>(row_cache_.size()))
        return {};

    const RowCache& c = row_cache_[static_cast<size_t>(row)];

    // ── Roles ─────────────────────────────────────────────────────────────────
    if (role == Qt::BackgroundRole)
        return c.bg_color;                     // ✅ pre-computed QColor

    if (role == Qt::ForegroundRole)
        return QColor("#dddddd");

    if (role == Qt::FontRole)
        return QFont("Monospace", 10);

    if (role == Qt::TextAlignmentRole) {
        const int col = index.column();
        if (col == COL_NO || col == COL_LEN || col == COL_PROTO)
            return Qt::AlignCenter;
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    }

    if (role != Qt::DisplayRole) return {};

    // ── Display — tất cả đọc từ cache, zero computation ──────────────────────
    switch (index.column()) {
        case COL_NO:     return QString::number(c.pkt_idx + 1);
        case COL_TIME:   return c.time_str;
        case COL_SRC_IP: return c.src;
        case COL_DST_IP: return c.dst;
        case COL_PROTO:  return c.proto;
        case COL_LEN:    return QString::number(c.orig_len);
        case COL_INFO:   return c.info;
        case COL_THREAT: return c.threat;      // ✅ pre-built — không gọi ring_buf_
        default:         return {};
    }
}

// ─── buildRowCache — tính toán 1 lần khi insert ──────────────────────────────
PacketListModel::RowCache
PacketListModel::buildRowCache(const PacketRecord& r) const {
    RowCache c;
    c.pkt_idx  = r.index;
    c.orig_len = r.orig_len;
    c.bg_color = computeRowColor(r);
    c.proto    = computeProto(r);
    c.info     = computeInfo(r);
    c.threat   = QString::fromStdString(r.threat_type);

    // IP:port — inet_ntoa tính 1 lần
    struct in_addr sa{}, da{};
    sa.s_addr = r.src_ip;
    da.s_addr = r.dst_ip;

    c.src = QString(inet_ntoa(sa));
    if (r.src_port) c.src += ':' + QString::number(r.src_port);

    c.dst = QString(inet_ntoa(da));
    if (r.dst_port) c.dst += ':' + QString::number(r.dst_port);

    // Relative time
    const double base = (base_timestamp_ >= 0.0) ? base_timestamp_ : r.timestamp;
    c.time_str = QString::number(r.timestamp - base, 'f', 6);

    return c;
}

// ─── appendRecords ────────────────────────────────────────────────────────────
// ✅ Gọi từ main thread (Qt queued connection từ UiBridge)
// Build cache TRƯỚC beginInsertRows → Qt không block trong notify
void PacketListModel::appendRecords(const std::vector<PacketRecord>& batch) {
    if (batch.empty()) return;

    // ── 1. Build cache ngoài lock ─────────────────────────────────────────────
    std::vector<RowCache> new_cache;
    new_cache.reserve(batch.size());

    for (const auto& r : batch) {
        // Set base_timestamp_ từ packet đầu tiên
        if (base_timestamp_ < 0.0)
            base_timestamp_ = r.timestamp;

        // Filter check — dùng withRecord để không copy
        bool pass = true;
        if (current_filter_.valid && !current_filter_.conditions.empty()) {
            pass = matchFilter(r.index, current_filter_);
        }
        if (!pass) continue;

        new_cache.push_back(buildRowCache(r));
    }

    if (new_cache.empty()) return;

    // ── 2. Giới hạn batch ────────────────────────────────────────────────────
    if (new_cache.size() > static_cast<size_t>(SCROLL_CHUNK))
        new_cache.resize(static_cast<size_t>(SCROLL_CHUNK));

    // ── 3. Evict nếu vượt MAX_DISPLAY_ROWS ───────────────────────────────────
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

    // ── 4. Insert ─────────────────────────────────────────────────────────────
    const int first = static_cast<int>(row_cache_.size());
    const int last  = first + static_cast<int>(new_cache.size()) - 1;

    beginInsertRows(QModelIndex{}, first, last);
    for (auto& c : new_cache) {
        filtered_indices_.push_back(c.pkt_idx);
        row_cache_.push_back(std::move(c));
    }
    endInsertRows();
}

// ─── applyFilter — rebuild từ ring_buf ───────────────────────────────────────
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
        // ✅ withRecord: không alloc, callback trong lock
        ring_buf_.withRecord(i, [&](const PacketRecord& r) {
            if (!matchFilter(i, filter)) return;

            if (base_timestamp_ < 0.0)
                base_timestamp_ = r.timestamp;

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

// ─── recordAt — dùng cho click → detail panel ────────────────────────────────
// Đây là trường hợp hiếm (user click) → shared_ptr alloc OK
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
        // Proto filter
        if (f.proto_filter != DisplayFilter::Proto::ANY) {
            const QString proto = computeProto(rec);
            switch (f.proto_filter) {
                case DisplayFilter::Proto::TCP:
                    if (proto != "TCP")  return;  break;
                case DisplayFilter::Proto::UDP:
                    if (proto != "UDP")  return;  break;
                case DisplayFilter::Proto::ICMP:
                    if (proto != "ICMP") return;  break;
                case DisplayFilter::Proto::HTTP:
                    if (proto != "HTTP") return;  break;
                case DisplayFilter::Proto::DNS:
                    if (proto != "DNS")  return;  break;
                default: break;
            }
        }

        // Conditions (AND)
        for (const auto& cond : f.conditions) {
            switch (cond.field) {
                case DisplayFilter::Field::SRC_IP: {
                    struct in_addr a{};
                    inet_pton(AF_INET, cond.value.c_str(), &a);
                    const bool eq = (rec.src_ip == a.s_addr);
                    if (cond.op == DisplayFilter::Op::EQ  && !eq) return;
                    if (cond.op == DisplayFilter::Op::NEQ &&  eq) return;
                    break;
                }
                case DisplayFilter::Field::DST_IP: {
                    struct in_addr a{};
                    inet_pton(AF_INET, cond.value.c_str(), &a);
                    const bool eq = (rec.dst_ip == a.s_addr);
                    if (cond.op == DisplayFilter::Op::EQ  && !eq) return;
                    if (cond.op == DisplayFilter::Op::NEQ &&  eq) return;
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
        default:           return QString("IP(%1)").arg(r.protocol);
    }
}

// ─── computeInfo ──────────────────────────────────────────────────────────────
QString PacketListModel::computeInfo(const PacketRecord& r) const {
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
        default:           return QColor(15, 15, 15);
    }
}
