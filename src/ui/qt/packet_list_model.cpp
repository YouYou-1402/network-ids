#include "packet_list_model.hpp"
#include <QFont>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdexcept>

static const QStringList HEADERS = {
    "No.", "Time", "Source", "Destination",
    "Protocol", "Length", "Info", "Threat"
};

// ─── evalOp — so sánh numeric cho port ───────────────────────────────────────
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
int PacketListModel::rowCount(const QModelIndex&) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(filtered_indices_.size());
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

// ─── appendRecords — Wireshark-style capped insert ───────────────────────────
void PacketListModel::appendRecords(const std::vector<PacketRecord>& batch) {
    if (batch.empty()) return;

    // ── 1. Lọc batch theo filter hiện tại ────────────────────────────────────
    std::vector<uint64_t> new_indices;
    new_indices.reserve(batch.size());

    for (const auto& r : batch) {
        if (base_timestamp_ < 0.0)
            base_timestamp_ = r.timestamp;
        if (matchFilter(r.index, current_filter_))
            new_indices.push_back(r.index);
    }
    if (new_indices.empty()) return;

    // ── 2. Giới hạn batch size để không block Qt event loop ──────────────────
    if (new_indices.size() > SCROLL_CHUNK)
        new_indices.resize(SCROLL_CHUNK);

    std::lock_guard<std::mutex> lock(mutex_);

    // ── 3. Evict rows đầu nếu vượt MAX_DISPLAY_ROWS ───────────────────────────
    int overflow = static_cast<int>(filtered_indices_.size())
                 + static_cast<int>(new_indices.size())
                 - MAX_DISPLAY_ROWS;

    if (overflow > 0) {
        beginRemoveRows(QModelIndex{}, 0, overflow - 1);
        for (int i = 0; i < overflow; i++)
            filtered_indices_.pop_front();
        endRemoveRows();
    }

    // ── 4. Insert rows mới ────────────────────────────────────────────────────
    int first = static_cast<int>(filtered_indices_.size());
    int last  = first + static_cast<int>(new_indices.size()) - 1;

    beginInsertRows(QModelIndex{}, first, last);
    for (uint64_t idx : new_indices)
        filtered_indices_.push_back(idx);
    endInsertRows();
}

// ─── data — lazy fetch từ ring_buf ───────────────────────────────────────────
QVariant PacketListModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid()) return {};

    std::lock_guard<std::mutex> lock(mutex_);

    int row = index.row();
    if (row < 0 || row >= static_cast<int>(filtered_indices_.size()))
        return {};

    uint64_t pkt_idx    = filtered_indices_[row];
    auto     record_ptr = ring_buf_.getByIndex(pkt_idx);
    if (!record_ptr) return {};

    const PacketRecord& r = *record_ptr;

    // ── Roles ─────────────────────────────────────────────────────────────────
    if (role == Qt::BackgroundRole)    return rowColor(r);
    if (role == Qt::ForegroundRole)    return QColor("#dddddd");
    if (role == Qt::FontRole)          return QFont("Monospace", 10);
    if (role == Qt::TextAlignmentRole) {
        if (index.column() == COL_NO   ||
            index.column() == COL_LEN  ||
            index.column() == COL_PROTO)
            return Qt::AlignCenter;
        return int(Qt::AlignLeft | Qt::AlignVCenter);
    }
    if (role != Qt::DisplayRole) return {};

    // ── Display data ──────────────────────────────────────────────────────────
    struct in_addr src_addr{}, dst_addr{};
    src_addr.s_addr = r.src_ip;
    dst_addr.s_addr = r.dst_ip;

    switch (index.column()) {
        case COL_NO:
            return QString::number(r.index + 1);

        case COL_TIME: {
            double rel = (base_timestamp_ >= 0.0)
                       ? r.timestamp - base_timestamp_
                       : r.timestamp;
            return QString::number(rel, 'f', 6);
        }

        case COL_SRC_IP: {
            QString ip = inet_ntoa(src_addr);
            if (r.src_port) ip += ":" + QString::number(r.src_port);
            return ip;
        }

        case COL_DST_IP: {
            QString ip = inet_ntoa(dst_addr);
            if (r.dst_port) ip += ":" + QString::number(r.dst_port);
            return ip;
        }

        case COL_PROTO:  return protocolName(r);
        case COL_LEN:    return QString::number(r.orig_len);
        case COL_INFO:   return buildInfo(r);
        case COL_THREAT: return QString::fromStdString(r.threat_type);
        default:         return {};
    }
}

// ─── applyFilter — rebuild filtered_indices_ từ ring_buf ─────────────────────
void PacketListModel::applyFilter(const DisplayFilter& filter) {
    beginResetModel();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        current_filter_ = filter;
        filtered_indices_.clear();

        uint64_t oldest = ring_buf_.oldestIndex();
        uint64_t total  = ring_buf_.totalReceived();

        uint64_t scan_from = (total > static_cast<uint64_t>(MAX_DISPLAY_ROWS))
                           ? total - MAX_DISPLAY_ROWS
                           : oldest;

        for (uint64_t i = scan_from; i < total; i++) {
            if (matchFilter(i, filter))
                filtered_indices_.push_back(i);
        }
    }
    endResetModel();
}

// ─── clear ────────────────────────────────────────────────────────────────────
void PacketListModel::clear() {
    beginResetModel();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        filtered_indices_.clear();
        base_timestamp_ = -1.0;
    }
    endResetModel();
}

// ─── recordAt ─────────────────────────────────────────────────────────────────
std::shared_ptr<PacketRecord> PacketListModel::recordAt(int row) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (row < 0 || row >= static_cast<int>(filtered_indices_.size()))
        return nullptr;
    return ring_buf_.getByIndex(filtered_indices_[row]);
}

// ─── matchFilter ──────────────────────────────────────────────────────────────
bool PacketListModel::matchFilter(uint64_t             idx,
                                   const DisplayFilter& f) const {
    // Filter rỗng hoặc invalid → pass all
    if (!f.valid || f.conditions.empty())
        return true;

    auto rec = ring_buf_.getByIndex(idx);
    if (!rec) return false;

    // ── Proto filter (check trước cho nhanh) ─────────────────────────────────
    if (f.proto_filter != DisplayFilter::Proto::ANY) {
        QString proto = protocolName(*rec);
        switch (f.proto_filter) {
            case DisplayFilter::Proto::TCP:
                if (proto != "TCP")   return false; break;
            case DisplayFilter::Proto::UDP:
                if (proto != "UDP")   return false; break;
            case DisplayFilter::Proto::ICMP:
                if (proto != "ICMP")  return false; break;
            case DisplayFilter::Proto::HTTP:
                if (proto != "HTTP")  return false; break;
            case DisplayFilter::Proto::DNS:
                if (proto != "DNS")   return false; break;
            default: break;
        }
    }

    // ── Conditions (AND logic) ────────────────────────────────────────────────
    for (const auto& cond : f.conditions) {
        switch (cond.field) {

            case DisplayFilter::Field::SRC_IP: {
                struct in_addr a{};
                inet_pton(AF_INET, cond.value.c_str(), &a);
                bool eq = (rec->src_ip == a.s_addr);
                if (cond.op == DisplayFilter::Op::EQ  && !eq) return false;
                if (cond.op == DisplayFilter::Op::NEQ &&  eq) return false;
                break;
            }
            case DisplayFilter::Field::DST_IP: {
                struct in_addr a{};
                inet_pton(AF_INET, cond.value.c_str(), &a);
                bool eq = (rec->dst_ip == a.s_addr);
                if (cond.op == DisplayFilter::Op::EQ  && !eq) return false;
                if (cond.op == DisplayFilter::Op::NEQ &&  eq) return false;
                break;
            }
            case DisplayFilter::Field::SRC_PORT: {
                uint16_t port = static_cast<uint16_t>(
                    std::stoul(cond.value));
                if (!evalOp(cond.op, rec->src_port, port)) return false;
                break;
            }
            case DisplayFilter::Field::DST_PORT: {
                uint16_t port = static_cast<uint16_t>(
                    std::stoul(cond.value));
                if (!evalOp(cond.op, rec->dst_port, port)) return false;
                break;
            }
            case DisplayFilter::Field::PROTOCOL: {
                bool eq = (protocolName(*rec).toStdString() == cond.value);
                if (cond.op == DisplayFilter::Op::EQ  && !eq) return false;
                if (cond.op == DisplayFilter::Op::NEQ &&  eq) return false;
                break;
            }
            case DisplayFilter::Field::TCP_FLAGS: {
                uint8_t mask = static_cast<uint8_t>(
                    std::stoul(cond.value, nullptr, 16));
                bool has = (rec->tcp_flags & mask) != 0;
                if (cond.op == DisplayFilter::Op::EQ  && !has) return false;
                if (cond.op == DisplayFilter::Op::NEQ &&  has) return false;
                break;
            }
            case DisplayFilter::Field::THREAT: {
                bool has = !rec->threat_type.empty() &&
                           rec->threat_type.find(cond.value)
                               != std::string::npos;
                if (cond.op == DisplayFilter::Op::EQ  && !has) return false;
                if (cond.op == DisplayFilter::Op::NEQ &&  has) return false;
                break;
            }
            default: break;
        }
    }
    return true;
}

// ─── protocolName ─────────────────────────────────────────────────────────────
QString PacketListModel::protocolName(const PacketRecord& r) const {
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

// ─── buildInfo ────────────────────────────────────────────────────────────────
QString PacketListModel::buildInfo(const PacketRecord& r) const {
    if (r.protocol == IPPROTO_TCP) {
        QStringList flags;
        if (r.tcp_flags & 0x02) flags << "SYN";
        if (r.tcp_flags & 0x10) flags << "ACK";
        if (r.tcp_flags & 0x04) flags << "RST";
        if (r.tcp_flags & 0x01) flags << "FIN";
        if (r.tcp_flags & 0x08) flags << "PSH";
        if (r.tcp_flags & 0x20) flags << "URG";

        QString flag_str = flags.isEmpty()
            ? "" : "[" + flags.join(", ") + "] ";
        return QString("%1%2 → %3  len=%4")
            .arg(flag_str)
            .arg(r.src_port)
            .arg(r.dst_port)
            .arg(r.payload_len);
    }
    if (r.protocol == IPPROTO_UDP) {
        return QString("UDP  %1 → %2  len=%3")
            .arg(r.src_port)
            .arg(r.dst_port)
            .arg(r.payload_len);
    }
    if (r.protocol == IPPROTO_ICMP)
        return "ICMP message";

    return QString("len=%1").arg(r.orig_len);
}

// ─── rowColor ─────────────────────────────────────────────────────────────────
QVariant PacketListModel::rowColor(const PacketRecord& r) const {
    // Threat (ưu tiên cao nhất)
    if (!r.threat_type.empty()) {
        if (r.threat_type.find("DDOS_VOLUMETRIC") != std::string::npos)
            return QColor(60, 15, 15);
        if (r.threat_type.find("SLOW_DDOS") != std::string::npos)
            return QColor(55, 50, 10);
        if (r.threat_type.find("PORT_SCAN") != std::string::npos)
            return QColor(60, 38, 10);
        return QColor(50, 10, 10);
    }

    // Protocol
    switch (r.protocol) {
        case IPPROTO_TCP: {
            if (r.tcp_flags & 0x04) return QColor(40, 10, 10);  // RST
            if (r.tcp_flags & 0x02) return QColor(15, 35, 15);  // SYN
            if (r.src_port == 80   || r.dst_port == 80   ||
                r.src_port == 8080 || r.dst_port == 8080)
                return QColor(15, 25, 45);                        // HTTP
            if (r.src_port == 443  || r.dst_port == 443)
                return QColor(20, 30, 50);                        // HTTPS
            return QColor(15, 15, 30);                            // TCP
        }
        case IPPROTO_UDP:
            if (r.src_port == 53 || r.dst_port == 53)
                return QColor(35, 20, 45);                        // DNS
            return QColor(20, 20, 35);
        case IPPROTO_ICMP:
            return QColor(10, 35, 35);
        default:
            return QColor(15, 15, 15);
    }
}
