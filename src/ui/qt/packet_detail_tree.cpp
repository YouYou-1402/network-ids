// src/ui/qt/packet_detail_tree.cpp
#include "packet_detail_tree.hpp"
#include <QFont>
#include <QDateTime>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <sstream>
#include <iomanip>

// ─── Constructor ──────────────────────────────────────────────────────────────
PacketDetailTree::PacketDetailTree(QWidget* parent)
    : QTreeWidget(parent)
{
    setHeaderHidden(true);
    setColumnCount(1);
    setIndentation(16);
    setAnimated(true);
    setStyleSheet(
        "QTreeWidget { background: #0d0d1a; color: #cccccc; "
        "border: 1px solid #333; font-family: monospace; font-size: 11px; }"
        "QTreeWidget::item { padding: 2px 4px; }"
        "QTreeWidget::item:selected { background: #2a2a4a; }"
        "QTreeWidget::branch { background: #0d0d1a; }"
    );
}

// ─── clearDetail ──────────────────────────────────────────────────────────────
void PacketDetailTree::clearDetail() {
    clear();
}

// ─── addSection ───────────────────────────────────────────────────────────────
QTreeWidgetItem* PacketDetailTree::addSection(const QString& title,
                                               const QString& summary) {
    auto* item = new QTreeWidgetItem(this);
    item->setText(0, summary.isEmpty()
        ? title : title + "  (" + summary + ")");
    item->setForeground(0, QColor("#88aaff"));
    QFont f = item->font(0);
    f.setBold(true);
    item->setFont(0, f);
    item->setExpanded(true);
    return item;
}

// ─── addField helper ──────────────────────────────────────────────────────────
static void addField(QTreeWidgetItem* parent,
                     const QString&   key,
                     const QString&   value,
                     const QColor&    color = QColor("#aaaaaa")) {
    auto* c = new QTreeWidgetItem(parent);
    // Padding key để align value — monospace font
    c->setText(0, QString("  %1 %2")
        .arg(key + ":", -30, QChar(' '))
        .arg(value));
    c->setForeground(0, color);
}

// ─── ipToString — network byte order ─────────────────────────────────────────
static QString ipStr(uint32_t ip_net) {
    if (ip_net == 0) return "0.0.0.0";
    struct in_addr a{};
    a.s_addr = ip_net;
    return QString::fromLatin1(inet_ntoa(a));
}

// ─── showPacket — entry point ─────────────────────────────────────────────────
void PacketDetailTree::showPacket(const PacketRecord& record) {
    clear();

    // ── 1. Frame section — luôn hiển thị được (không cần raw_data) ───────────
    {
        auto* frame = addSection("📦 Frame",
            QString("len=%1  cap=%2  #%3")
                .arg(record.orig_len)
                .arg(record.cap_len)
                .arg(record.index + 1));

        // Timestamp
        const qint64 secs = static_cast<qint64>(record.timestamp);
        const int    ms   = static_cast<int>(
            (record.timestamp - secs) * 1000);
        QDateTime dt = QDateTime::fromSecsSinceEpoch(secs);
        addField(frame, "Arrival Time",
                 dt.toString("yyyy-MM-dd hh:mm:ss")
                 + QString(".%1").arg(ms, 3, 10, QChar('0')));
        addField(frame, "Frame Number",   QString::number(record.index + 1));
        addField(frame, "Frame Length",
                 QString::number(record.orig_len) + " bytes");
        addField(frame, "Capture Length",
                 QString::number(record.cap_len) + " bytes");

        if (record.cap_len < record.orig_len)
            addField(frame, "⚠ Truncated",
                     QString("missing %1 bytes")
                         .arg(record.orig_len - record.cap_len),
                     QColor("#ffaa44"));
    }

    // ── 2. Có raw_data → parse đầy đủ từ bytes ───────────────────────────────
    if (record.raw_data && !record.raw_data->empty()) {
        const uint8_t* data = record.raw_data->data();
        const uint32_t len  = record.cap_len;

        if (len >= sizeof(struct ether_header))
            showEthernet(data, len);

    } else {
        // ── 3. Không có raw_data (đã evict) → dùng pre-decoded fields ─────────
        showFromFields(record);

        auto* note = new QTreeWidgetItem(this);
        note->setText(0, "ℹ  Raw bytes evicted — showing decoded fields only");
        note->setForeground(0, QColor("#666688"));
    }

    // ── 4. Threat section — luôn hiển thị nếu có ─────────────────────────────
    if (!record.threat_type.empty())
        showThreat(record);
}

// ─── showEthernet ─────────────────────────────────────────────────────────────
void PacketDetailTree::showEthernet(const uint8_t* data, uint32_t len) {
    const auto* eth = reinterpret_cast<const struct ether_header*>(data);

    uint16_t eth_type  = ntohs(eth->ether_type);
    uint32_t ip_offset = sizeof(struct ether_header);  // 14

    // Build EtherType string
    auto ethTypeStr = [](uint16_t t) -> QString {
        switch (t) {
            case 0x0800: return "IPv4 (0x0800)";
            case 0x0806: return "ARP  (0x0806)";
            case 0x86DD: return "IPv6 (0x86DD)";
            case 0x8100: return "VLAN (0x8100)";
            default:     return QString("0x%1").arg(t, 4, 16, QChar('0'));
        }
    };

    auto* eth_sec = addSection("🔌 Ethernet II",
        QString("src=%1  dst=%2")
            .arg(macStr(eth->ether_shost))
            .arg(macStr(eth->ether_dhost)));

    addField(eth_sec, "Destination MAC", macStr(eth->ether_dhost));
    addField(eth_sec, "Source MAC",      macStr(eth->ether_shost));
    addField(eth_sec, "EtherType",       ethTypeStr(eth_type));

    // ── VLAN 802.1Q ───────────────────────────────────────────────────────────
    if (eth_type == 0x8100) {
        if (ip_offset + 4 > len) return;

        const uint16_t tci      = ntohs(
            *reinterpret_cast<const uint16_t*>(data + ip_offset));
        const uint16_t vlan_id  = tci & 0x0FFF;
        const uint8_t  priority = (tci >> 13) & 0x07;

        addField(eth_sec, "VLAN ID",   QString::number(vlan_id));
        addField(eth_sec, "Priority",  QString::number(priority));

        eth_type  = ntohs(
            *reinterpret_cast<const uint16_t*>(data + ip_offset + 2));
        ip_offset += 4;
        addField(eth_sec, "Inner EtherType", ethTypeStr(eth_type));
    }

    // ── Dispatch L3 ───────────────────────────────────────────────────────────
    const uint8_t* l3   = data + ip_offset;
    const uint32_t l3len = (len > ip_offset) ? len - ip_offset : 0;

    switch (eth_type) {
        case 0x0800:
            if (l3len >= sizeof(struct ip))
                showIPv4(l3, l3len);
            break;
        case 0x0806:
            showARP(l3, l3len);
            break;
        case 0x86DD:
            showIPv6Stub(l3, l3len);
            break;
        default:
            break;
    }
}

// ─── showIPv4 ─────────────────────────────────────────────────────────────────
void PacketDetailTree::showIPv4(const uint8_t* data, uint32_t len) {
    const auto* ip = reinterpret_cast<const struct ip*>(data);

    const QString src = ipStr(ip->ip_src.s_addr);
    const QString dst = ipStr(ip->ip_dst.s_addr);

    const QString proto_str =
        (ip->ip_p == IPPROTO_TCP)  ? "TCP (6)"   :
        (ip->ip_p == IPPROTO_UDP)  ? "UDP (17)"  :
        (ip->ip_p == IPPROTO_ICMP) ? "ICMP (1)"  :
        QString("Unknown (%1)").arg(ip->ip_p);

    auto* sec = addSection("🌐 Internet Protocol v4",
                            src + " → " + dst);

    addField(sec, "Version",        QString::number(ip->ip_v));
    addField(sec, "Header Length",  QString::number(ip->ip_hl * 4) + " bytes");
    addField(sec, "DSCP / ECN",
             QString("0x%1").arg(ip->ip_tos, 2, 16, QChar('0')));
    addField(sec, "Total Length",   QString::number(ntohs(ip->ip_len)));
    addField(sec, "Identification",
             QString("0x%1").arg(ntohs(ip->ip_id), 4, 16, QChar('0')));

    // Fragmentation flags
    const uint16_t frag_off = ntohs(ip->ip_off);
    QStringList frag_flags;
    if (frag_off & IP_DF) frag_flags << "DF";
    if (frag_off & IP_MF) frag_flags << "MF";
    addField(sec, "Flags",
             frag_flags.isEmpty() ? "None" : frag_flags.join(", "));

    addField(sec, "TTL",            QString::number(ip->ip_ttl));
    addField(sec, "Protocol",       proto_str);
    addField(sec, "Checksum",
             QString("0x%1").arg(ntohs(ip->ip_sum), 4, 16, QChar('0')));
    addField(sec, "Source IP",      src);
    addField(sec, "Destination IP", dst);

    // ── L4 dispatch ───────────────────────────────────────────────────────────
    const uint32_t ip_hdr_len = ip->ip_hl * 4;
    if (ip_hdr_len > len) return;

    const uint8_t* l4    = data + ip_hdr_len;
    const uint32_t l4len = len  - ip_hdr_len;

    switch (ip->ip_p) {
        case IPPROTO_TCP:  showTCP (l4, l4len); break;
        case IPPROTO_UDP:  showUDP (l4, l4len); break;
        case IPPROTO_ICMP: showICMP(l4, l4len); break;
        default: break;
    }
}

// ─── showTCP ──────────────────────────────────────────────────────────────────
void PacketDetailTree::showTCP(const uint8_t* data, uint32_t len) {
    if (len < sizeof(struct tcphdr)) return;
    const auto* tcp = reinterpret_cast<const struct tcphdr*>(data);

    const uint16_t sport = ntohs(tcp->th_sport);
    const uint16_t dport = ntohs(tcp->th_dport);
    const QString  flags = flagsToString(tcp->th_flags);

    auto* sec = addSection("🔗 Transmission Control Protocol",
        QString("%1 → %2  [%3]").arg(sport).arg(dport).arg(flags));

    addField(sec, "Source Port",      QString::number(sport));
    addField(sec, "Destination Port", QString::number(dport));
    addField(sec, "Sequence Number",  QString::number(ntohl(tcp->th_seq)));
    addField(sec, "Ack Number",       QString::number(ntohl(tcp->th_ack)));
    addField(sec, "Header Length",
             QString::number(tcp->th_off * 4) + " bytes");
    addField(sec, "Flags",            flags);
    addField(sec, "Window Size",      QString::number(ntohs(tcp->th_win)));
    addField(sec, "Checksum",
             QString("0x%1").arg(ntohs(tcp->th_sum), 4, 16, QChar('0')));
    addField(sec, "Urgent Pointer",   QString::number(ntohs(tcp->th_urp)));

    // ── Payload ───────────────────────────────────────────────────────────────
    const uint32_t tcp_hdr_len = tcp->th_off * 4;
    if (tcp_hdr_len >= len) return;

    const uint8_t* payload     = data + tcp_hdr_len;
    const uint32_t payload_len = len  - tcp_hdr_len;

    addField(sec, "Payload Length",
             QString::number(payload_len) + " bytes");

    // HTTP detection
    if ((sport == 80 || dport == 80 ||
         sport == 8080 || dport == 8080) && payload_len > 0)
        showHTTP(sec, payload, payload_len);
}

// ─── showUDP ──────────────────────────────────────────────────────────────────
void PacketDetailTree::showUDP(const uint8_t* data, uint32_t len) {
    if (len < sizeof(struct udphdr)) return;
    const auto* udp = reinterpret_cast<const struct udphdr*>(data);

    const uint16_t sport = ntohs(udp->uh_sport);
    const uint16_t dport = ntohs(udp->uh_dport);

    auto* sec = addSection("📡 User Datagram Protocol",
        QString("%1 → %2").arg(sport).arg(dport));

    addField(sec, "Source Port",      QString::number(sport));
    addField(sec, "Destination Port", QString::number(dport));
    addField(sec, "Length",           QString::number(ntohs(udp->uh_ulen)));
    addField(sec, "Checksum",
             QString("0x%1").arg(ntohs(udp->uh_sum), 4, 16, QChar('0')));

    // DNS
    if (sport == 53 || dport == 53) {
        const uint8_t* dns_data = data + sizeof(struct udphdr);
        const uint32_t dns_len  = (ntohs(udp->uh_ulen) > 8)
                                  ? ntohs(udp->uh_ulen) - 8 : 0;
        if (dns_len > 0)
            showDNS(sec, dns_data, dns_len);
    }
}

// ─── showICMP ─────────────────────────────────────────────────────────────────
void PacketDetailTree::showICMP(const uint8_t* data, uint32_t len) {
    if (len < 4) return;
    const auto* icmp = reinterpret_cast<const struct icmphdr*>(data);

    auto typeStr = [](uint8_t t) -> QString {
        switch (t) {
            case ICMP_ECHO:         return "Echo Request (8)";
            case ICMP_ECHOREPLY:    return "Echo Reply (0)";
            case ICMP_DEST_UNREACH: return "Dest Unreachable (3)";
            case ICMP_TIME_EXCEEDED:return "Time Exceeded (11)";
            case ICMP_REDIRECT:     return "Redirect (5)";
            default: return QString("Type %1").arg(t);
        }
    };

    auto* sec = addSection("🏓 Internet Control Message Protocol",
                            typeStr(icmp->type));

    addField(sec, "Type", typeStr(icmp->type));
    addField(sec, "Code", QString::number(icmp->code));
    addField(sec, "Checksum",
             QString("0x%1").arg(
                 ntohs(icmp->checksum), 4, 16, QChar('0')));

    if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
        addField(sec, "Identifier",
                 QString::number(ntohs(icmp->un.echo.id)));
        addField(sec, "Sequence",
                 QString::number(ntohs(icmp->un.echo.sequence)));
    }
}

// ─── showARP ──────────────────────────────────────────────────────────────────
void PacketDetailTree::showARP(const uint8_t* data, uint32_t len) {
    // ARP header: 28 bytes cho IPv4/Ethernet
    if (len < 28) return;

    const uint16_t opcode = ntohs(
        *reinterpret_cast<const uint16_t*>(data + 6));
    const QString op_str  = (opcode == 1) ? "Request (1)" :
                            (opcode == 2) ? "Reply (2)"   :
                            QString::number(opcode);

    auto* sec = addSection("📋 Address Resolution Protocol", op_str);

    addField(sec, "Hardware Type",
             QString("0x%1").arg(
                 ntohs(*reinterpret_cast<const uint16_t*>(data)),
                 4, 16, QChar('0')));
    addField(sec, "Protocol Type",
             QString("0x%1").arg(
                 ntohs(*reinterpret_cast<const uint16_t*>(data + 2)),
                 4, 16, QChar('0')));
    addField(sec, "Opcode", op_str);

    // Sender MAC / IP
    addField(sec, "Sender MAC", macStr(data + 8));
    struct in_addr sa{};
    memcpy(&sa.s_addr, data + 14, 4);
    addField(sec, "Sender IP",  QString::fromLatin1(inet_ntoa(sa)));

    // Target MAC / IP
    addField(sec, "Target MAC", macStr(data + 18));
    struct in_addr ta{};
    memcpy(&ta.s_addr, data + 24, 4);
    addField(sec, "Target IP",  QString::fromLatin1(inet_ntoa(ta)));
}

// ─── showIPv6Stub ─────────────────────────────────────────────────────────────
void PacketDetailTree::showIPv6Stub(const uint8_t* data, uint32_t len) {
    if (len < 40) return;

    auto* sec = addSection("🌐 Internet Protocol v6", "(IPv6)");
    addField(sec, "Version",       "6");
    addField(sec, "Payload Length",
             QString::number(ntohs(
                 *reinterpret_cast<const uint16_t*>(data + 4))));
    addField(sec, "Next Header",   QString::number(data[6]));
    addField(sec, "Hop Limit",     QString::number(data[7]));

    // Hiển thị địa chỉ dạng hex đơn giản (không dùng inet_ntop để tránh include)
    auto ipv6Str = [](const uint8_t* addr) -> QString {
        char buf[40];
        snprintf(buf, sizeof(buf),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5],addr[6],addr[7],
            addr[8],addr[9],addr[10],addr[11],
            addr[12],addr[13],addr[14],addr[15]);
        return QString::fromLatin1(buf);
    };

    addField(sec, "Source IPv6",      ipv6Str(data + 8));
    addField(sec, "Destination IPv6", ipv6Str(data + 24));
}

// ─── showFromFields — fallback khi raw_data đã evict ─────────────────────────
void PacketDetailTree::showFromFields(const PacketRecord& rec) {
    // ARP
    if (rec.eth_type == 0x0806) {
        auto* sec = addSection("📋 Address Resolution Protocol",
                                "(from fields)");
        addField(sec, "EtherType", "ARP (0x0806)");
        return;
    }

    // IPv4
    if (rec.src_ip != 0 || rec.dst_ip != 0) {
        const QString src = ipStr(rec.src_ip);
        const QString dst = ipStr(rec.dst_ip);

        auto* ip_sec = addSection("🌐 Internet Protocol v4",
                                   src + " → " + dst);
        addField(ip_sec, "Source IP",      src);
        addField(ip_sec, "Destination IP", dst);

        const QString proto_str =
            (rec.protocol == IPPROTO_TCP)  ? "TCP (6)"   :
            (rec.protocol == IPPROTO_UDP)  ? "UDP (17)"  :
            (rec.protocol == IPPROTO_ICMP) ? "ICMP (1)"  :
            QString("Unknown (%1)").arg(rec.protocol);
        addField(ip_sec, "Protocol", proto_str);

        // TCP
        if (rec.protocol == IPPROTO_TCP) {
            auto* tcp_sec = addSection("🔗 Transmission Control Protocol",
                QString("%1 → %2  [%3]")
                    .arg(rec.src_port)
                    .arg(rec.dst_port)
                    .arg(flagsToString(rec.tcp_flags)));

            addField(tcp_sec, "Source Port",
                     QString::number(rec.src_port));
            addField(tcp_sec, "Destination Port",
                     QString::number(rec.dst_port));
            addField(tcp_sec, "Flags",
                     flagsToString(rec.tcp_flags));
            addField(tcp_sec, "Payload Length",
                     QString::number(rec.payload_len) + " bytes");

        // UDP
        } else if (rec.protocol == IPPROTO_UDP) {
            auto* udp_sec = addSection("📡 User Datagram Protocol",
                QString("%1 → %2")
                    .arg(rec.src_port).arg(rec.dst_port));

            addField(udp_sec, "Source Port",
                     QString::number(rec.src_port));
            addField(udp_sec, "Destination Port",
                     QString::number(rec.dst_port));
            addField(udp_sec, "Payload Length",
                     QString::number(rec.payload_len) + " bytes");

        // ICMP
        } else if (rec.protocol == IPPROTO_ICMP) {
            auto* icmp_sec = addSection(
                "🏓 Internet Control Message Protocol", "");
            addField(icmp_sec, "Type (src_port field)",
                     QString::number(rec.src_port));
            addField(icmp_sec, "Code (dst_port field)",
                     QString::number(rec.dst_port));
        }
    }
}

// ─── showHTTP ─────────────────────────────────────────────────────────────────
void PacketDetailTree::showHTTP(QTreeWidgetItem* parent,
                                 const uint8_t*   data,
                                 uint32_t         len) {
    if (len < 4) return;

    const std::string start(reinterpret_cast<const char*>(data),
                            std::min(len, 4u));
    const bool is_http = (start == "GET " || start == "POST" ||
                          start == "HTTP" || start == "HEAD" ||
                          start == "PUT " || start == "DELE");
    if (!is_http) return;

    auto* sec = new QTreeWidgetItem(
        parent ? parent : invisibleRootItem());
    sec->setText(0, "🌍 Hypertext Transfer Protocol");
    sec->setForeground(0, QColor("#88aaff"));
    QFont f = sec->font(0);
    f.setBold(true);
    sec->setFont(0, f);
    sec->setExpanded(true);

    std::string raw(reinterpret_cast<const char*>(data),
                    std::min(len, 2048u));
    std::istringstream ss(raw);
    std::string line;
    int count = 0;

    while (std::getline(ss, line) && count < 20) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        auto* child = new QTreeWidgetItem(sec);
        child->setText(0, "  " + QString::fromStdString(line));
        child->setForeground(0, QColor("#aaaaaa"));
        ++count;
    }
}

// ─── showDNS ──────────────────────────────────────────────────────────────────
void PacketDetailTree::showDNS(QTreeWidgetItem* parent,
                                const uint8_t*   data,
                                uint32_t         len) {
    if (len < 12) return;

    const uint16_t txid  = ntohs(
        *reinterpret_cast<const uint16_t*>(data));
    const uint16_t flags = ntohs(
        *reinterpret_cast<const uint16_t*>(data + 2));
    const uint16_t qdcnt = ntohs(
        *reinterpret_cast<const uint16_t*>(data + 4));
    const uint16_t ancnt = ntohs(
        *reinterpret_cast<const uint16_t*>(data + 6));
    const bool is_resp   = (flags & 0x8000) != 0;

    auto* sec = new QTreeWidgetItem(
        parent ? parent : invisibleRootItem());
    sec->setText(0, QString("🔍 Domain Name System (%1)")
        .arg(is_resp ? "Response" : "Query"));
    sec->setForeground(0, QColor("#88aaff"));
    QFont f = sec->font(0);
    f.setBold(true);
    sec->setFont(0, f);
    sec->setExpanded(true);

    addField(sec, "Transaction ID",
             QString("0x%1").arg(txid, 4, 16, QChar('0')));
    addField(sec, "Type",      is_resp ? "Response" : "Query");
    addField(sec, "Questions", QString::number(qdcnt));
    addField(sec, "Answer RRs",QString::number(ancnt));

    // Parse question section (tên domain)
    if (qdcnt > 0 && len > 12) {
        const uint8_t* ptr = data + 12;
        const uint8_t* end = data + len;
        std::string domain;
        while (ptr < end && *ptr != 0) {
            const uint8_t label_len = *ptr++;
            if (ptr + label_len > end) break;
            if (!domain.empty()) domain += '.';
            domain.append(reinterpret_cast<const char*>(ptr), label_len);
            ptr += label_len;
        }
        if (!domain.empty())
            addField(sec, "Query Name",
                     QString::fromStdString(domain));
    }
}

// ─── showThreat ───────────────────────────────────────────────────────────────
void PacketDetailTree::showThreat(const PacketRecord& record) {
    auto* sec = addSection("🚨 IDS/IPS Detection",
        QString::fromStdString(record.threat_type));
    sec->setForeground(0, QColor("#ff6666"));

    auto addThreat = [&](const QString& k, const QString& v) {
        auto* c = new QTreeWidgetItem(sec);
        c->setText(0, QString("  %1 %2")
            .arg(k + ":", -30, QChar(' ')).arg(v));
        c->setForeground(0, QColor("#ffaaaa"));
    };

    addThreat("Threat Type",
              QString::fromStdString(record.threat_type));
    addThreat("Action",
              QString::fromStdString(record.action));
}

// ─── flagsToString ────────────────────────────────────────────────────────────
QString PacketDetailTree::flagsToString(uint8_t flags) {
    QStringList f;
    if (flags & 0x02) f << "SYN";
    if (flags & 0x10) f << "ACK";
    if (flags & 0x04) f << "RST";
    if (flags & 0x01) f << "FIN";
    if (flags & 0x08) f << "PSH";
    if (flags & 0x20) f << "URG";
    return f.isEmpty() ? "NONE" : f.join(", ");
}

// ─── macStr ───────────────────────────────────────────────────────────────────
QString PacketDetailTree::macStr(const uint8_t* mac) {
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(mac[0], 2, 16, QChar('0'))
        .arg(mac[1], 2, 16, QChar('0'))
        .arg(mac[2], 2, 16, QChar('0'))
        .arg(mac[3], 2, 16, QChar('0'))
        .arg(mac[4], 2, 16, QChar('0'))
        .arg(mac[5], 2, 16, QChar('0'));
}
