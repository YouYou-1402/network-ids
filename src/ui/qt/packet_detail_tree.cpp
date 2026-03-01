// ── packet_detail_tree.cpp ────────────────────────────────────────────────────
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

void PacketDetailTree::clearDetail() {
    clear();
}

QTreeWidgetItem* PacketDetailTree::addSection(const QString& title,
                                               const QString& summary) {
    auto* item = new QTreeWidgetItem(this);
    QString text = summary.isEmpty()
        ? title
        : title + "  (" + summary + ")";
    item->setText(0, text);
    item->setForeground(0, QColor("#88aaff"));

    QFont f = item->font(0);
    f.setBold(true);
    item->setFont(0, f);
    item->setExpanded(true);
    return item;
}

void PacketDetailTree::showPacket(const PacketRecord& record) {
    clear();

    if (!record.raw_data || record.raw_data->empty()) {
        auto* item = new QTreeWidgetItem(this);
        item->setText(0, "⚠️  Raw data not available (click to load)");
        item->setForeground(0, QColor("#ffaa44"));
        return;
    }

    const uint8_t* data = record.raw_data->data();
    uint32_t       len  = record.cap_len;

    // ── Frame info ────────────────────────────────────────────────────────────
    {
        auto* frame = addSection("📦 Frame",
            QString("len=%1 cap=%2").arg(record.orig_len).arg(record.cap_len));

        auto addField = [&](const QString& k, const QString& v) {
            auto* child = new QTreeWidgetItem(frame);
            child->setText(0, QString("  %-28s %2").arg(k + ":").arg(v));
            child->setForeground(0, QColor("#aaaaaa"));
        };

        QDateTime dt = QDateTime::fromSecsSinceEpoch(
            static_cast<qint64>(record.timestamp));
        addField("Arrival Time",
                 dt.toString("yyyy-MM-dd hh:mm:ss.zzz"));
        addField("Frame Number",  QString::number(record.index + 1));
        addField("Frame Length",  QString::number(record.orig_len) + " bytes");
        addField("Capture Length",QString::number(record.cap_len)  + " bytes");
    }

    size_t offset = 0;

    // ── Ethernet ──────────────────────────────────────────────────────────────
    if (len >= sizeof(struct ether_header)) {
        decodeEthernet(nullptr, data, len);
        offset += sizeof(struct ether_header);

        // VLAN
        uint16_t eth_type = ntohs(
            reinterpret_cast<const struct ether_header*>(data)->ether_type);
        if (eth_type == 0x8100 && offset + 4 <= len) {
            eth_type = ntohs(
                *reinterpret_cast<const uint16_t*>(data + offset + 2));
            offset += 4;
        }

        if (eth_type == ETHERTYPE_IP && offset + sizeof(struct ip) <= len) {
            size_t next = offset;
            decodeIPv4(nullptr, data + offset, len - offset, next);
            offset += next;
        }
    }

    // ── Threat info ───────────────────────────────────────────────────────────
    if (!record.threat_type.empty()) {
        decodeThreat(nullptr, record);
    }
}

void PacketDetailTree::decodeEthernet(QTreeWidgetItem*,
                                       const uint8_t* data,
                                       uint32_t       len) {
    if (len < sizeof(struct ether_header)) return;
    auto* eth = reinterpret_cast<const struct ether_header*>(data);

    uint16_t eth_type = ntohs(eth->ether_type);
    QString  type_str = (eth_type == ETHERTYPE_IP)   ? "IPv4 (0x0800)" :
                        (eth_type == ETHERTYPE_ARP)  ? "ARP  (0x0806)" :
                        (eth_type == 0x86DD)         ? "IPv6 (0x86DD)" :
                        (eth_type == 0x8100)         ? "VLAN (0x8100)" :
                        QString("0x%1").arg(eth_type, 4, 16, QChar('0'));

    auto* section = addSection(
        "🔌 Ethernet II",
        QString("src=%1 dst=%2")
            .arg(macToString(eth->ether_shost))
            .arg(macToString(eth->ether_dhost))
    );

    auto addF = [&](const QString& k, const QString& v) {
        auto* c = new QTreeWidgetItem(section);
        c->setText(0, QString("  %-28s %2").arg(k + ":").arg(v));
        c->setForeground(0, QColor("#aaaaaa"));
    };

    addF("Destination MAC", macToString(eth->ether_dhost));
    addF("Source MAC",      macToString(eth->ether_shost));
    addF("EtherType",       type_str);
}

void PacketDetailTree::decodeIPv4(QTreeWidgetItem*,
                                   const uint8_t* data,
                                   uint32_t       len,
                                   size_t&        next_offset) {
    if (len < sizeof(struct ip)) return;
    auto* ip = reinterpret_cast<const struct ip*>(data);

    struct in_addr src, dst;
    src.s_addr = ip->ip_src.s_addr;
    dst.s_addr = ip->ip_dst.s_addr;

    QString proto_str =
        (ip->ip_p == IPPROTO_TCP)  ? "TCP (6)"   :
        (ip->ip_p == IPPROTO_UDP)  ? "UDP (17)"  :
        (ip->ip_p == IPPROTO_ICMP) ? "ICMP (1)"  :
        QString::number(ip->ip_p);

    auto* section = addSection(
        "🌐 Internet Protocol v4",
        QString("%1 → %2")
            .arg(inet_ntoa(src))
            .arg(inet_ntoa(dst))
    );

    auto addF = [&](const QString& k, const QString& v) {
        auto* c = new QTreeWidgetItem(section);
        c->setText(0, QString("  %-28s %2").arg(k + ":").arg(v));
        c->setForeground(0, QColor("#aaaaaa"));
    };

    addF("Version",          QString::number(ip->ip_v));
    addF("Header Length",    QString::number(ip->ip_hl * 4) + " bytes");
    addF("DSCP / ECN",       QString("0x%1").arg(ip->ip_tos, 2, 16, QChar('0')));
    addF("Total Length",     QString::number(ntohs(ip->ip_len)));
    addF("Identification",   QString("0x%1").arg(ntohs(ip->ip_id), 4, 16, QChar('0')));
    addF("TTL",              QString::number(ip->ip_ttl));
    addF("Protocol",         proto_str);
    addF("Checksum",         QString("0x%1").arg(ntohs(ip->ip_sum), 4, 16, QChar('0')));
    addF("Source IP",        inet_ntoa(src));
    addF("Destination IP",   inet_ntoa(dst));

    size_t ip_hdr_len = ip->ip_hl * 4;
    next_offset = ip_hdr_len;

    const uint8_t* l4_data = data + ip_hdr_len;
    uint32_t       l4_len  = (len > ip_hdr_len) ? len - ip_hdr_len : 0;

    if (ip->ip_p == IPPROTO_TCP)
        decodeTCP(nullptr, l4_data, l4_len);
    else if (ip->ip_p == IPPROTO_UDP)
        decodeUDP(nullptr, l4_data, l4_len);
    else if (ip->ip_p == IPPROTO_ICMP)
        decodeICMP(nullptr, l4_data, l4_len);
}

void PacketDetailTree::decodeTCP(QTreeWidgetItem*,
                                  const uint8_t* data,
                                  uint32_t       len) {
    if (len < sizeof(struct tcphdr)) return;
    auto* tcp = reinterpret_cast<const struct tcphdr*>(data);

    auto* section = addSection(
        "🔗 Transmission Control Protocol",
        QString("port %1 → %2  [%3]")
            .arg(ntohs(tcp->th_sport))
            .arg(ntohs(tcp->th_dport))
            .arg(flagsToString(tcp->th_flags))
    );

    auto addF = [&](const QString& k, const QString& v) {
        auto* c = new QTreeWidgetItem(section);
        c->setText(0, QString("  %-28s %2").arg(k + ":").arg(v));
        c->setForeground(0, QColor("#aaaaaa"));
    };

    addF("Source Port",      QString::number(ntohs(tcp->th_sport)));
    addF("Destination Port", QString::number(ntohs(tcp->th_dport)));
    addF("Sequence Number",  QString::number(ntohl(tcp->th_seq)));
    addF("Ack Number",       QString::number(ntohl(tcp->th_ack)));
    addF("Header Length",    QString::number(tcp->th_off * 4) + " bytes");
    addF("Flags",            flagsToString(tcp->th_flags));
    addF("Window Size",      QString::number(ntohs(tcp->th_win)));
    addF("Checksum",         QString("0x%1").arg(ntohs(tcp->th_sum), 4, 16, QChar('0')));

    // Payload
    size_t tcp_hdr_len = tcp->th_off * 4;
    if (len > tcp_hdr_len) {
        uint32_t payload_len = len - tcp_hdr_len;
        addF("Payload Length", QString::number(payload_len) + " bytes");

        const uint8_t* payload = data + tcp_hdr_len;

        // HTTP detection
        if ((ntohs(tcp->th_sport) == 80  ||
             ntohs(tcp->th_dport) == 80  ||
             ntohs(tcp->th_sport) == 8080||
             ntohs(tcp->th_dport) == 8080) && payload_len > 0) {
            decodeHTTP(section, payload, payload_len);
        }
    }
}

void PacketDetailTree::decodeUDP(QTreeWidgetItem*,
                                  const uint8_t* data,
                                  uint32_t       len) {
    if (len < sizeof(struct udphdr)) return;
    auto* udp = reinterpret_cast<const struct udphdr*>(data);

    auto* section = addSection(
        "📡 User Datagram Protocol",
        QString("port %1 → %2")
            .arg(ntohs(udp->uh_sport))
            .arg(ntohs(udp->uh_dport))
    );

    auto addF = [&](const QString& k, const QString& v) {
        auto* c = new QTreeWidgetItem(section);
        c->setText(0, QString("  %-28s %2").arg(k + ":").arg(v));
        c->setForeground(0, QColor("#aaaaaa"));
    };

    addF("Source Port",      QString::number(ntohs(udp->uh_sport)));
    addF("Destination Port", QString::number(ntohs(udp->uh_dport)));
    addF("Length",           QString::number(ntohs(udp->uh_ulen)));
    addF("Checksum",         QString("0x%1").arg(ntohs(udp->uh_sum), 4, 16, QChar('0')));

    // DNS
    if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53) {
        const uint8_t* dns_data = data + sizeof(struct udphdr);
        uint32_t       dns_len  = ntohs(udp->uh_ulen) > 8
                                  ? ntohs(udp->uh_ulen) - 8 : 0;
        if (dns_len > 0)
            decodeDNS(section, dns_data, dns_len);
    }
}

void PacketDetailTree::decodeICMP(QTreeWidgetItem*,
                                   const uint8_t* data,
                                   uint32_t       len) {
    if (len < 4) return;
    auto* icmp = reinterpret_cast<const struct icmphdr*>(data);

    QString type_str;
    switch (icmp->type) {
        case ICMP_ECHO:      type_str = "Echo Request (8)";  break;
        case ICMP_ECHOREPLY: type_str = "Echo Reply (0)";    break;
        case ICMP_DEST_UNREACH: type_str = "Dest Unreachable (3)"; break;
        case ICMP_TIME_EXCEEDED:type_str = "Time Exceeded (11)";   break;
        default: type_str = QString("Type %1").arg(icmp->type);
    }

    auto* section = addSection("🏓 Internet Control Message Protocol",
                                type_str);
    auto* c1 = new QTreeWidgetItem(section);
    c1->setText(0, QString("  %-28s %2").arg("Type:").arg(type_str));
    c1->setForeground(0, QColor("#aaaaaa"));

    auto* c2 = new QTreeWidgetItem(section);
    c2->setText(0, QString("  %-28s %2")
        .arg("Code:").arg(icmp->code));
    c2->setForeground(0, QColor("#aaaaaa"));
}

void PacketDetailTree::decodeHTTP(QTreeWidgetItem* parent,
                                   const uint8_t*   data,
                                   uint32_t         len) {
    // Chỉ decode nếu là printable ASCII
    bool is_http = false;
    if (len >= 4) {
        std::string start(reinterpret_cast<const char*>(data), 4);
        is_http = (start == "GET " || start == "POST" ||
                   start == "HTTP" || start == "HEAD" ||
                   start == "PUT " || start == "DELE");
    }
    if (!is_http) return;

    auto* section = new QTreeWidgetItem(parent ? parent : invisibleRootItem());
    section->setText(0, "🌍 Hypertext Transfer Protocol");
    section->setForeground(0, QColor("#88aaff"));

    QFont f = section->font(0);
    f.setBold(true);
    section->setFont(0, f);
    section->setExpanded(true);

    // Parse HTTP headers line by line
    std::string raw(reinterpret_cast<const char*>(data),
                    std::min(len, 2048u));
    std::istringstream ss(raw);
    std::string line;
    int line_count = 0;

    while (std::getline(ss, line) && line_count < 20) {
        // Remove \r
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty()) break;

        auto* child = new QTreeWidgetItem(section);
        child->setText(0, "  " + QString::fromStdString(line));
        child->setForeground(0, QColor("#aaaaaa"));
        line_count++;
    }
}

void PacketDetailTree::decodeDNS(QTreeWidgetItem* parent,
                                  const uint8_t*   data,
                                  uint32_t         len) {
    if (len < 12) return;

    uint16_t txid  = ntohs(*reinterpret_cast<const uint16_t*>(data));
    uint16_t flags = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    uint16_t qdcnt = ntohs(*reinterpret_cast<const uint16_t*>(data + 4));
    uint16_t ancnt = ntohs(*reinterpret_cast<const uint16_t*>(data + 6));

    bool is_response = (flags & 0x8000) != 0;

    auto* section = new QTreeWidgetItem(parent ? parent : invisibleRootItem());
    section->setText(0, QString("🔍 Domain Name System (%1)")
        .arg(is_response ? "Response" : "Query"));
    section->setForeground(0, QColor("#88aaff"));

    QFont f = section->font(0);
    f.setBold(true);
    section->setFont(0, f);
    section->setExpanded(true);

    auto addF = [&](const QString& k, const QString& v) {
        auto* c = new QTreeWidgetItem(section);
        c->setText(0, QString("  %-28s %2").arg(k + ":").arg(v));
        c->setForeground(0, QColor("#aaaaaa"));
    };

    addF("Transaction ID", QString("0x%1").arg(txid, 4, 16, QChar('0')));
    addF("Type",           is_response ? "Response" : "Query");
    addF("Questions",      QString::number(qdcnt));
    addF("Answer RRs",     QString::number(ancnt));
}

void PacketDetailTree::decodeThreat(QTreeWidgetItem*,
                                     const PacketRecord& record) {
    auto* section = addSection(
        "🚨 IDS/IPS Detection",
        QString::fromStdString(record.threat_type)
    );
    section->setForeground(0, QColor("#ff6666"));

    auto addF = [&](const QString& k, const QString& v,
                    const QColor& color = QColor("#ffaaaa")) {
        auto* c = new QTreeWidgetItem(section);
        c->setText(0, QString("  %-28s %2").arg(k + ":").arg(v));
        c->setForeground(0, color);
    };

    addF("Threat Type", QString::fromStdString(record.threat_type));
    addF("Action",      QString::fromStdString(record.action));
}

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

QString PacketDetailTree::macToString(const uint8_t* mac) {
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(mac[0], 2, 16, QChar('0'))
        .arg(mac[1], 2, 16, QChar('0'))
        .arg(mac[2], 2, 16, QChar('0'))
        .arg(mac[3], 2, 16, QChar('0'))
        .arg(mac[4], 2, 16, QChar('0'))
        .arg(mac[5], 2, 16, QChar('0'));
}
