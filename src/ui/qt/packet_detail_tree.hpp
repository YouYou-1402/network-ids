// ── packet_detail_tree.hpp ────────────────────────────────────────────────────
#pragma once
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include "../../pcap_io/packet_ring_buffer.hpp"

// Decode và hiển thị chi tiết từng layer (giống Wireshark middle pane)
class PacketDetailTree : public QTreeWidget {
    Q_OBJECT

public:
    explicit PacketDetailTree(QWidget* parent = nullptr);

    // Hiển thị chi tiết một packet
    void showPacket(const PacketRecord& record);

    // Xóa
    void clearDetail();

private:
    QTreeWidgetItem* addSection(const QString& title,
                                 const QString& summary = "");

    void decodeEthernet (QTreeWidgetItem* parent,
                         const uint8_t*   data, uint32_t len);
    void decodeIPv4     (QTreeWidgetItem* parent,
                         const uint8_t*   data, uint32_t len,
                         size_t&          next_offset);
    void decodeTCP      (QTreeWidgetItem* parent,
                         const uint8_t*   data, uint32_t len);
    void decodeUDP      (QTreeWidgetItem* parent,
                         const uint8_t*   data, uint32_t len);
    void decodeICMP     (QTreeWidgetItem* parent,
                         const uint8_t*   data, uint32_t len);
    void decodeHTTP     (QTreeWidgetItem* parent,
                         const uint8_t*   data, uint32_t len);
    void decodeDNS      (QTreeWidgetItem* parent,
                         const uint8_t*   data, uint32_t len);
    void decodeThreat   (QTreeWidgetItem* parent,
                         const PacketRecord& record);

    static QString flagsToString(uint8_t flags);
    static QString macToString  (const uint8_t* mac);
};
