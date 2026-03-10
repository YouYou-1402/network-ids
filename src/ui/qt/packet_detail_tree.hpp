// src/ui/qt/packet_detail_tree.hpp
#pragma once

#include <QTreeWidget>
#include <QTreeWidgetItem>
#include "../../capture/io/packet_ring_buffer.hpp"


class PacketDetailTree : public QTreeWidget {
    Q_OBJECT

public:
    explicit PacketDetailTree(QWidget* parent = nullptr);

    /// Hiển thị chi tiết một packet
    void showPacket(const PacketRecord& record);

    /// Xóa toàn bộ nội dung
    void clearDetail();

private:
    // ── Section / field helpers ───────────────────────────────────────────────
    QTreeWidgetItem* addSection(const QString& title,
                                const QString& summary = {});

    // ── Layer parsers — raw bytes ─────────────────────────────────────────────
    void showEthernet (const uint8_t* data, uint32_t len);
    void showIPv4     (const uint8_t* data, uint32_t len);
    void showTCP      (const uint8_t* data, uint32_t len);
    void showUDP      (const uint8_t* data, uint32_t len);
    void showICMP     (const uint8_t* data, uint32_t len);
    void showARP      (const uint8_t* data, uint32_t len);
    void showIPv6Stub (const uint8_t* data, uint32_t len);

    // ── Application-layer parsers ─────────────────────────────────────────────
    void showHTTP (QTreeWidgetItem* parent, const uint8_t* data, uint32_t len);
    void showDNS  (QTreeWidgetItem* parent, const uint8_t* data, uint32_t len);

    // ── Fallback khi raw_data đã bị evict ────────────────────────────────────
    void showFromFields (const PacketRecord& rec);
    void showThreat     (const PacketRecord& record);

    // ── Utilities ────────────────────────────────────────────────────────────
    static QString flagsToString (uint8_t        flags);
    static QString macStr        (const uint8_t* mac);
};
