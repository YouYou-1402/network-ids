#pragma once
#include <string>
#include <vector>
#include <cstdint>

// ─────────────────────────────────────────────────────────────────────────────
//  BpfFilter — Builder pattern để tạo BPF filter expression
//
//  Sử dụng:
//    std::string expr = BpfFilter::builder()
//        .inbound("192.168.99.79")
//        .excludeHost("192.168.99.79")   // loại outbound của IDS
//        .tcp()
//        .port(80)
//        .build();
//
//  Hoặc dùng preset:
//    std::string expr = BpfFilter::inboundOnly("192.168.99.79");
//    std::string expr = BpfFilter::monitorHost("192.168.99.79", {80, 443});
// ─────────────────────────────────────────────────────────────────────────────

class BpfFilter {
public:

    // =========================================================================
    //  Builder
    // =========================================================================
    class Builder {
    public:
        // ── Host filters ─────────────────────────────────────────────────────

        /// Chỉ capture traffic đến host này (inbound)
        Builder& inbound(const std::string& dst_ip);

        /// Chỉ capture traffic từ host này (outbound)
        Builder& outbound(const std::string& src_ip);

        /// Loại trừ traffic từ/đến host này
        Builder& excludeHost(const std::string& ip);

        /// Loại trừ traffic từ host này (src)
        Builder& excludeSrc(const std::string& ip);

        /// Chỉ capture traffic giữa 2 host
        Builder& between(const std::string& ip_a, const std::string& ip_b);

        // ── Protocol filters ──────────────────────────────────────────────────

        Builder& tcp();
        Builder& udp();
        Builder& icmp();
        Builder& tcpOrUdp();

        // ── Port filters ──────────────────────────────────────────────────────

        /// Chỉ capture traffic đến port này (dst port)
        Builder& port(uint16_t p);

        /// Chỉ capture traffic đến các port này
        Builder& ports(const std::vector<uint16_t>& ps);

        /// Loại trừ port
        Builder& excludePort(uint16_t p);

        // ── TCP flag filters ──────────────────────────────────────────────────

        /// Chỉ capture TCP SYN packet (không có ACK)
        Builder& tcpSynOnly();

        /// Chỉ capture TCP SYN + ACK
        Builder& tcpSynAck();

        /// Loại trừ TCP ACK-only (giảm noise)
        Builder& excludeTcpAckOnly();

        // ── Subnet filters ────────────────────────────────────────────────────

        /// Chỉ capture traffic trong subnet
        Builder& subnet(const std::string& cidr);

        /// Loại trừ traffic từ subnet
        Builder& excludeSubnet(const std::string& cidr);

        // ── Payload size filter ───────────────────────────────────────────────

        /// Chỉ capture packet có payload > n bytes
        Builder& minPayload(uint32_t bytes);

        // ── Raw expression ────────────────────────────────────────────────────

        /// Thêm raw BPF expression (AND với các điều kiện khác)
        Builder& raw(const std::string& expr);

        // ── Build ─────────────────────────────────────────────────────────────
        std::string build() const;

    private:
        std::vector<std::string> include_clauses_;   // AND
        std::vector<std::string> exclude_clauses_;   // AND NOT
    };

    // =========================================================================
    //  Static factory
    // =========================================================================
    static Builder builder() { return Builder{}; }

    // ── Preset filters ────────────────────────────────────────────────────────

    /// Chỉ capture traffic inbound đến ids_ip
    /// → loại bỏ outbound của chính máy IDS
    static std::string inboundOnly(const std::string& ids_ip);

    /// Capture traffic liên quan ids_ip trên các port cụ thể
    static std::string monitorHost(const std::string& ids_ip,
                                   const std::vector<uint16_t>& ports);

    /// Capture tất cả trừ traffic nội bộ của IDS
    static std::string excludeIdsTraffic(const std::string& ids_ip);

    /// Preset cho Slow DDoS detection:
    /// - Chỉ TCP inbound
    /// - Loại outbound của IDS
    /// - Loại ACK-only (giảm noise)
    static std::string slowDdosDetection(const std::string& ids_ip,
                                         uint16_t           port = 80);

    /// Preset cho Port Scan detection:
    /// - Chỉ inbound TCP/UDP
    /// - Loại outbound của IDS
    static std::string portScanDetection(const std::string& ids_ip);

    /// Preset cho full monitoring (tất cả inbound, loại IDS outbound)
    static std::string fullMonitor(const std::string& ids_ip);

    // ── Validate ──────────────────────────────────────────────────────────────

    /// Kiểm tra BPF expression có hợp lệ không (compile thử với pcap)
    /// Trả về "" nếu hợp lệ, error message nếu không
    static std::string validate(const std::string& expr);
};
