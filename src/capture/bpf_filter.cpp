#include "bpf_filter.hpp"
#include "../common/logger.hpp"

#include <pcap.h>
#include <sstream>
#include <stdexcept>

// =============================================================================
//  Builder — internal helpers
// =============================================================================

namespace {

/// Wrap expression trong ngoặc nếu chứa khoảng trắng
std::string wrap(const std::string& s) {
    if (s.find(' ') != std::string::npos)
        return "(" + s + ")";
    return s;
}

/// Join vector<string> bằng separator
std::string join(const std::vector<std::string>& v,
                 const std::string&               sep) {
    std::string result;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) result += sep;
        result += v[i];
    }
    return result;
}

} // namespace

// =============================================================================
//  Builder — implementation
// =============================================================================

BpfFilter::Builder& BpfFilter::Builder::inbound(const std::string& dst_ip) {
    include_clauses_.push_back("dst host " + dst_ip);
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::outbound(const std::string& src_ip) {
    include_clauses_.push_back("src host " + src_ip);
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::excludeHost(const std::string& ip) {
    exclude_clauses_.push_back("host " + ip);
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::excludeSrc(const std::string& ip) {
    exclude_clauses_.push_back("src host " + ip);
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::between(const std::string& ip_a,
                                                  const std::string& ip_b) {
    include_clauses_.push_back(
        "(src host " + ip_a + " and dst host " + ip_b + ")"
        " or "
        "(src host " + ip_b + " and dst host " + ip_a + ")"
    );
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::tcp() {
    include_clauses_.push_back("tcp");
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::udp() {
    include_clauses_.push_back("udp");
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::icmp() {
    include_clauses_.push_back("icmp");
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::tcpOrUdp() {
    include_clauses_.push_back("(tcp or udp)");
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::port(uint16_t p) {
    include_clauses_.push_back("dst port " + std::to_string(p));
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::ports(const std::vector<uint16_t>& ps) {
    if (ps.empty()) return *this;
    if (ps.size() == 1) return port(ps[0]);

    std::string expr = "(dst port " + std::to_string(ps[0]);
    for (size_t i = 1; i < ps.size(); ++i)
        expr += " or dst port " + std::to_string(ps[i]);
    expr += ")";
    include_clauses_.push_back(expr);
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::excludePort(uint16_t p) {
    exclude_clauses_.push_back("port " + std::to_string(p));
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::tcpSynOnly() {
    // tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn
    include_clauses_.push_back(
        "tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack)) == tcp-syn"
    );
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::tcpSynAck() {
    include_clauses_.push_back(
        "tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack)) == (tcp-syn|tcp-ack)"
    );
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::excludeTcpAckOnly() {
    // Loại packet chỉ có ACK (không SYN, FIN, RST, PSH)
    // tcp[tcpflags] & (syn|fin|rst|psh|urg) == 0  AND  ack != 0
    exclude_clauses_.push_back(
        "(tcp and "
        "(tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-push|tcp-urg)) == 0 and "
        "(tcp[tcpflags] & tcp-ack) != 0)"
    );
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::subnet(const std::string& cidr) {
    include_clauses_.push_back("net " + cidr);
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::excludeSubnet(const std::string& cidr) {
    exclude_clauses_.push_back("net " + cidr);
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::minPayload(uint32_t bytes) {
    // greater N: packet có length > N bytes (bao gồm header)
    // Dùng "greater" thay vì "len > N" cho portable hơn
    include_clauses_.push_back("greater " + std::to_string(bytes));
    return *this;
}

BpfFilter::Builder& BpfFilter::Builder::raw(const std::string& expr) {
    if (!expr.empty())
        include_clauses_.push_back(wrap(expr));
    return *this;
}

// ─── build ────────────────────────────────────────────────────────────────────
std::string BpfFilter::Builder::build() const {
    std::vector<std::string> parts;

    // AND tất cả include clauses
    for (const auto& c : include_clauses_)
        parts.push_back(wrap(c));

    // AND NOT tất cả exclude clauses
    for (const auto& c : exclude_clauses_)
        parts.push_back("not " + wrap(c));

    if (parts.empty()) return "";

    const std::string result = join(parts, " and ");

    LOG_DEBUG("BpfFilter built: " + result);
    return result;
}

// =============================================================================
//  Preset filters
// =============================================================================

std::string BpfFilter::inboundOnly(const std::string& ids_ip) {
    // Chỉ packet đến ids_ip
    // Loại outbound của IDS (src = ids_ip)
    return builder()
        .inbound(ids_ip)
        .build();
}

std::string BpfFilter::monitorHost(const std::string&           ids_ip,
                                    const std::vector<uint16_t>& ports) {
    return builder()
        .inbound(ids_ip)
        .ports(ports)
        .build();
}

std::string BpfFilter::excludeIdsTraffic(const std::string& ids_ip) {
    // Capture tất cả TRỪ traffic do chính IDS tạo ra
    return builder()
        .excludeSrc(ids_ip)
        .build();
}

std::string BpfFilter::slowDdosDetection(const std::string& ids_ip,
                                          uint16_t           port) {
    // TCP inbound đến port cụ thể
    // Loại ACK-only để giảm noise từ response packet
    return builder()
        .tcp()
        .inbound(ids_ip)
        .port(port)
        .excludeTcpAckOnly()
        .build();
}

std::string BpfFilter::portScanDetection(const std::string& ids_ip) {
    // TCP + UDP inbound
    // Loại outbound của IDS
    return builder()
        .tcpOrUdp()
        .inbound(ids_ip)
        .build();
}

std::string BpfFilter::fullMonitor(const std::string& ids_ip) {
    // Tất cả inbound, loại outbound của IDS
    return builder()
        .inbound(ids_ip)
        .build();
}

// =============================================================================
//  Validate
// =============================================================================

std::string BpfFilter::validate(const std::string& expr) {
    if (expr.empty()) return "";

    // Dùng pcap_open_dead để compile thử mà không cần interface thật
    pcap_t* p = pcap_open_dead(DLT_EN10MB, 65535);
    if (!p) return "pcap_open_dead failed";

    struct bpf_program fp{};
    const int rc = pcap_compile(p, &fp, expr.c_str(), 1, PCAP_NETMASK_UNKNOWN);

    std::string err;
    if (rc < 0)
        err = std::string(pcap_geterr(p));
    else
        pcap_freecode(&fp);

    pcap_close(p);

    if (!err.empty())
        LOG_WARN("BpfFilter::validate failed [" + expr + "]: " + err);

    return err;   // "" = OK
}
