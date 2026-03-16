// src/core/packet_info.cpp
#include "packet_info.hpp"
#include <sstream>
#include <arpa/inet.h>

std::string PacketInfo::flowKey() const {
    if (is_ipv6) {
        char src_buf[INET6_ADDRSTRLEN] {};
        char dst_buf[INET6_ADDRSTRLEN] {};
        inet_ntop(AF_INET6, src_ip6.data(), src_buf, sizeof(src_buf));
        inet_ntop(AF_INET6, dst_ip6.data(), dst_buf, sizeof(dst_buf));
        std::ostringstream oss;
        oss << src_buf << ":" << src_port
            << "-" << dst_buf << ":" << dst_port
            << "-" << static_cast<int>(protocol);
        return oss.str();
    }

    // IPv4: src_ip là network byte order → truyền thẳng vào inet_ntop
    char src_buf[INET_ADDRSTRLEN] {};
    char dst_buf[INET_ADDRSTRLEN] {};
    struct in_addr src_addr{}, dst_addr{};
    src_addr.s_addr = src_ip;   // KHÔNG ntohl
    dst_addr.s_addr = dst_ip;
    inet_ntop(AF_INET, &src_addr, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &dst_addr, dst_buf, sizeof(dst_buf));

    std::ostringstream oss;
    oss << src_buf << ":" << src_port
        << "-" << dst_buf << ":" << dst_port
        << "-" << static_cast<int>(protocol);
    return oss.str();
}
