#include "packet_info.hpp"
#include <sstream>
#include <arpa/inet.h>

std::string PacketInfo::flowKey() const {
    // Convert IP sang string
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = src_ip;
    dst_addr.s_addr = dst_ip;

    std::ostringstream oss;
    oss << inet_ntoa(src_addr) << ":" << src_port
        << "-"
        << inet_ntoa(dst_addr) << ":" << dst_port
        << "-" << static_cast<int>(protocol);
    return oss.str();
}
