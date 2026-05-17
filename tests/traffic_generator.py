"""
traffic_generator.py
Tạo luồng traffic bình thường thật sự qua mạng:
  - HTTP GET requests
  - TCP connections
  - UDP packets
  - ICMP ping
  - DNS queries
Chạy: python traffic_generator.py
"""

import socket
import time
import random
import threading
import urllib.request
import subprocess
import platform

# ─── Cấu hình ────────────────────────────────────────────────────────────────
DURATION   = 60        # Chạy bao nhiêu giây
INTERVAL   = 0.5       # Khoảng cách giữa mỗi request (giây)
LOG_FILE   = "traffic_log.txt"

# Danh sách target bình thường (public, hợp lệ)
HTTP_TARGETS = [
    "http://example.com",
    "http://httpbin.org/get",
    "http://neverssl.com",
]

DNS_TARGETS = [
    "example.com",
    "google.com",
    "github.com",
    "wikipedia.org",
]

UDP_HOST = "8.8.8.8"   # Google DNS
UDP_PORT = 53

log_lock = threading.Lock()

def log(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with log_lock:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")

# ─── 1. HTTP GET ─────────────────────────────────────────────────────────────
def send_http():
    url = random.choice(HTTP_TARGETS)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            size = len(resp.read())
            log(f"[HTTP ] GET {url} → {resp.status} | {size} bytes")
    except Exception as e:
        log(f"[HTTP ] {url} → ERR: {e}")

# ─── 2. TCP Connect ──────────────────────────────────────────────────────────
TCP_TARGETS = [
    ("example.com",  80),
    ("github.com",   443),
    ("google.com",   80),
]

def send_tcp():
    host, port = random.choice(TCP_TARGETS)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        # Gửi HTTP request đơn giản
        s.send(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = s.recv(256)
        s.close()
        log(f"[TCP  ] {host}:{port} → {len(data)} bytes received")
    except Exception as e:
        log(f"[TCP  ] {host}:{port} → ERR: {e}")

# ─── 3. UDP Packet ───────────────────────────────────────────────────────────
def send_udp():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        # DNS query đơn giản cho google.com
        dns_query = (
            b'\xaa\xbb'   # Transaction ID
            b'\x01\x00'   # Flags: standard query
            b'\x00\x01'   # Questions: 1
            b'\x00\x00\x00\x00\x00\x00'
            b'\x06google\x03com\x00'
            b'\x00\x01\x00\x01'
        )
        s.sendto(dns_query, (UDP_HOST, UDP_PORT))
        data, _ = s.recvfrom(512)
        s.close()
        log(f"[UDP  ] DNS query → {UDP_HOST}:{UDP_PORT} | resp {len(data)} bytes")
    except Exception as e:
        log(f"[UDP  ] ERR: {e}")

# ─── 4. DNS Lookup ───────────────────────────────────────────────────────────
def send_dns():
    domain = random.choice(DNS_TARGETS)
    try:
        ip = socket.gethostbyname(domain)
        log(f"[DNS  ] {domain} → {ip}")
    except Exception as e:
        log(f"[DNS  ] {domain} → ERR: {e}")

# ─── 5. ICMP Ping ────────────────────────────────────────────────────────────
PING_TARGETS = ["8.8.8.8", "1.1.1.1", "example.com"]

def send_ping():
    host = random.choice(PING_TARGETS)
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(
            ["ping", param, "1", "-W", "2", host],
            capture_output=True, text=True, timeout=5
        )
        status = "OK" if result.returncode == 0 else "FAIL"
        log(f"[ICMP ] ping {host} → {status}")
    except Exception as e:
        log(f"[ICMP ] ping {host} → ERR: {e}")

# ─── Main Loop ───────────────────────────────────────────────────────────────
ACTIONS = [send_http, send_tcp, send_udp, send_dns, send_ping]
WEIGHTS  = [0.35,     0.25,     0.15,     0.15,     0.10]   # xác suất mỗi loại

def main():
    print("=" * 55)
    print("  Normal Traffic Generator")
    print(f"  Duration : {DURATION}s | Interval: {INTERVAL}s")
    print(f"  Log file : {LOG_FILE}")
    print("=" * 55)

    open(LOG_FILE, "w").close()   # reset log

    start = time.time()
    count = 0

    while time.time() - start < DURATION:
        # Chọn ngẫu nhiên loại traffic theo trọng số
        action = random.choices(ACTIONS, weights=WEIGHTS, k=1)[0]

        # Chạy trong thread riêng để không block
        t = threading.Thread(target=action, daemon=True)
        t.start()

        count += 1
        time.sleep(INTERVAL + random.uniform(-0.1, 0.2))  # jitter tự nhiên

    print(f"\n✅ Hoàn thành! Đã gửi {count} requests trong {DURATION}s")
    print(f"📄 Log lưu tại: {LOG_FILE}")

if __name__ == "__main__":
    main()
