#!/bin/bash
# scripts/generate_test_traffic.py companion shell script
# File: scripts/test_layer1.sh

echo "=== Layer 1 IPS Test Suite ==="

TARGET_IP="127.0.0.1"
TARGET_PORT="8080"

echo "[1] Testing SYN Flood detection..."
hping3 -S -p $TARGET_PORT --flood -c 500 $TARGET_IP &
sleep 3
kill %1

echo "[2] Testing Port Scan detection..."
nmap -sS -p 1-100 $TARGET_IP

echo "[3] Testing Slowloris detection..."
python3 scripts/generate_test_traffic.py --type slowloris \
    --target $TARGET_IP --port $TARGET_PORT --connections 50

echo "=== Test complete. Check ids_system.log ==="
