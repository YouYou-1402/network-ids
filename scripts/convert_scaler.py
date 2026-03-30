#!/usr/bin/env python3
"""
Convert ae_scaler.pkl (sklearn RobustScaler) → ae_scaler.bin
RobustScaler: z = (x - center_) / scale_   (dùng median + IQR)

Format binary C++ đọc:
  [float32 center × 21][float32 scale × 21] = 168 bytes
  → StandardScaler::load() đọc vào mean_[] và std_[]
  → transform: z = (x - mean_[i]) / std_[i]  ← tương thích
"""
import pickle, struct, numpy as np, sys, os

PKL_PATH = "/media/linhlinh/learn/nckh/network-ids/models/ae_scaler.pkl"
BIN_PATH = "/media/linhlinh/learn/nckh/network-ids/models/ae_scaler.bin"
N_FEATURES = 21

with open(PKL_PATH, "rb") as f:
    scaler = pickle.load(f)

print(f"[INFO] Scaler type : {type(scaler).__name__}")
print(f"[INFO] Scaler attrs: {[a for a in dir(scaler) if not a.startswith('_')]}")

# ── RobustScaler: dùng center_ và scale_ ──────────────────────────────────────
if hasattr(scaler, 'center_'):
    center = np.array(scaler.center_).astype(np.float32)
    scale  = np.array(scaler.scale_).astype(np.float32)
    print(f"[INFO] RobustScaler detected")
    print(f"       center[:5] = {center[:5]}")
    print(f"       scale[:5]  = {scale[:5]}")

# ── StandardScaler: dùng mean_ và scale_ ──────────────────────────────────────
elif hasattr(scaler, 'mean_'):
    center = np.array(scaler.mean_).astype(np.float32)
    scale  = np.array(scaler.scale_).astype(np.float32)
    print(f"[INFO] StandardScaler detected")

# ── MinMaxScaler ───────────────────────────────────────────────────────────────
elif hasattr(scaler, 'data_min_'):
    center = np.array(scaler.data_min_).astype(np.float32)
    scale  = np.array(scaler.data_range_).astype(np.float32)
    print(f"[INFO] MinMaxScaler detected")

else:
    print(f"[ERROR] Unknown scaler type: {type(scaler).__name__}")
    print(f"        Available attrs: {[a for a in dir(scaler) if not a.startswith('_')]}")
    sys.exit(1)

# ── Validate ──────────────────────────────────────────────────────────────────
assert len(center) == N_FEATURES, \
    f"Expected {N_FEATURES} features, got {len(center)}"
assert len(scale) == N_FEATURES, \
    f"Expected {N_FEATURES} features, got {len(scale)}"

for i, s in enumerate(scale):
    if s <= 0:
        print(f"[WARN] scale[{i}]={s} <= 0, clamping to 1.0")
        scale[i] = 1.0

# ── Ghi binary ────────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(BIN_PATH), exist_ok=True)
with open(BIN_PATH, "wb") as f:
    f.write(struct.pack(f"{N_FEATURES}f", *center))
    f.write(struct.pack(f"{N_FEATURES}f", *scale))

print(f"\n[OK] Saved → {BIN_PATH}  ({N_FEATURES*2*4} bytes)")

# ── Verify: đọc lại ───────────────────────────────────────────────────────────
with open(BIN_PATH, "rb") as f:
    c2 = np.frombuffer(f.read(N_FEATURES * 4), dtype=np.float32)
    s2 = np.frombuffer(f.read(N_FEATURES * 4), dtype=np.float32)

assert np.allclose(center, c2), "center mismatch!"
assert np.allclose(scale,  s2), "scale mismatch!"
print("[OK] Verify passed — binary file is correct")

# ── In bảng đầy đủ ───────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "flow_duration",    "total_pkt_fwd",   "total_pkt_bwd",
    "total_byte_fwd",   "total_byte_bwd",
    "syn_count",        "ack_count",       "rst_count",
    "fin_count",        "syn_no_ack_ratio",
    "pkt_rate",         "byte_rate",       "pkt_per_flow",
    "conn_duration",    "bytes_per_second",
    "inter_arrival_mean","inter_arrival_std",
    "header_complete",  "concurrent_conn",
    "unique_dst_ports", "rst_ratio"
]

print(f"\n{'idx':<4} {'feature':<22} {'center':>12} {'scale':>12}")
print("-" * 54)
for i, name in enumerate(FEATURE_NAMES):
    print(f"{i:<4} {name:<22} {center[i]:>12.4f} {scale[i]:>12.4f}")
