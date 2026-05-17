#!/usr/bin/env python3
# =============================================================================
#  test_model_direct.py
#  Test ONNX autoencoder trực tiếp — không cần network, không cần IDS
#  Chạy: python3 test_model_direct.py --model models/autoencoder_ids_model.onnx
#                                     --scaler models/scaler_nslkdd.bin
# =============================================================================

import argparse
import struct
import numpy as np

try:
    import onnxruntime as ort
    HAS_ORT = True
except ImportError:
    HAS_ORT = False
    print("[WARN] onnxruntime not installed: pip install onnxruntime")

# =============================================================================
#  1. Load RobustScaler từ .bin (168 bytes)
# =============================================================================
def load_scaler(path: str):
    with open(path, "rb") as f:
        data = f.read()
    assert len(data) == 168, f"scaler size={len(data)}, expected 168 bytes"
    center = np.frombuffer(data[:84],  dtype=np.float32).copy()  # 21 floats
    scale  = np.frombuffer(data[84:],  dtype=np.float32).copy()  # 21 floats
    scale[scale < 1e-9] = 1.0
    print(f"[Scaler] center[:5] = {center[:5]}")
    print(f"[Scaler] scale[:5]  = {scale[:5]}")
    return center, scale

# =============================================================================
#  2. RobustScaler transform
# =============================================================================
def robust_scale(raw21: np.ndarray, center, scale) -> np.ndarray:
    z = (raw21 - center) / scale
    return np.clip(z, -5.0, 5.0)

# =============================================================================
#  3. Build feature vector 35 dims từ dict flow
#
#  Layout:
#  [0..14]  log1p → RobustScaler  (15 cols)
#  [15..20] RobustScaler only     (6  cols)
#  [21..23] protocol OHE          (icmp/tcp/udp)
#  [24..33] flag OHE              (OTH/REJ/RSTO/RSTR/S0/S1/S2/S3/SF/SH)
#  [34]     service freq          (FrequencyEncoder)
# =============================================================================
PROTO_IDX = {"icmp": 21, "tcp": 22, "udp": 23}
FLAG_IDX  = {"OTH":24,"REJ":25,"RSTO":26,"RSTR":27,
             "S0":28,"S1":29,"S2":30,"S3":31,"SF":32,"SH":33}

def build_vector(flow: dict, center, scale) -> np.ndarray:
    vec = np.zeros(35, dtype=np.float32)

    # ── LOG block [0..14] ────────────────────────────────────────────────────
    raw = np.zeros(21, dtype=np.float32)
    raw[0]  = np.log1p(max(0, flow.get("duration",          0)))
    raw[1]  = np.log1p(max(0, flow.get("src_bytes",         0)))
    raw[2]  = np.log1p(max(0, flow.get("dst_bytes",         0)))
    raw[3]  = np.log1p(max(0, flow.get("wrong_fragment",    0)))
    raw[4]  = np.log1p(max(0, flow.get("hot",               0)))
    raw[5]  = np.log1p(max(0, flow.get("num_compromised",   0)))
    raw[6]  = 0.0  # num_file_creations (dropped)
    raw[7]  = np.log1p(max(0, flow.get("count",             0)))
    raw[8]  = np.log1p(max(0, flow.get("srv_count",         0)))
    raw[9]  = np.log1p(np.clip(flow.get("rerror_rate",      0), 0, 1))
    raw[10] = np.log1p(np.clip(flow.get("diff_srv_rate",    0), 0, 1))
    raw[11] = np.log1p(np.clip(flow.get("srv_diff_host_rate",0),0, 1))
    raw[12] = np.log1p(np.clip(flow.get("dst_host_diff_srv_rate",0),0,1))
    raw[13] = np.log1p(np.clip(flow.get("dst_host_same_src_port_rate",0),0,1))
    raw[14] = np.log1p(np.clip(flow.get("dst_host_srv_diff_host_rate",0),0,1))

    # ── NUM block [15..20] ───────────────────────────────────────────────────
    raw[15] = 1.0 if flow.get("logged_in", False) else 0.0
    raw[16] = np.clip(flow.get("serror_rate",          0), 0, 1)
    raw[17] = np.clip(flow.get("same_srv_rate",        0), 0, 1)
    raw[18] = float(flow.get("dst_host_count",         0))
    raw[19] = float(flow.get("dst_host_srv_count",     0))
    raw[20] = np.clip(flow.get("dst_host_same_srv_rate",0), 0, 1)

    # ── RobustScaler ─────────────────────────────────────────────────────────
    scaled = robust_scale(raw, center, scale)
    vec[:21] = scaled

    # ── Protocol OHE [21..23] ────────────────────────────────────────────────
    proto = flow.get("protocol", "tcp").lower()
    if proto in PROTO_IDX:
        vec[PROTO_IDX[proto]] = 1.0

    # ── Flag OHE [24..33] ────────────────────────────────────────────────────
    flag = flow.get("flag", "SF").upper()
    if flag in FLAG_IDX:
        vec[FLAG_IDX[flag]] = 1.0

    # ── Service FreqEnc [34] ─────────────────────────────────────────────────
    vec[34] = float(flow.get("service_freq", -0.01))

    return vec

# =============================================================================
#  4. ONNX inference
# =============================================================================
def infer(session, vec35: np.ndarray, threshold: float):
    inp = vec35.reshape(1, 35).astype(np.float32)
    input_name  = session.get_inputs()[0].name
    output_name = session.get_outputs()[0].name
    recon = session.run([output_name], {input_name: inp})[0][0]
    mse   = float(np.mean((vec35 - recon) ** 2))
    label = "🔴 ATTACK" if mse > threshold else "🟢 NORMAL"
    return mse, label, recon

# =============================================================================
#  5. Test cases — NSL-KDD style
# =============================================================================
TEST_CASES = [
    # ── NORMAL ────────────────────────────────────────────────────────────────
    {
        "name": "Normal HTTP",
        "expect": "NORMAL",
        "flow": {
            "duration": 2, "src_bytes": 500, "dst_bytes": 8000,
            "protocol": "tcp", "flag": "SF", "service_freq": 0.15,
            "logged_in": True, "count": 10, "srv_count": 10,
            "serror_rate": 0.0, "rerror_rate": 0.0,
            "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 50, "dst_host_srv_count": 50,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.5,
            "dst_host_srv_diff_host_rate": 0.0,
        }
    },
    {
        "name": "Normal FTP",
        "expect": "NORMAL",
        "flow": {
            "duration": 5, "src_bytes": 1200, "dst_bytes": 3000,
            "protocol": "tcp", "flag": "SF", "service_freq": 0.05,
            "logged_in": True, "count": 5, "srv_count": 5,
            "serror_rate": 0.0, "rerror_rate": 0.0,
            "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 20, "dst_host_srv_count": 20,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.2,
            "dst_host_srv_diff_host_rate": 0.0,
        }
    },
    {
        "name": "Normal DNS (UDP)",
        "expect": "NORMAL",
        "flow": {
            "duration": 0, "src_bytes": 60, "dst_bytes": 200,
            "protocol": "udp", "flag": "SF", "service_freq": 0.08,
            "logged_in": False, "count": 3, "srv_count": 3,
            "serror_rate": 0.0, "rerror_rate": 0.0,
            "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 10, "dst_host_srv_count": 10,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.1,
            "dst_host_srv_diff_host_rate": 0.0,
        }
    },
    # ── PORT SCAN ─────────────────────────────────────────────────────────────
    {
        "name": "Port Scan (SYN scan)",
        "expect": "ATTACK",
        "flow": {
            "duration": 0, "src_bytes": 0, "dst_bytes": 0,
            "protocol": "tcp", "flag": "S0", "service_freq": -0.01,
            "logged_in": False, "count": 511, "srv_count": 3,
            "serror_rate": 1.0, "rerror_rate": 0.0,
            "same_srv_rate": 0.01, "diff_srv_rate": 0.99,
            "srv_diff_host_rate": 0.99,
            "dst_host_count": 255, "dst_host_srv_count": 3,
            "dst_host_same_srv_rate": 0.01,
            "dst_host_diff_srv_rate": 0.99,
            "dst_host_same_src_port_rate": 0.01,
            "dst_host_srv_diff_host_rate": 0.99,
        }
    },
    {
        "name": "Port Scan (REJ)",
        "expect": "ATTACK",
        "flow": {
            "duration": 0, "src_bytes": 0, "dst_bytes": 0,
            "protocol": "tcp", "flag": "REJ", "service_freq": -0.01,
            "logged_in": False, "count": 255, "srv_count": 2,
            "serror_rate": 0.0, "rerror_rate": 1.0,
            "same_srv_rate": 0.01, "diff_srv_rate": 0.99,
            "srv_diff_host_rate": 0.99,
            "dst_host_count": 255, "dst_host_srv_count": 2,
            "dst_host_same_srv_rate": 0.01,
            "dst_host_diff_srv_rate": 0.99,
            "dst_host_same_src_port_rate": 0.01,
            "dst_host_srv_diff_host_rate": 0.99,
        }
    },
    # ── SYN FLOOD / DDoS ──────────────────────────────────────────────────────
    {
        "name": "SYN Flood (DDoS)",
        "expect": "ATTACK",
        "flow": {
            "duration": 0, "src_bytes": 0, "dst_bytes": 0,
            "protocol": "tcp", "flag": "S0", "service_freq": 0.15,
            "logged_in": False, "count": 511, "srv_count": 511,
            "serror_rate": 1.0, "rerror_rate": 0.0,
            "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255, "dst_host_srv_count": 255,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
        }
    },
    {
        "name": "UDP Flood",
        "expect": "ATTACK",
        "flow": {
            "duration": 0, "src_bytes": 100000, "dst_bytes": 0,
            "protocol": "udp", "flag": "SF", "service_freq": -0.01,
            "logged_in": False, "count": 511, "srv_count": 511,
            "serror_rate": 0.0, "rerror_rate": 0.0,
            "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255, "dst_host_srv_count": 255,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 1.0,
            "dst_host_srv_diff_host_rate": 0.0,
        }
    },
    # ── SLOW ATTACK ───────────────────────────────────────────────────────────
    {
        "name": "Slowloris",
        "expect": "ATTACK",
        "flow": {
            "duration": 300, "src_bytes": 200, "dst_bytes": 0,
            "protocol": "tcp", "flag": "S1", "service_freq": 0.15,
            "logged_in": False, "count": 255, "srv_count": 255,
            "serror_rate": 0.0, "rerror_rate": 0.0,
            "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255, "dst_host_srv_count": 255,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
        }
    },
    # ── PROBE / R2L ───────────────────────────────────────────────────────────
    {
        "name": "Neptune (DoS)",
        "expect": "ATTACK",
        "flow": {
            "duration": 0, "src_bytes": 0, "dst_bytes": 0,
            "protocol": "tcp", "flag": "S0", "service_freq": 0.15,
            "logged_in": False, "count": 511, "srv_count": 511,
            "serror_rate": 1.0, "rerror_rate": 0.0,
            "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255, "dst_host_srv_count": 255,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
        }
    },
    {
        "name": "Smurf (ICMP flood)",
        "expect": "ATTACK",
        "flow": {
            "duration": 0, "src_bytes": 1032, "dst_bytes": 0,
            "protocol": "icmp", "flag": "SF", "service_freq": -0.01,
            "logged_in": False, "count": 511, "srv_count": 511,
            "serror_rate": 0.0, "rerror_rate": 0.0,
            "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255, "dst_host_srv_count": 255,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 1.0,
            "dst_host_srv_diff_host_rate": 0.0,
        }
    },
]

# =============================================================================
#  6. MAIN
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="Direct ONNX model tester")
    parser.add_argument("--model",     required=True,  help="Path to .onnx model")
    parser.add_argument("--scaler",    required=True,  help="Path to scaler_nslkdd.bin")
    parser.add_argument("--threshold", type=float, default=0.099726)
    parser.add_argument("--verbose",   action="store_true")
    args = parser.parse_args()

    if not HAS_ORT:
        print("ERROR: pip install onnxruntime")
        return

    # Load
    print(f"\n{'='*60}")
    print(f"  Model   : {args.model}")
    print(f"  Scaler  : {args.scaler}")
    print(f"  Threshold: {args.threshold}")
    print(f"{'='*60}\n")

    center, scale = load_scaler(args.scaler)
    sess = ort.InferenceSession(args.model,
           providers=["CPUExecutionProvider"])

    # Validate input dim
    input_shape = sess.get_inputs()[0].shape
    print(f"[Model] input shape : {input_shape}")
    print(f"[Model] output shape: {sess.get_outputs()[0].shape}\n")

    if input_shape[1] != 35:
        print(f"[ERROR] Model expects {input_shape[1]} dims, pipeline produces 35!")
        print("        → Cần export lại model với input_dim=35")
        return

    # Run test cases
    print(f"{'─'*60}")
    print(f"{'#':<3} {'Name':<28} {'Expect':<8} {'MSE':>10}  {'Result':<14} {'OK?'}")
    print(f"{'─'*60}")

    n_pass = n_fail = 0
    for i, tc in enumerate(TEST_CASES):
        vec  = build_vector(tc["flow"], center, scale)
        mse, label, recon = infer(sess, vec, args.threshold)
        result_str = "ATTACK" if "ATTACK" in label else "NORMAL"
        ok = "✅" if result_str == tc["expect"] else "❌"
        if result_str == tc["expect"]: n_pass += 1
        else:                          n_fail += 1

        print(f"{i+1:<3} {tc['name']:<28} {tc['expect']:<8} {mse:>10.6f}  {label:<14} {ok}")

        if args.verbose:
            print(f"    vec[:5]  = {vec[:5]}")
            print(f"    recon[:5]= {recon[:5]}")

    print(f"{'─'*60}")
    print(f"  PASS: {n_pass}/{len(TEST_CASES)}   FAIL: {n_fail}/{len(TEST_CASES)}")
    print(f"{'='*60}\n")

    # MSE distribution
    print("[INFO] MSE distribution per category:")
    normal_mse  = []
    attack_mse  = []
    for tc in TEST_CASES:
        vec = build_vector(tc["flow"], center, scale)
        mse, _, _ = infer(sess, vec, args.threshold)
        if tc["expect"] == "NORMAL": normal_mse.append(mse)
        else:                        attack_mse.append(mse)

    if normal_mse:
        print(f"  NORMAL  MSE: min={min(normal_mse):.6f}  "
              f"max={max(normal_mse):.6f}  "
              f"mean={sum(normal_mse)/len(normal_mse):.6f}")
    if attack_mse:
        print(f"  ATTACK  MSE: min={min(attack_mse):.6f}  "
              f"max={max(attack_mse):.6f}  "
              f"mean={sum(attack_mse)/len(attack_mse):.6f}")
    print(f"  Threshold  : {args.threshold:.6f}")

    if n_fail > 0:
        print(f"\n[HINT] Nếu ATTACK MSE < threshold → tăng threshold")
        print(f"       Nếu NORMAL MSE > threshold → giảm threshold")
        print(f"       Hoặc kiểm tra lại scaler (center/scale values)")

if __name__ == "__main__":
    main()
