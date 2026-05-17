#!/usr/bin/env python3
"""
find_threshold.py — Tìm threshold tối ưu cho NSL-KDD Autoencoder (35 dims)
Vector 35 chiều:
  [0..14]  : 15 log-features  (scaled bằng scaler 21 features — index 0..14)
  [15..20] : 6  num-features  (scaled bằng scaler 21 features — index 15..20)
  [21..23] : 3  proto one-hot (KHÔNG scale)
  [24..33] : 10 flag  one-hot (KHÔNG scale)
  [34]     : 1  freq feature  (KHÔNG scale)
  → Scaler chỉ áp dụng cho 21 features đầu (index 0..20)
"""

import argparse, struct, os, sys
import numpy as np
import onnxruntime as ort

# ── NSL-KDD columns ──────────────────────────────────────────────────────────
COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

# 15 log-features (index trong raw NSL-KDD)
LOG_COLS = [
    "duration","src_bytes","dst_bytes","wrong_fragment","urgent","hot",
    "num_failed_logins","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds"
]
# 6 num-features
NUM_COLS = [
    "count","srv_count","dst_host_count","dst_host_srv_count",
    "serror_rate","rerror_rate"
]
# proto & flag
PROTOS = ["tcp","udp","icmp"]
FLAGS  = ["SF","S0","REJ","RSTO","RSTR","SH","S1","S2","S3","OTH"]

def load_scaler(path):
    with open(path,"rb") as f: data = f.read()
    n = len(data) // 8
    arr = np.array(struct.unpack(f"{n}d", data), dtype=np.float32)
    half = n // 2
    return arr[:half], arr[half:]   # center, scale

def load_freqmap(path):
    freq = {}
    with open(path,"rb") as f:
        n = struct.unpack("I", f.read(4))[0]
        for _ in range(n):
            klen = struct.unpack("I", f.read(4))[0]
            key  = f.read(klen).decode()
            val  = struct.unpack("f", f.read(4))[0]
            freq[key] = val
    return freq

def build_vector(row, freq_map):
    """Build 35-dim vector từ 1 row NSL-KDD"""
    vec = []
    # 15 log features
    for c in LOG_COLS:
        v = float(row.get(c, 0))
        vec.append(np.log1p(v))
    # 6 num features
    for c in NUM_COLS:
        vec.append(float(row.get(c, 0)))
    # 3 proto one-hot
    proto = str(row.get("protocol_type","tcp")).lower().strip()
    vec += [1.0 if proto == p else 0.0 for p in PROTOS]
    # 10 flag one-hot
    flag = str(row.get("flag","SF")).strip()
    vec += [1.0 if flag == f else 0.0 for f in FLAGS]
    # 1 freq feature
    svc = str(row.get("service","other")).lower().strip()
    vec.append(freq_map.get(svc, 0.0))
    return np.array(vec, dtype=np.float32)

def scale_vector(vec, center, scale):
    """Chỉ scale 21 features đầu (index 0..20), giữ nguyên 14 còn lại"""
    out = vec.copy()
    out[:21] = (vec[:21] - center) / scale
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model",    required=True)
    ap.add_argument("--scaler",   required=True)
    ap.add_argument("--data",     required=True)
    ap.add_argument("--freq_map", required=True)
    ap.add_argument("--max_rows", type=int, default=10000)
    args = ap.parse_args()

    # Load
    center, scale = load_scaler(args.scaler)
    print(f"[Scaler] {len(center)} features, center[:3]={center[:3]}, scale[:3]={scale[:3]}")

    freq_map = load_freqmap(args.freq_map)
    print(f"[FreqMap] {len(freq_map)} entries")

    sess = ort.InferenceSession(args.model)
    in_name  = sess.get_inputs()[0].name
    out_name = sess.get_outputs()[0].name
    print(f"[Model] input={sess.get_inputs()[0].shape}, output={sess.get_outputs()[0].shape}")

    # Load data
    import csv
    print(f"[Data] Loading {args.data} ...")
    rows, y_true = [], []
    with open(args.data) as f:
        reader = csv.reader(f)
        for i, line in enumerate(reader):
            if i >= args.max_rows: break
            if len(line) < 42: continue
            row = dict(zip(COLUMNS, line))
            label_raw = row["label"].strip().rstrip(".")
            is_attack = 0 if label_raw == "normal" else 1
            vec = build_vector(row, freq_map)
            vec_scaled = scale_vector(vec, center, scale)
            rows.append(vec_scaled)
            y_true.append(is_attack)

    X = np.array(rows, dtype=np.float32)
    y = np.array(y_true, dtype=np.int32)
    print(f"[Data] {len(X)} rows | Normal={sum(y==0)} | Attack={sum(y==1)}")
    print(f"[Data] X shape={X.shape}, X[:1,:5]={X[0,:5]}")

    # Inference
    recon = sess.run([out_name], {in_name: X})[0]
    mse   = np.mean((X - recon)**2, axis=1)

    normal_mse = mse[y == 0]
    attack_mse = mse[y == 1]
    print(f"\n[MSE] NORMAL: mean={normal_mse.mean():.6f} p50={np.percentile(normal_mse,50):.6f} p95={np.percentile(normal_mse,95):.6f} p99={np.percentile(normal_mse,99):.6f} max={normal_mse.max():.6f}")
    print(f"[MSE] ATTACK: mean={attack_mse.mean():.6f} p50={np.percentile(attack_mse,50):.6f} p5={np.percentile(attack_mse,5):.6f}  min={attack_mse.min():.6f}")

    # Tìm threshold tối ưu theo F1
    from sklearn.metrics import f1_score, roc_auc_score
    thresholds = np.percentile(mse, np.linspace(1, 99, 500))
    thresholds = np.unique(np.sort(thresholds))

    best_f1, best_t_f1 = 0, 0
    best_youden, best_t_youden = 0, 0

    results = []
    for t in thresholds:
        pred = (mse > t).astype(int)
        tp = np.sum((pred==1)&(y==1))
        fp = np.sum((pred==1)&(y==0))
        tn = np.sum((pred==0)&(y==0))
        fn = np.sum((pred==0)&(y==1))
        tpr = tp/(tp+fn+1e-9)
        fpr = fp/(fp+tn+1e-9)
        acc = (tp+tn)/len(y)
        prec = tp/(tp+fp+1e-9)
        f1  = 2*prec*tpr/(prec+tpr+1e-9)
        youden = tpr - fpr
        results.append((t, acc, f1, tpr, fpr, youden))
        if f1 > best_f1:
            best_f1, best_t_f1 = f1, t
        if youden > best_youden:
            best_youden, best_t_youden = youden, t

    # p95, p99 normal
    t_p95 = np.percentile(normal_mse, 95)
    t_p99 = np.percentile(normal_mse, 99)

    def eval_t(t):
        pred = (mse > t).astype(int)
        tp = np.sum((pred==1)&(y==1)); fp = np.sum((pred==1)&(y==0))
        tn = np.sum((pred==0)&(y==0)); fn = np.sum((pred==0)&(y==1))
        tpr = tp/(tp+fn+1e-9); fpr = fp/(fp+tn+1e-9)
        acc = (tp+tn)/len(y)
        prec = tp/(tp+fp+1e-9)
        f1  = 2*prec*tpr/(prec+tpr+1e-9)
        return acc, f1, tpr, fpr

    try:
        auc = roc_auc_score(y, mse)
        print(f"\n[ROC-AUC] {auc:.4f}")
    except: pass

    print(f"\n{'='*65}")
    print(f"  {'Method':<20} {'Threshold':>12}  {'ACC':>6}  {'F1':>6}  {'TPR':>6}  {'FPR':>6}")
    print(f"  {'-'*63}")
    for name, t in [("Best F1", best_t_f1), ("Best Youden", best_t_youden),
                    ("Normal p95", t_p95), ("Normal p99", t_p99)]:
        acc, f1, tpr, fpr = eval_t(t)
        print(f"  {name:<20} {t:>12.6f}  {acc:>6.3f}  {f1:>6.3f}  {tpr:>6.3f}  {fpr:>6.3f}")
    print(f"{'='*65}")
    print(f"\n[RECOMMEND] Dùng threshold = {best_t_f1:.6f}  (Best F1)")
    print(f"  → Cập nhật config.json: \"threshold\": {best_t_f1:.6f}")

if __name__ == "__main__":
    main()
