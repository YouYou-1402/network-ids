# scripts/train_models.py
"""
Train XGBoost + Autoencoder trên CICIDS2017, export sang ONNX
Output:
    models/xgboost.onnx
    models/autoencoder.onnx
    models/scaler.bin
"""
import numpy as np
import pandas as pd
import struct
import xgboost as xgb
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import torch
import torch.nn as nn
import torch.onnx

# ─── Config ──────────────────────────────────────────────────────────────────
FEATURE_COLS = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'SYN Flag Count', 'ACK Flag Count', 'RST Flag Count', 'FIN Flag Count',
    'syn_no_ack_ratio',
    'Flow Packets/s', 'Flow Bytes/s', 'Total Packets',
    'Flow Duration',  # conn_duration = alias
    'Flow Bytes/s',   # bytes_per_second = alias
    'Flow IAT Mean', 'Flow IAT Std',
    'header_complete', 'concurrent_conn',
    'unique_dst_ports', 'rst_ratio'
]

LABEL_MAP = {
    'BENIGN':    0,
    'DDoS':      1,
    'SlowDDoS':  2,
    'PortScan':  3,
}

# ─── Load & preprocess ───────────────────────────────────────────────────────
def load_cicids2017(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    return df

# ─── Save scaler.bin ─────────────────────────────────────────────────────────
def save_scaler_bin(scaler: StandardScaler, path: str):
    """Format: [float32 mean×21][float32 std×21] = 168 bytes"""
    mean = scaler.mean_.astype(np.float32)
    std  = scaler.scale_.astype(np.float32)
    with open(path, 'wb') as f:
        f.write(struct.pack(f'{len(mean)}f', *mean))
        f.write(struct.pack(f'{len(std)}f',  *std))
    print(f"Scaler saved: {path} ({len(mean)*2*4} bytes)")

# ─── Train XGBoost ───────────────────────────────────────────────────────────
def train_xgboost(X_train, y_train, X_val, y_val):
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric='mlogloss',
        tree_method='hist',
        num_class=4,
        objective='multi:softprob',
        random_state=42,
    )
    model.fit(X_train, y_train,
              eval_set=[(X_val, y_val)],
              early_stopping_rounds=20,
              verbose=50)

    y_pred = model.predict(X_val)
    print(classification_report(y_val, y_pred,
          target_names=['Normal','DDoS','SlowDDoS','PortScan']))
    return model

def export_xgboost_onnx(model, output_path: str, n_features: int = 21):
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    initial_type = [('X', FloatTensorType([None, n_features]))]
    onnx_model = convert_sklearn(model, initial_types=initial_type,
                                  target_opset=12)
    with open(output_path, 'wb') as f:
        f.write(onnx_model.SerializeToString())
    print(f"XGBoost ONNX saved: {output_path}")

# ─── Autoencoder ─────────────────────────────────────────────────────────────
class Autoencoder(nn.Module):
    def __init__(self, input_dim: int = 21):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

def train_autoencoder(X_normal_train, X_normal_val,
                      epochs=100, batch_size=512):
    model = Autoencoder(input_dim=21)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()

    X_t = torch.tensor(X_normal_train, dtype=torch.float32)
    X_v = torch.tensor(X_normal_val,   dtype=torch.float32)

    for epoch in range(epochs):
        model.train()
        perm = torch.randperm(len(X_t))
        total_loss = 0.0
        for i in range(0, len(X_t), batch_size):
            batch = X_t[perm[i:i+batch_size]]
            optimizer.zero_grad()
            recon = model(batch)
            loss  = criterion(recon, batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if (epoch + 1) % 20 == 0:
            model.eval()
            with torch.no_grad():
                val_loss = criterion(model(X_v), X_v).item()
# scripts/train_models.py (tiếp theo)

            print(f"Epoch {epoch+1}/{epochs} "
                  f"train_loss={total_loss:.4f} val_loss={val_loss:.6f}")
    return model

def find_ae_threshold(model, X_normal_val, percentile=95):
    """
    Tìm MSE threshold tại percentile_95 của normal traffic
    → ~5% false positive rate trên normal traffic
    """
    model.eval()
    X_v = torch.tensor(X_normal_val, dtype=torch.float32)
    with torch.no_grad():
        recon = model(X_v).numpy()
    mse_per_sample = np.mean((X_normal_val - recon) ** 2, axis=1)
    threshold = float(np.percentile(mse_per_sample, percentile))
    print(f"AE threshold (p{percentile}): {threshold:.6f}")
    print(f"  MSE mean={mse_per_sample.mean():.6f}"
          f"  std={mse_per_sample.std():.6f}"
          f"  max={mse_per_sample.max():.6f}")
    return threshold

def export_autoencoder_onnx(model, output_path: str, input_dim: int = 21):
    model.eval()
    dummy = torch.randn(1, input_dim)
    torch.onnx.export(
        model, dummy, output_path,
        input_names  = ["input"],
        output_names = ["output"],
        dynamic_axes = {"input":  {0: "batch_size"},
                        "output": {0: "batch_size"}},
        opset_version = 12,
    )
    print(f"Autoencoder ONNX saved: {output_path}")

# ─── Validate ONNX models ────────────────────────────────────────────────────
def validate_onnx(model_path: str, X_sample: np.ndarray):
    import onnxruntime as ort
    sess = ort.InferenceSession(model_path)
    inp  = X_sample[:5].astype(np.float32)
    out  = sess.run(None, {sess.get_inputs()[0].name: inp})
    print(f"ONNX validate [{model_path}]: output shapes = {[o.shape for o in out]}")
    return out

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    import os, argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv",    required=True,
                        help="Path to CICIDS2017 CSV")
    parser.add_argument("--outdir", default="models",
                        help="Output directory")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    # ── Load data ────────────────────────────────────────────────────────────
    print("Loading data...")
    df = load_cicids2017(args.csv)
    print(f"  Total rows: {len(df)}")
    print(f"  Label dist:\n{df['Label'].value_counts()}")

    # ── Map labels ───────────────────────────────────────────────────────────
    # CICIDS2017 label → int
    # Các variant của DDoS đều map về 1
    def map_label(label: str) -> int:
        label = label.strip().upper()
        if label == 'BENIGN':                    return 0
        if 'SLOWLORIS' in label or \
           'SLOWHTTPTEST' in label or \
           'SLOW' in label:                      return 2
        if 'PORTSCAN' in label or \
           'PORT SCAN' in label:                 return 3
        if 'DDOS' in label or 'DOS' in label:    return 1
        return 0   # unknown → treat as normal

    df['label_int'] = df['Label'].apply(map_label)

    # ── Feature selection ────────────────────────────────────────────────────
    # Dùng tên cột thực tế của CICIDS2017
    ACTUAL_COLS = [
        ' Flow Duration',
        ' Total Fwd Packets',
        ' Total Backward Packets',
        ' Total Length of Fwd Packets',
        ' Total Length of Bwd Packets',
        ' SYN Flag Count',
        ' ACK Flag Count',
        ' RST Flag Count',
        ' FIN Flag Count',
        'syn_no_ack_ratio',        # computed below
        ' Flow Packets/s',
        ' Flow Bytes/s',
        ' Total Fwd Packets',      # pkt_per_flow ≈ total fwd
        ' Flow Duration',          # conn_duration = alias
        ' Flow Bytes/s',           # bytes_per_second = alias
        ' Flow IAT Mean',
        ' Flow IAT Std',
        'header_complete',         # computed below (0 for CICIDS2017)
        'concurrent_conn',         # computed below (0 for CICIDS2017)
        'unique_dst_ports',        # computed below
        'rst_ratio',               # computed below
    ]

    # Computed features không có trong CICIDS2017 → tính thủ công
    eps = 1e-9
    df['syn_no_ack_ratio'] = (
        df[' SYN Flag Count'] /
        (df[' SYN Flag Count'] + eps)
    ).clip(0, 1)

    df['rst_ratio'] = (
        df[' RST Flag Count'] /
        (df[' Total Fwd Packets'] + df[' Total Backward Packets'] + eps)
    ).clip(0, 1)

    df['header_complete']  = 0.0   # không có trong CICIDS2017
    df['concurrent_conn']  = 0.0   # không có trong CICIDS2017
    df['unique_dst_ports'] = 0.0   # không có trong CICIDS2017

    # Build feature matrix
    X = df[ACTUAL_COLS].values.astype(np.float32)
    y = df['label_int'].values

    print(f"  Feature matrix: {X.shape}")
    print(f"  Label counts: {np.bincount(y)}")

    # ── Train/val split ──────────────────────────────────────────────────────
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    # ── StandardScaler ───────────────────────────────────────────────────────
    print("\nFitting StandardScaler...")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s   = scaler.transform(X_val)

    scaler_path = os.path.join(args.outdir, "scaler.bin")
    save_scaler_bin(scaler, scaler_path)

    # ── Train XGBoost ────────────────────────────────────────────────────────
    print("\n=== Training XGBoost ===")
    xgb_model = train_xgboost(X_train_s, y_train, X_val_s, y_val)

    xgb_path = os.path.join(args.outdir, "xgboost.onnx")
    export_xgboost_onnx(xgb_model, xgb_path)
    validate_onnx(xgb_path, X_val_s)

    # ── Train Autoencoder (chỉ dùng normal traffic) ──────────────────────────
    print("\n=== Training Autoencoder ===")
    X_normal_train = X_train_s[y_train == 0]
    X_normal_val   = X_val_s  [y_val   == 0]
    print(f"  Normal train: {len(X_normal_train)}"
          f"  val: {len(X_normal_val)}")

    ae_model = train_autoencoder(X_normal_train, X_normal_val,
                                  epochs=100, batch_size=512)

    ae_threshold = find_ae_threshold(ae_model, X_normal_val, percentile=95)

    ae_path = os.path.join(args.outdir, "autoencoder.onnx")
    export_autoencoder_onnx(ae_model, ae_path)
    validate_onnx(ae_path, X_val_s)

    # ── Evaluate AE trên attack traffic ──────────────────────────────────────
    print("\n=== Autoencoder attack detection ===")
    ae_model.eval()
    X_attack_val = X_val_s[y_val != 0]
    y_attack_val = y_val  [y_val != 0]

    X_at = torch.tensor(X_attack_val, dtype=torch.float32)
    with torch.no_grad():
        recon_attack = ae_model(X_at).numpy()
    mse_attack = np.mean((X_attack_val - recon_attack) ** 2, axis=1)

    detected = (mse_attack > ae_threshold).sum()
    print(f"  Attack samples: {len(mse_attack)}")
    print(f"  Detected (MSE > {ae_threshold:.6f}): "
          f"{detected} ({100*detected/len(mse_attack):.1f}%)")

    # ── Save thresholds config ────────────────────────────────────────────────
    cfg_path = os.path.join(args.outdir, "thresholds.txt")
    with open(cfg_path, 'w') as f:
        f.write(f"xgb_threshold=0.5\n")
        f.write(f"ae_threshold={ae_threshold:.6f}\n")
        f.write(f"min_confidence=0.60\n")
        f.write(f"auto_approve_threshold=0.85\n")
        f.write(f"xgb_weight=0.65\n")
        f.write(f"ae_weight=0.35\n")
    print(f"\nThresholds saved: {cfg_path}")
    print("\n=== Done ===")
    print(f"  {args.outdir}/xgboost.onnx")
    print(f"  {args.outdir}/autoencoder.onnx")
    print(f"  {args.outdir}/scaler.bin")
    print(f"  {args.outdir}/thresholds.txt")

if __name__ == "__main__":
    main()
