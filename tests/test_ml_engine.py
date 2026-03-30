import onnxruntime as ort
import onnx
import numpy as np

# ── Đổi đường dẫn cho đúng ──
XGB_PATH = "/media/linhlinh/learn/nckh/network-ids/models/xgboost_ids_model.onnx"
N_FEAT   = 21   # FeatureVector::SIZE của bạn

# ─────────────────────────────────────────────
# 1. In metadata của model (không cần chạy)
# ─────────────────────────────────────────────
def inspect_model(path, name):
    print(f"\n{'='*50}")
    print(f"  {name}: {path}")
    print(f"{'='*50}")
    model = onnx.load(path)

    print("\n[INPUTS]")
    for inp in model.graph.input:
        shape = [d.dim_value for d in inp.type.tensor_type.shape.dim]
        dtype = inp.type.tensor_type.elem_type
        print(f"  name={inp.name!r}  shape={shape}  dtype={dtype}")

    print("\n[OUTPUTS]")
    for out in model.graph.output:
        t = out.type
        if t.HasField("tensor_type"):
            shape = [d.dim_value for d in t.tensor_type.shape.dim]
            dtype = t.tensor_type.elem_type
            print(f"  name={out.name!r}  shape={shape}  dtype={dtype}  kind=tensor")
        elif t.HasField("sequence_type"):
            print(f"  name={out.name!r}  kind=SEQUENCE (map/list)")
        elif t.HasField("map_type"):
            print(f"  name={out.name!r}  kind=MAP")
        else:
            print(f"  name={out.name!r}  kind=unknown")

inspect_model(XGB_PATH, "XGBoost")


# ─────────────────────────────────────────────
# 2. Chạy thử inference với input giả
# ─────────────────────────────────────────────
def test_infer(path, name):
    print(f"\n{'='*50}")
    print(f"  Inference test: {name}")
    print(f"{'='*50}")
    sess = ort.InferenceSession(path)

    # In tên input/output
    in_name  = sess.get_inputs()[0].name
    out_names = [o.name for o in sess.get_outputs()]
    print(f"  input_name  = {in_name!r}")
    print(f"  output_names= {out_names}")

    # Tạo input giả — tất cả = 0.5
    dummy = np.full((1, N_FEAT), 0.5, dtype=np.float32)
    results = sess.run(None, {in_name: dummy})

    for i, (oname, res) in enumerate(zip(out_names, results)):
        print(f"\n  output[{i}] name={oname!r}")
        print(f"    type  = {type(res)}")
        if isinstance(res, np.ndarray):
            print(f"    shape = {res.shape}")
            print(f"    dtype = {res.dtype}")
            print(f"    value = {res}")
        elif isinstance(res, list):
            print(f"    len   = {len(res)}")
            print(f"    [0]   = {res[0]}")
        else:
            print(f"    value = {res}")

test_infer(XGB_PATH, "XGBoost")
