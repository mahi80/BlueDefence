"""ONNX end-to-end roundtrip test.

Closes the RL training -> inference loop without needing cgo:

  1. Train sklearn baseline on the synthetic env distribution.
  2. Export to ONNX via skl2onnx.
  3. Load ONNX via onnxruntime.
  4. Generate held-out observations.
  5. Compare sklearn predictions vs ONNX inference action-for-action.
  6. Assert >99% match (numerical jitter is OK; structural mismatch is not).
  7. Report per-action timing.

Run:
  pip install scikit-learn skl2onnx onnxruntime numpy
  python -m aegis.rl.test_onnx_roundtrip

If the test passes, the export pipeline (skl2onnx -> onnxruntime) is
verified end-to-end. The Tier-0 Go filter swap (linear-features JSON
-> ONNX via onnxruntime_go) is then a separate engineering concern,
not a model-correctness concern.
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .baseline import _generate_dataset


def main() -> int:
    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from skl2onnx import to_onnx
        import onnxruntime as ort
    except ImportError as exc:  # noqa: BLE001
        print(f"missing deps: {exc}")
        print("Install: pip install scikit-learn skl2onnx onnxruntime numpy")
        return 2

    print("[onnx-test] generating training data...")
    Xt, yt = _generate_dataset(8000, seed=42)
    Xt_arr = np.array(Xt, dtype=np.float32)
    yt_arr = np.array(yt, dtype=np.int64)

    print("[onnx-test] fitting sklearn LogisticRegression...")
    clf = LogisticRegression(max_iter=500)
    clf.fit(Xt, yt)

    print("[onnx-test] exporting to ONNX via skl2onnx...")
    onnx_model = to_onnx(clf, Xt_arr[:1], target_opset=15)
    with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as tmp:
        tmp.write(onnx_model.SerializeToString())
        onnx_path = Path(tmp.name)
    print(f"[onnx-test] wrote {onnx_path} ({onnx_path.stat().st_size} bytes)")

    print("[onnx-test] loading via onnxruntime + warming up...")
    sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name
    output_name = sess.get_outputs()[0].name
    # Warm up
    sess.run([output_name], {input_name: Xt_arr[:1]})

    print("[onnx-test] generating held-out test set + comparing...")
    Xv, yv = _generate_dataset(2000, seed=43)
    Xv_arr = np.array(Xv, dtype=np.float32)

    sklearn_start = time.perf_counter()
    sk_preds = clf.predict(Xv)
    sklearn_ms = (time.perf_counter() - sklearn_start) * 1000.0

    onnx_start = time.perf_counter()
    onnx_preds = sess.run([output_name], {input_name: Xv_arr})[0]
    onnx_ms = (time.perf_counter() - onnx_start) * 1000.0

    matches = int(np.sum(np.asarray(sk_preds) == np.asarray(onnx_preds)))
    n = len(sk_preds)
    match_rate = matches / n

    print("[onnx-test] results:")
    print(f"  test set size:           {n}")
    print(f"  sklearn predictions:     {sklearn_ms:.2f} ms ({sklearn_ms/n*1000:.2f} us/sample)")
    print(f"  onnxruntime inference:   {onnx_ms:.2f} ms ({onnx_ms/n*1000:.2f} us/sample)")
    print(f"  agreement:               {matches}/{n} = {match_rate:.4%}")

    # Action distribution
    sk_dist = {int(a): int(np.sum(sk_preds == a)) for a in (0, 1, 2)}
    onnx_dist = {int(a): int(np.sum(onnx_preds == a)) for a in (0, 1, 2)}
    print(f"  sklearn action dist:     allow={sk_dist[0]} escalate={sk_dist[1]} block={sk_dist[2]}")
    print(f"  onnxruntime action dist: allow={onnx_dist[0]} escalate={onnx_dist[1]} block={onnx_dist[2]}")

    onnx_path.unlink(missing_ok=True)

    if match_rate < 0.99:
        print(f"\n[onnx-test] FAIL: match rate {match_rate:.2%} below 99% threshold")
        return 1
    print(f"\n[onnx-test] PASS — RL export pipeline verified end-to-end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
