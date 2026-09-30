"""Export an IsolationForest or autoencoder ML snapshot to ONNX + vocab sidecar.

Optional dependency: ``skl2onnx`` (and ``onnx``). Not required for the default
IsolationForest pipeline path.

Examples::

    python scripts/export_ml_onnx.py \\
        --baseline-dir data/baselines \\
        --snapshot-id <sha256> \\
        --model-type autoencoder \\
        --output data/models/ae.onnx

    # Then in pipeline.yaml:
    #   ml:
    #     model_type: onnx
    #     onnx_model_path: data/models/ae.onnx
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

CODE_ROOT = Path(__file__).resolve().parents[1]
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from src.detectors.ml.attribution import feature_names  # noqa: E402
from src.detectors.ml.autoencoder import (  # noqa: E402
    AutoencoderBundle,
    scaler_params,
    vocab_to_dict,
)
from src.detectors.ml.isolation_forest import IsolationBundle  # noqa: E402
from src.detectors.ml.onnx_scorer import sidecar_path_for  # noqa: E402
from src.detectors.ml.snapshots import (  # noqa: E402
    load_autoencoder_snapshot,
    load_ml_snapshot,
)


def _export_mlp_identity_onnx(
    n_features: int,
    output_path: Path,
    *,
    weights: list[np.ndarray],
    biases: list[np.ndarray],
) -> str:
    """Export a fitted MLPRegressor (identity output activation) via skl2onnx."""
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
        from sklearn.neural_network import MLPRegressor
    except ImportError as exc:
        raise SystemExit(
            "Export requires skl2onnx and onnx. Install with:\n"
            "  pip install skl2onnx onnx"
        ) from exc

    # Rebuild a throwaway MLP with fitted coefs so convert_sklearn works.
    hidden = tuple(int(w.shape[0]) for w in weights[:-1])
    model = MLPRegressor(hidden_layer_sizes=hidden if hidden else (1,))
    # Minimal fit to allocate structures, then overwrite.
    dummy = np.zeros((max(2, n_features), n_features), dtype=np.float64)
    model.fit(dummy, dummy)
    model.coefs_ = list(weights)
    model.intercepts_ = list(biases)
    model.n_outputs_ = n_features
    model.out_activation_ = "identity"

    initial_type = [("X", FloatTensorType([None, n_features]))]
    onnx_model = convert_sklearn(model, initial_types=initial_type, target_opset=12)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(onnx_model.SerializeToString())
    return "X"


def export_autoencoder(
    bundle: AutoencoderBundle, output_path: Path
) -> Path:
    n_features = len(feature_names(bundle.vocab))
    input_name = _export_mlp_identity_onnx(
        n_features,
        output_path,
        weights=[np.asarray(c, dtype=np.float64) for c in bundle.model.coefs_],
        biases=[np.asarray(b, dtype=np.float64) for b in bundle.model.intercepts_],
    )
    sidecar = {
        "score_kind": "ae_mse",
        "input_name": input_name,
        "output_index": 0,
        **vocab_to_dict(bundle.vocab),
        **scaler_params(bundle),
        "hidden_dims": list(bundle.hidden_dims),
        "model_type": "autoencoder",
    }
    side = sidecar_path_for(output_path)
    side.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
    return side


def export_isolation_forest(
    bundle: IsolationBundle, output_path: Path
) -> Path:
    """Export IF decision scores via skl2onnx (raw_score = -decision_function)."""
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
    except ImportError as exc:
        raise SystemExit(
            "Export requires skl2onnx and onnx. Install with:\n"
            "  pip install skl2onnx onnx"
        ) from exc

    n_features = len(feature_names(bundle.vocab))
    # Pipeline: scaler already applied in sidecar; export model-only on scaled X.
    # We still embed a no-op identity by exporting the forest alone and scaling
    # in the Python scorer via sidecar mean/scale.
    initial_type = [("X", FloatTensorType([None, n_features]))]
    onnx_model = convert_sklearn(
        bundle.model, initial_types=initial_type, target_opset=12
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(onnx_model.SerializeToString())

    mean = getattr(bundle.scaler, "mean_", None)
    scale = getattr(bundle.scaler, "scale_", None)
    if mean is None or scale is None:
        raise SystemExit("IsolationBundle scaler is not fitted")

    # skl2onnx IsolationForest typically emits scores; document as raw_score and
    # negate in a thin wrapper by storing score_kind with a note. Prefer AE export
    # for reconstruction attribution. For IF we store score_kind=raw_score and
    # expect the ONNX graph to emit decision_function; we negate below via a
    # custom note in sidecar that the Python scorer should negate.
    sidecar = {
        "score_kind": "raw_score",
        "negate_output": True,
        "input_name": "X",
        "output_index": 0,
        "top_templates": list(bundle.vocab.top_templates),
        "top_bigrams": [list(pair) for pair in bundle.vocab.top_bigrams],
        "feature_names": feature_names(bundle.vocab),
        "scaler_mean": [float(x) for x in mean],
        "scaler_scale": [float(x) for x in scale],
        "model_type": "isolation_forest",
    }
    side = sidecar_path_for(output_path)
    side.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
    return side


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-dir", required=True)
    parser.add_argument("--snapshot-id", required=True)
    parser.add_argument(
        "--model-type",
        choices=("autoencoder", "isolation_forest"),
        default="autoencoder",
    )
    parser.add_argument("--output", required=True, help="Destination .onnx path")
    args = parser.parse_args(argv)

    output = Path(args.output)
    if args.model_type == "autoencoder":
        bundle = load_autoencoder_snapshot(args.baseline_dir, args.snapshot_id)
        side = export_autoencoder(bundle, output)
    else:
        bundle = load_ml_snapshot(args.baseline_dir, args.snapshot_id)
        side = export_isolation_forest(bundle, output)

    print(f"Wrote ONNX model: {output}")
    print(f"Wrote vocab sidecar: {side}")
    print("Set ml.model_type: onnx and ml.onnx_model_path to the .onnx file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
