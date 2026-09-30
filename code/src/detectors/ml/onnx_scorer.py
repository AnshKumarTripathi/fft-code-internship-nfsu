"""ONNX Runtime scorer for frozen ML models (Phase 53 / SDD §7.6).

Expects ``onnx_model_path`` plus a sibling ``*.vocab.json`` sidecar written by
``scripts/export_ml_onnx.py`` (or an equivalent export).

Sidecar schema (minimum)::

    {
      "score_kind": "ae_mse" | "raw_score",
      "top_templates": [...],
      "top_bigrams": [[a, b], ...],
      "scaler_mean": [...],
      "scaler_scale": [...],
      "input_name": "X",          # optional
      "output_index": 0          # optional
    }

``ae_mse``: ONNX outputs reconstructed scaled features; scorer computes MSE.
``raw_score``: ONNX outputs a 1-D anomaly score (higher = more anomalous).
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from src.detectors.ml.attribution import (
    attribution_from_residuals,
    attribution_median_deviation,
    feature_names,
)
from src.detectors.ml.isolation_forest import (
    DEFAULT_FLAGGING,
    DEFAULT_MAD_K,
    FeatureVocab,
    MlWindowScore,
    TemplateWindow,
    apply_ml_flagging,
    vectorize_window,
)
from src.detectors.robust_z import robust_z_scores


class ModelNotConfiguredError(Exception):
    """Raised when ``ml.model_type=onnx`` but no usable model path is set."""


def sidecar_path_for(onnx_model_path: Path) -> Path:
    """Default vocab sidecar: ``model.onnx`` → ``model.vocab.json``."""
    return onnx_model_path.with_suffix("").with_name(
        onnx_model_path.stem + ".vocab.json"
    )


def load_onnx_sidecar(onnx_model_path: Path) -> dict[str, Any]:
    path = sidecar_path_for(onnx_model_path)
    if not path.is_file():
        raise ModelNotConfiguredError(
            f"ONNX vocab sidecar not found next to model: {path}. "
            "Export with scripts/export_ml_onnx.py or provide "
            f"{onnx_model_path.stem}.vocab.json."
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelNotConfiguredError(
            f"Failed to read ONNX vocab sidecar {path}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ModelNotConfiguredError(f"ONNX vocab sidecar must be a JSON object: {path}")
    return payload


def vocab_from_sidecar(sidecar: dict[str, Any]) -> FeatureVocab:
    templates = sidecar.get("top_templates") or []
    bigrams = sidecar.get("top_bigrams") or []
    if not isinstance(templates, list) or not isinstance(bigrams, list):
        raise ModelNotConfiguredError(
            "ONNX sidecar top_templates and top_bigrams must be lists"
        )
    parsed_bigrams: list[tuple[str, str]] = []
    for item in bigrams:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            parsed_bigrams.append((str(item[0]), str(item[1])))
        else:
            raise ModelNotConfiguredError(
                f"ONNX sidecar bigram must be a [left, right] pair, got {item!r}"
            )
    return FeatureVocab(
        top_templates=tuple(str(t) for t in templates),
        top_bigrams=tuple(parsed_bigrams),
    )


def _scale_matrix(
    matrix: np.ndarray, sidecar: dict[str, Any]
) -> np.ndarray:
    mean = sidecar.get("scaler_mean")
    scale = sidecar.get("scaler_scale")
    if mean is None or scale is None:
        return matrix
    mean_arr = np.asarray(mean, dtype=np.float64)
    scale_arr = np.asarray(scale, dtype=np.float64)
    if mean_arr.shape[0] != matrix.shape[1] or scale_arr.shape[0] != matrix.shape[1]:
        raise ModelNotConfiguredError(
            "ONNX sidecar scaler_mean/scale length does not match feature dim "
            f"({matrix.shape[1]})"
        )
    safe_scale = np.where(np.abs(scale_arr) < 1e-12, 1.0, scale_arr)
    return (matrix - mean_arr) / safe_scale


def score_windows_onnx(
    windows: Sequence[TemplateWindow],
    *,
    onnx_model_path: str | Path | None,
    flagging: str = DEFAULT_FLAGGING,
    score_threshold: float | None = None,
    mad_k: float = DEFAULT_MAD_K,
    model_snapshot_id: str | None = None,
    top_k_features: int = 5,
    **_: Any,
) -> list[MlWindowScore]:
    """Score windows with an ONNX model + vocab sidecar."""
    if onnx_model_path is None or str(onnx_model_path).strip() in ("", "null", "None"):
        raise ModelNotConfiguredError(
            "ml.model_type is 'onnx' but ml.onnx_model_path is not set. "
            "Set onnx_model_path to a trained model file, or use "
            "ml.model_type: isolation_forest."
        )

    path = Path(onnx_model_path)
    if not path.is_file():
        raise ModelNotConfiguredError(
            f"ml.onnx_model_path does not exist or is not a file: {path}. "
            "Provide a valid ONNX model, or use ml.model_type: isolation_forest."
        )

    try:
        import onnxruntime as ort
    except ImportError as exc:
        raise ModelNotConfiguredError(
            "onnxruntime is required for ml.model_type: onnx. "
            "Install with: pip install onnxruntime"
        ) from exc

    sidecar = load_onnx_sidecar(path)
    vocab = vocab_from_sidecar(sidecar)
    score_kind = str(sidecar.get("score_kind") or "ae_mse").strip().lower()
    if score_kind not in {"ae_mse", "raw_score"}:
        raise ModelNotConfiguredError(
            f"ONNX sidecar score_kind must be 'ae_mse' or 'raw_score', got {score_kind!r}"
        )

    if not windows:
        return []

    matrix = np.vstack(
        [vectorize_window(window.template_ids, vocab) for window in windows]
    ).astype(np.float32)
    expected_names = feature_names(vocab)
    if matrix.shape[1] != len(expected_names):
        raise ModelNotConfiguredError(
            f"Feature dim mismatch: matrix={matrix.shape[1]} "
            f"vocab_names={len(expected_names)}"
        )
    scaled = _scale_matrix(matrix.astype(np.float64), sidecar).astype(np.float32)

    try:
        session = ort.InferenceSession(
            str(path), providers=["CPUExecutionProvider"]
        )
    except Exception as exc:
        raise ModelNotConfiguredError(
            f"Failed to load ONNX model {path}: {exc}"
        ) from exc

    input_name = sidecar.get("input_name")
    if not input_name:
        inputs = session.get_inputs()
        if not inputs:
            raise ModelNotConfiguredError(f"ONNX model has no inputs: {path}")
        input_name = inputs[0].name
    output_index = int(sidecar.get("output_index") or 0)

    try:
        outputs = session.run(None, {str(input_name): scaled})
    except Exception as exc:
        raise ModelNotConfiguredError(
            f"ONNX inference failed for {path}: {exc}"
        ) from exc

    if output_index < 0 or output_index >= len(outputs):
        raise ModelNotConfiguredError(
            f"ONNX output_index {output_index} out of range for {path}"
        )
    raw_out = np.asarray(outputs[output_index], dtype=np.float64)

    residuals: np.ndarray | None = None
    if score_kind == "ae_mse":
        if raw_out.ndim != 2 or raw_out.shape != scaled.shape:
            raise ModelNotConfiguredError(
                f"ae_mse ONNX output shape {raw_out.shape} must match "
                f"scaled input {scaled.shape}"
            )
        residuals = scaled.astype(np.float64) - raw_out
        raw_scores = [float(np.mean(row ** 2)) for row in residuals]
    else:
        flat = raw_out.reshape(len(windows), -1)
        if flat.shape[1] != 1:
            raise ModelNotConfiguredError(
                f"raw_score ONNX output must be (N,) or (N,1), got {raw_out.shape}"
            )
        raw_scores = [float(v) for v in flat[:, 0]]
        if bool(sidecar.get("negate_output")):
            raw_scores = [-float(v) for v in raw_scores]

    effective_flagging = "mad_threshold" if flagging == "predict" else flagging
    flagged_flags = apply_ml_flagging(
        list(raw_scores),
        flagging=effective_flagging,
        score_threshold=score_threshold,
        mad_k=mad_k,
    )
    mad_z_scores = robust_z_scores([float(score) for score in raw_scores])
    batch_median = np.median(scaled.astype(np.float64), axis=0)
    snapshot = model_snapshot_id or path.stem

    rows: list[MlWindowScore] = []
    for index, (window, score, flagged, mad_z) in enumerate(
        zip(windows, raw_scores, flagged_flags, mad_z_scores, strict=True)
    ):
        attribution = None
        if flagged:
            if residuals is not None:
                attribution = attribution_from_residuals(
                    residuals[index], vocab, top_k=top_k_features
                )
            else:
                attribution = attribution_median_deviation(
                    scaled[index].astype(np.float64),
                    batch_median,
                    vocab,
                    top_k=top_k_features,
                )
        rows.append(
            MlWindowScore(
                entity_id=window.entity_id,
                window_start=window.window_start,
                window_end=window.window_end,
                model_score=float(score),
                flagged=flagged,
                model_snapshot_id=snapshot,
                mad_z=float(mad_z) if math.isfinite(mad_z) else None,
                attribution=attribution,
            )
        )
    return rows
