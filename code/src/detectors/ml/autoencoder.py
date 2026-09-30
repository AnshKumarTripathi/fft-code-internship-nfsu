"""Sequence-window autoencoder on IsolationForest feature vectors (Phase 53).

Trains a sklearn ``MLPRegressor`` to reconstruct scaled template/bigram
features. ``model_score`` is mean squared reconstruction error (higher =
more anomalous). Flagging reuses IsolationForest MAD / threshold helpers.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from src.detectors.ml.attribution import attribution_from_residuals, feature_names
from src.detectors.ml.isolation_forest import (
    DEFAULT_FLAGGING,
    DEFAULT_MAD_K,
    RANDOM_STATE,
    FeatureVocab,
    MlWindowScore,
    TemplateWindow,
    apply_ml_flagging,
    build_vocab,
    vectorize_window,
)
from src.detectors.robust_z import robust_z_scores

DEFAULT_AE_HIDDEN_DIMS: tuple[int, ...] = (32, 8, 32)
DEFAULT_AE_MAX_ITER = 200


@dataclass
class AutoencoderBundle:
    """Fitted MLP autoencoder + the vocab/scaler it was trained with."""

    model: MLPRegressor
    scaler: StandardScaler
    vocab: FeatureVocab
    hidden_dims: tuple[int, ...]
    max_iter: int
    random_state: int


def _parse_hidden_dims(hidden_dims: Sequence[int] | None) -> tuple[int, ...]:
    if hidden_dims is None:
        return DEFAULT_AE_HIDDEN_DIMS
    dims = tuple(int(d) for d in hidden_dims)
    if not dims or any(d < 1 for d in dims):
        raise ValueError(
            f"ae_hidden_dims must be a non-empty sequence of positive ints, "
            f"got {hidden_dims!r}"
        )
    return dims


def fit_autoencoder_bundle(
    windows: Sequence[TemplateWindow],
    *,
    hidden_dims: Sequence[int] | None = None,
    max_iter: int = DEFAULT_AE_MAX_ITER,
    random_state: int = RANDOM_STATE,
) -> tuple[AutoencoderBundle, list[float], np.ndarray] | None:
    """Fit scaler + MLP autoencoder. None when the corpus is too small."""
    if not windows:
        return None
    dims = _parse_hidden_dims(hidden_dims)
    if max_iter < 1:
        raise ValueError(f"ae_max_iter must be >= 1, got {max_iter!r}")

    sequences = [w.template_ids for w in windows]
    vocab = build_vocab(sequences)
    matrix = np.vstack([vectorize_window(seq, vocab) for seq in sequences])
    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)
    n_samples = scaled.shape[0]
    if n_samples < 2:
        return None

    model = MLPRegressor(
        hidden_layer_sizes=dims,
        activation="relu",
        solver="adam",
        max_iter=int(max_iter),
        random_state=random_state,
        warm_start=False,
    )
    model.fit(scaled, scaled)
    reconstructed = model.predict(scaled)
    residuals = scaled - reconstructed
    raw_scores = [float(np.mean(row ** 2)) for row in residuals]
    bundle = AutoencoderBundle(
        model=model,
        scaler=scaler,
        vocab=vocab,
        hidden_dims=dims,
        max_iter=int(max_iter),
        random_state=random_state,
    )
    return bundle, raw_scores, residuals


def score_windows_with_autoencoder(
    windows: Sequence[TemplateWindow],
    bundle: AutoencoderBundle,
    *,
    flagging: str = DEFAULT_FLAGGING,
    score_threshold: float | None = None,
    mad_k: float = DEFAULT_MAD_K,
    model_snapshot_id: str | None = None,
    raw_scores: Sequence[float] | None = None,
    residuals: np.ndarray | None = None,
    top_k_features: int = 5,
) -> list[MlWindowScore]:
    """Score windows with a frozen AutoencoderBundle (reuse_snapshot)."""
    if not windows:
        return []

    if raw_scores is None or residuals is None:
        matrix = np.vstack(
            [vectorize_window(window.template_ids, bundle.vocab) for window in windows]
        )
        scaled = bundle.scaler.transform(matrix)
        reconstructed = bundle.model.predict(scaled)
        residuals = scaled - reconstructed
        raw_scores = [float(np.mean(row ** 2)) for row in residuals]

    effective_flagging = "mad_threshold" if flagging == "predict" else flagging
    flagged_flags = apply_ml_flagging(
        list(raw_scores),
        flagging=effective_flagging,
        score_threshold=score_threshold,
        mad_k=mad_k,
    )

    mad_z_scores = robust_z_scores([float(score) for score in raw_scores])
    rows: list[MlWindowScore] = []
    for index, (window, score, flagged, mad_z) in enumerate(
        zip(windows, raw_scores, flagged_flags, mad_z_scores, strict=True)
    ):
        attribution = None
        if flagged and residuals is not None:
            attribution = attribution_from_residuals(
                residuals[index],
                bundle.vocab,
                top_k=top_k_features,
            )
        rows.append(
            MlWindowScore(
                entity_id=window.entity_id,
                window_start=window.window_start,
                window_end=window.window_end,
                model_score=float(score),
                flagged=flagged,
                model_snapshot_id=model_snapshot_id,
                mad_z=float(mad_z) if math.isfinite(mad_z) else None,
                attribution=attribution,
            )
        )
    return rows


def fit_score_autoencoder_windows(
    windows: Sequence[TemplateWindow],
    *,
    hidden_dims: Sequence[int] | None = None,
    max_iter: int = DEFAULT_AE_MAX_ITER,
    flagging: str = DEFAULT_FLAGGING,
    score_threshold: float | None = None,
    mad_k: float = DEFAULT_MAD_K,
    random_state: int = RANDOM_STATE,
    model_snapshot_id: str | None = None,
    top_k_features: int = 5,
) -> list[MlWindowScore]:
    """Fit a global autoencoder and score every window."""
    if not windows:
        return []
    fitted = fit_autoencoder_bundle(
        windows,
        hidden_dims=hidden_dims,
        max_iter=max_iter,
        random_state=random_state,
    )
    if fitted is None:
        return [
            MlWindowScore(
                entity_id=windows[0].entity_id,
                window_start=windows[0].window_start,
                window_end=windows[0].window_end,
                model_score=0.0,
                flagged=False,
                model_snapshot_id=model_snapshot_id,
            )
        ]
    bundle, raw_scores, residuals = fitted
    return score_windows_with_autoencoder(
        windows,
        bundle,
        flagging=flagging,
        score_threshold=score_threshold,
        mad_k=mad_k,
        model_snapshot_id=model_snapshot_id,
        raw_scores=raw_scores,
        residuals=residuals,
        top_k_features=top_k_features,
    )


def scaler_params(bundle: AutoencoderBundle) -> dict[str, list[float]]:
    """Serialize scaler mean/scale for ONNX sidecars."""
    mean = getattr(bundle.scaler, "mean_", None)
    scale = getattr(bundle.scaler, "scale_", None)
    if mean is None or scale is None:
        raise ValueError("AutoencoderBundle scaler is not fitted")
    return {
        "scaler_mean": [float(x) for x in mean],
        "scaler_scale": [float(x) for x in scale],
    }


def vocab_to_dict(vocab: FeatureVocab) -> dict:
    """JSON-serializable vocab for ONNX sidecars."""
    return {
        "top_templates": list(vocab.top_templates),
        "top_bigrams": [list(pair) for pair in vocab.top_bigrams],
        "feature_names": feature_names(vocab),
    }
