"""Coarse ML feature / template attribution (Phase 53).

Ranks template and bigram columns by deviation from a batch reference
(median of scaled features) or by autoencoder reconstruction residual.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np

from src.detectors.ml.isolation_forest import (
    TOP_K_BIGRAMS,
    TOP_K_TEMPLATES,
    FeatureVocab,
    vectorize_window,
)


def feature_names(vocab: FeatureVocab) -> list[str]:
    """Stable column names matching ``vectorize_window`` layout."""
    names = [f"tmpl:{tid}" for tid in vocab.top_templates]
    names.append("tmpl:other")
    for left, right in vocab.top_bigrams:
        names.append(f"bigram:{left}->{right}")
    names.append("bigram:other")
    names.extend(["seq_len", "unique_count", "entropy"])
    return names


def expected_feature_dim(
    *,
    top_k_templates: int = TOP_K_TEMPLATES,
    top_k_bigrams: int = TOP_K_BIGRAMS,
) -> int:
    """Fixed vector length for empty-vocab edge cases."""
    return top_k_templates + 1 + top_k_bigrams + 1 + 3


def rank_contributions(
    contributions: np.ndarray,
    names: Sequence[str],
    *,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """Return top-k ``{name, contribution}`` rows sorted by contribution desc."""
    if contributions.ndim != 1:
        raise ValueError("contributions must be 1-D")
    if len(contributions) != len(names):
        raise ValueError(
            f"contributions length {len(contributions)} != names {len(names)}"
        )
    if top_k < 1 or len(contributions) == 0:
        return []
    order = np.argsort(-contributions)
    out: list[dict[str, Any]] = []
    for idx in order[:top_k]:
        value = float(contributions[idx])
        if not np.isfinite(value):
            continue
        out.append({"name": str(names[idx]), "contribution": value})
    return out


def templates_from_features(
    ranked: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map ranked ``tmpl:*`` features onto template contribution rows."""
    out: list[dict[str, Any]] = []
    for row in ranked:
        name = str(row.get("name") or "")
        if not name.startswith("tmpl:") or name == "tmpl:other":
            continue
        template_id = name[len("tmpl:") :]
        contribution = row.get("contribution")
        try:
            score = float(contribution) if contribution is not None else 0.0
        except (TypeError, ValueError):
            score = 0.0
        out.append(
            {
                "template_id": template_id,
                "template_string": None,
                "event_count": 0,
                "contribution": score,
            }
        )
    return out


def attribution_from_residuals(
    residuals: np.ndarray,
    vocab: FeatureVocab,
    *,
    top_k: int = 5,
) -> dict[str, Any]:
    """Build attribution payload from per-feature absolute residuals."""
    names = feature_names(vocab)
    ranked = rank_contributions(np.abs(residuals).astype(np.float64), names, top_k=top_k)
    return {
        "top_contributing_features": ranked,
        "top_templates": templates_from_features(ranked),
    }


def attribution_median_deviation(
    scaled_row: np.ndarray,
    batch_median: np.ndarray,
    vocab: FeatureVocab,
    *,
    top_k: int = 5,
) -> dict[str, Any]:
    """Rank ``|scaled_x − batch_median|`` (IsolationForest / ONNX IF path)."""
    residuals = np.abs(scaled_row - batch_median)
    return attribution_from_residuals(residuals, vocab, top_k=top_k)


def attribution_reconstruction(
    scaled_row: np.ndarray,
    reconstructed: np.ndarray,
    vocab: FeatureVocab,
    *,
    top_k: int = 5,
) -> dict[str, Any]:
    """Rank ``|x − x_hat|`` residuals (autoencoder / ONNX AE path)."""
    residuals = np.abs(scaled_row - reconstructed)
    return attribution_from_residuals(residuals, vocab, top_k=top_k)


def batch_median_scaled(
    windows: Sequence[Any],
    vocab: FeatureVocab,
    scaler: Any,
) -> np.ndarray:
    """Median of scaled feature rows across windows (reference for IF attribution)."""
    if not windows:
        dim = len(feature_names(vocab))
        return np.zeros(dim, dtype=np.float64)
    matrix = np.vstack(
        [vectorize_window(window.template_ids, vocab) for window in windows]
    )
    scaled = scaler.transform(matrix)
    return np.median(scaled, axis=0)
