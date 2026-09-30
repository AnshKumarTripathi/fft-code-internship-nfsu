"""IsolationForest sequence scorer over Drain3 template_id windows (SDD §7.6).

MVP windowing (locked for Phase 7; do not edit ground truth):
  D = statistical.window_buckets * bucketing.bucket_seconds (default 3600s).
  Non-overlapping windows aligned to the bucket grid (multiples of D).
  Skip windows with fewer than MIN_EVENTS events.

Features (fixed-dim, rebuilt each batch run):
  top-TOP_K_TEMPLATES template counts + other bin;
  top-TOP_K_BIGRAMS bigram counts + other bin;
  sequence length, unique template count, Shannon entropy.

Fit: one global IsolationForest + global vocab per batch.
Per-entity models are deferred until Phase 15 shows global MAD flagging
fails on labeled data.

model_score increases with anomaly (negated decision_function).
Default flagging is mad_threshold (robust z of model_score, one-sided high).
flagging=predict keeps v1 IsolationForest predict == -1.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.detectors.robust_z import robust_z_scores

MIN_EVENTS = 5
TOP_K_TEMPLATES = 20
TOP_K_BIGRAMS = 50
RANDOM_STATE = 42
DEFAULT_FLAGGING = "mad_threshold"
DEFAULT_MAD_K = 4.0
FLAGGING_POLICIES = frozenset(
    {"predict", "score_threshold", "mad_threshold", "none"}
)


@dataclass(frozen=True)
class MlWindowScore:
    entity_id: str
    window_start: datetime
    window_end: datetime
    model_score: float
    flagged: bool
    model_snapshot_id: str | None = None
    mad_z: float | None = None
    attribution: dict[str, Any] | None = None


@dataclass
class IsolationBundle:
    """Fitted global IsolationForest + the vocab/scaler it was trained with."""

    model: IsolationForest
    scaler: StandardScaler
    vocab: FeatureVocab
    contamination: float
    random_state: int


@dataclass(frozen=True)
class TemplateWindow:
    entity_id: str
    window_start: datetime
    window_end: datetime
    template_ids: tuple[str, ...]


@dataclass(frozen=True)
class FeatureVocab:
    top_templates: tuple[str, ...]
    top_bigrams: tuple[tuple[str, str], ...]


def slice_entity_windows(
    events: Sequence[tuple[datetime, str]],
    *,
    entity_id: str,
    window_seconds: int,
    min_events: int = MIN_EVENTS,
) -> list[TemplateWindow]:
    """Slice sorted (timestamp, template_id) events into non-overlapping windows."""
    if window_seconds <= 0:
        raise ValueError(f"window_seconds must be positive, got {window_seconds!r}")
    if min_events <= 0:
        raise ValueError(f"min_events must be positive, got {min_events!r}")
    if not events:
        return []

    buckets: dict[int, list[str]] = {}
    for ts, template_id in events:
        ts_utc = _ensure_utc(ts)
        start_epoch = int(ts_utc.timestamp()) // window_seconds * window_seconds
        buckets.setdefault(start_epoch, []).append(template_id)

    windows: list[TemplateWindow] = []
    for start_epoch in sorted(buckets):
        templates = buckets[start_epoch]
        if len(templates) < min_events:
            continue
        window_start = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
        window_end = datetime.fromtimestamp(
            start_epoch + window_seconds, tz=timezone.utc
        )
        windows.append(
            TemplateWindow(
                entity_id=entity_id,
                window_start=window_start,
                window_end=window_end,
                template_ids=tuple(templates),
            )
        )
    return windows


def build_vocab(
    sequences: Sequence[Sequence[str]],
    *,
    top_k_templates: int = TOP_K_TEMPLATES,
    top_k_bigrams: int = TOP_K_BIGRAMS,
) -> FeatureVocab:
    """Build a fixed global vocabulary from all window template sequences."""
    template_counts: Counter[str] = Counter()
    bigram_counts: Counter[tuple[str, str]] = Counter()
    for seq in sequences:
        template_counts.update(seq)
        bigram_counts.update(zip(seq, seq[1:]))

    top_templates = tuple(tid for tid, _ in template_counts.most_common(top_k_templates))
    top_bigrams = tuple(bg for bg, _ in bigram_counts.most_common(top_k_bigrams))
    return FeatureVocab(top_templates=top_templates, top_bigrams=top_bigrams)


def vectorize_window(template_ids: Sequence[str], vocab: FeatureVocab) -> np.ndarray:
    """Encode one window as a fixed-length float feature vector."""
    n = len(template_ids)
    template_set = set(vocab.top_templates)
    bigram_set = set(vocab.top_bigrams)

    template_counts = Counter(template_ids)
    template_feats = [float(template_counts.get(tid, 0)) for tid in vocab.top_templates]
    other_templates = float(
        sum(c for tid, c in template_counts.items() if tid not in template_set)
    )

    bigram_counts = Counter(zip(template_ids, template_ids[1:]))
    bigram_feats = [float(bigram_counts.get(bg, 0)) for bg in vocab.top_bigrams]
    other_bigrams = float(
        sum(c for bg, c in bigram_counts.items() if bg not in bigram_set)
    )

    unique = float(len(set(template_ids)))
    entropy = _shannon_entropy(template_counts, n)

    return np.asarray(
        template_feats
        + [other_templates]
        + bigram_feats
        + [other_bigrams]
        + [float(n), unique, entropy],
        dtype=np.float64,
    )


def apply_ml_flagging(
    model_scores: Sequence[float],
    predictions: Sequence[int] | None = None,
    *,
    flagging: str = DEFAULT_FLAGGING,
    score_threshold: float | None = None,
    mad_k: float = DEFAULT_MAD_K,
) -> list[bool]:
    """Map model scores (and optional predict labels) onto flagged booleans."""
    if flagging not in FLAGGING_POLICIES:
        raise ValueError(
            f"flagging must be one of {sorted(FLAGGING_POLICIES)}, got {flagging!r}"
        )
    n = len(model_scores)
    if n == 0:
        return []

    if flagging == "none":
        return [False] * n

    if flagging == "predict":
        if predictions is None or len(predictions) != n:
            raise ValueError("flagging='predict' requires predictions of equal length")
        return [bool(pred == -1) for pred in predictions]

    if flagging == "score_threshold":
        if score_threshold is None:
            raise ValueError(
                "score_threshold is required when flagging is 'score_threshold'"
            )
        return [float(score) >= score_threshold for score in model_scores]

    z_scores = robust_z_scores([float(score) for score in model_scores])
    return [z >= mad_k for z in z_scores]


def fit_isolation_bundle(
    windows: Sequence[TemplateWindow],
    *,
    contamination: float,
    random_state: int = RANDOM_STATE,
) -> tuple[IsolationBundle, list[float], list[int]] | None:
    """Fit scaler + IsolationForest. None when the corpus is too small to isolate."""
    if not windows:
        return None
    if not (0.0 < contamination <= 0.5):
        raise ValueError(
            f"contamination must be in (0, 0.5], got {contamination!r}"
        )

    sequences = [w.template_ids for w in windows]
    vocab = build_vocab(sequences)
    matrix = np.vstack([vectorize_window(seq, vocab) for seq in sequences])
    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)
    n_samples = scaled.shape[0]
    if n_samples < 2:
        return None

    min_contam = 1.0 / n_samples
    effective_contamination = max(contamination, min_contam)
    if effective_contamination > 0.5:
        effective_contamination = min(0.5, max(min_contam, 1.0 / n_samples))

    model = IsolationForest(
        contamination=effective_contamination,
        random_state=random_state,
        n_estimators=100,
    )
    predictions = [int(pred) for pred in model.fit_predict(scaled)]
    raw_scores = [float(score) for score in -model.decision_function(scaled)]
    bundle = IsolationBundle(
        model=model,
        scaler=scaler,
        vocab=vocab,
        contamination=contamination,
        random_state=random_state,
    )
    return bundle, raw_scores, predictions


def score_windows_with_bundle(
    windows: Sequence[TemplateWindow],
    bundle: IsolationBundle,
    *,
    flagging: str = DEFAULT_FLAGGING,
    score_threshold: float | None = None,
    mad_k: float = DEFAULT_MAD_K,
    model_snapshot_id: str | None = None,
    raw_scores: Sequence[float] | None = None,
    predictions: Sequence[int] | None = None,
    top_k_features: int = 5,
) -> list[MlWindowScore]:
    """Score windows with a frozen IsolationBundle (R5 reuse_snapshot)."""
    if not windows:
        return []
    matrix = np.vstack(
        [vectorize_window(window.template_ids, bundle.vocab) for window in windows]
    )
    scaled = bundle.scaler.transform(matrix)
    if raw_scores is None or predictions is None:
        predictions = [int(pred) for pred in bundle.model.predict(scaled)]
        raw_scores = [
            float(score) for score in -bundle.model.decision_function(scaled)
        ]
    flagged_flags = apply_ml_flagging(
        list(raw_scores),
        list(predictions),
        flagging=flagging,
        score_threshold=score_threshold,
        mad_k=mad_k,
    )
    mad_z_scores = robust_z_scores([float(score) for score in raw_scores])
    batch_median = np.median(scaled, axis=0)
    from src.detectors.ml.attribution import attribution_median_deviation

    rows: list[MlWindowScore] = []
    for index, (window, score, flagged, mad_z) in enumerate(
        zip(windows, raw_scores, flagged_flags, mad_z_scores, strict=True)
    ):
        attribution = None
        if flagged:
            attribution = attribution_median_deviation(
                scaled[index],
                batch_median,
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


def fit_score_windows(
    windows: Sequence[TemplateWindow],
    *,
    contamination: float,
    flagging: str = DEFAULT_FLAGGING,
    score_threshold: float | None = None,
    mad_k: float = DEFAULT_MAD_K,
    random_state: int = RANDOM_STATE,
    model_snapshot_id: str | None = None,
) -> list[MlWindowScore]:
    """Fit a global IsolationForest and score every window."""
    if not windows:
        return []
    fitted = fit_isolation_bundle(
        windows, contamination=contamination, random_state=random_state
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
    bundle, raw_scores, predictions = fitted
    return score_windows_with_bundle(
        windows,
        bundle,
        flagging=flagging,
        score_threshold=score_threshold,
        mad_k=mad_k,
        model_snapshot_id=model_snapshot_id,
        raw_scores=raw_scores,
        predictions=predictions,
    )


def _shannon_entropy(counts: Counter[str], total: int) -> float:
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)
