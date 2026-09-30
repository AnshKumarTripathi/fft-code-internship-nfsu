"""STFT windowed spectral deviation scores (SDD §7.5.3).

Energy uses STFT column total power. Shape compares Welch PSD on each window
segment (``nperseg=window_buckets``) against a rematched full-series Welch
baseline at the same segment length so frequency grids align (§7.5.5 #2).

Empty series, series shorter than ``window_buckets``, and series containing
NaN or Inf return ``[]`` and never raise. Invalid ``window_buckets`` /
``step_buckets`` / ``bucket_seconds`` still raise ``ValueError``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

import numpy as np
from scipy.signal import stft, welch
from scipy.spatial.distance import jensenshannon

from src.detectors.robust_z import robust_z_scores
from src.detectors.spectral.baseline import FS, SpectralBaseline
from src.detectors.spectral.features import dominant_ac_peak
from src.detectors.spectral.series import (
    DEFAULT_FFT_WINDOW,
    MIN_WELCH_LENGTH,
    WELCH_DETREND,
    as_count_series,
    psd_is_usable,
    series_has_nonfinite,
)


@dataclass(frozen=True)
class SpectralWindowScore:
    entity_id: str
    window_start: datetime
    window_end: datetime
    energy_z: float
    shape_js_z: float
    flagged: bool
    dominant_period_hours: float | None = None
    shape_top_bins: tuple[dict[str, float | None], ...] = ()


def recompute_baseline_shape_at_nperseg(
    counts: np.ndarray,
    nperseg: int,
    *,
    window: str = DEFAULT_FFT_WINDOW,
    min_welch_length: int = MIN_WELCH_LENGTH,
) -> tuple[np.ndarray, np.ndarray]:
    """Welch PSD normalized to a probability vector at ``nperseg``."""
    series = as_count_series(counts)
    if series.size < min_welch_length:
        raise ValueError("counts too short for Welch rematch")
    if nperseg <= 0:
        raise ValueError("nperseg must be positive")
    if series_has_nonfinite(series):
        return np.array([]), np.array([])

    effective = min(nperseg, series.size)
    effective = max(min_welch_length, effective)
    noverlap = effective // 2
    freqs, psd = welch(
        series,
        fs=FS,
        window=window,
        nperseg=effective,
        noverlap=noverlap,
        detrend=WELCH_DETREND,
    )
    if not psd_is_usable(psd):
        return freqs, np.zeros_like(psd)
    return freqs, psd / float(np.sum(psd))


def _align_prob_vectors(p: np.ndarray, q: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    length = min(p.size, q.size)
    if length == 0:
        return np.array([]), np.array([])
    p_trim = p[:length]
    q_trim = q[:length]
    p_sum = float(np.sum(p_trim))
    q_sum = float(np.sum(q_trim))
    if p_sum <= 0.0 or q_sum <= 0.0:
        return p_trim, q_trim
    return p_trim / p_sum, q_trim / q_sum


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def top_abs_diff_bins(
    p: np.ndarray,
    q: np.ndarray,
    freqs: np.ndarray,
    bucket_seconds: int,
    *,
    top_k: int,
) -> tuple[dict[str, float | None], ...]:
    """Largest |p−q| bins after JS alignment (coarse shape attribution)."""
    if top_k < 1:
        return ()
    p_aligned, q_aligned = p, q
    n = min(p_aligned.size, q_aligned.size)
    if n == 0:
        return ()
    diff = np.abs(p_aligned[:n] - q_aligned[:n])
    freq_arr = np.asarray(freqs, dtype=np.float64)[:n]
    k = min(top_k, n)
    order = np.argsort(diff)[::-1][:k]
    bins: list[dict[str, float | None]] = []
    for idx in order:
        freq = float(freq_arr[idx]) if idx < freq_arr.size else 0.0
        period = (1.0 / freq) * bucket_seconds / 3600.0 if freq > 0.0 else None
        bins.append(
            {
                "freq": freq,
                "period_hours": period,
                "abs_diff": float(diff[idx]),
            }
        )
    return tuple(bins)


KNOWN_FLAG_MODES = frozenset({"or", "and", "energy_only", "shape_only"})


def apply_spectral_flag(
    energy_z: float,
    shape_js_z: float,
    *,
    energy_z_threshold: float,
    shape_js_z_threshold: float,
    flag_mode: str = "or",
) -> bool:
    """Apply Phase 51 spectral flag policy to one window's z scores."""
    mode = flag_mode.strip().lower()
    if mode not in KNOWN_FLAG_MODES:
        raise ValueError(f"unknown spectral flag_mode: {flag_mode!r}")
    energy_hit = math.isfinite(energy_z) and energy_z >= energy_z_threshold
    shape_hit = math.isfinite(shape_js_z) and shape_js_z >= shape_js_z_threshold
    if mode == "or":
        return energy_hit or shape_hit
    if mode == "and":
        return energy_hit and shape_hit
    if mode == "energy_only":
        return energy_hit
    return shape_hit


def windowed_deviation(
    counts: np.ndarray,
    bucket_starts: Sequence[datetime],
    baseline: SpectralBaseline,
    *,
    bucket_seconds: int,
    window_buckets: int,
    step_buckets: int,
    z_threshold: float,
    window: str = DEFAULT_FFT_WINDOW,
    min_welch_length: int = MIN_WELCH_LENGTH,
    top_js_bins: int = 3,
    energy_z_threshold: float | None = None,
    shape_js_z_threshold: float | None = None,
    flag_mode: str = "or",
    discount_last_window: bool = False,
) -> list[SpectralWindowScore]:
    """Slide STFT windows; score energy and shape JS vs rematched baseline."""
    if window_buckets <= 0 or step_buckets <= 0:
        raise ValueError("window_buckets and step_buckets must be positive")
    if bucket_seconds <= 0:
        raise ValueError("bucket_seconds must be positive")

    energy_thr = float(
        z_threshold if energy_z_threshold is None else energy_z_threshold
    )
    shape_thr = float(
        z_threshold if shape_js_z_threshold is None else shape_js_z_threshold
    )

    series = as_count_series(counts)
    if series.size != len(bucket_starts):
        raise ValueError("counts and bucket_starts must have equal length")
    if series.size < window_buckets or series_has_nonfinite(series):
        return []

    noverlap = window_buckets - step_buckets
    if noverlap < 0:
        noverlap = 0

    _, _, zxx = stft(
        series,
        fs=FS,
        window=window,
        nperseg=window_buckets,
        noverlap=noverlap,
        boundary=None,
        detrend=WELCH_DETREND,
    )
    n_windows = zxx.shape[1]
    if n_windows == 0:
        return []

    baseline_freqs, baseline_shape = recompute_baseline_shape_at_nperseg(
        series,
        window_buckets,
        window=window,
        min_welch_length=min_welch_length,
    )

    energies: list[float] = []
    js_values: list[float] = []
    window_meta: list[tuple[datetime, datetime]] = []
    window_periods: list[float | None] = []
    window_bins: list[tuple[dict[str, float | None], ...]] = []

    for col in range(n_windows):
        power = np.abs(zxx[:, col]) ** 2
        energies.append(float(np.sum(power)))

        start_idx = col * step_buckets
        end_idx = start_idx + window_buckets - 1
        if end_idx >= len(bucket_starts):
            end_idx = len(bucket_starts) - 1
            start_idx = max(0, end_idx - window_buckets + 1)
        segment = series[start_idx : end_idx + 1]
        period_hours: float | None = None
        bins: tuple[dict[str, float | None], ...] = ()
        try:
            window_freqs, window_shape = recompute_baseline_shape_at_nperseg(
                segment,
                window_buckets,
                window=window,
                min_welch_length=min_welch_length,
            )
        except ValueError:
            js_values.append(0.0)
        else:
            if psd_is_usable(window_shape):
                period_hours, _ = dominant_ac_peak(
                    window_freqs, window_shape, bucket_seconds
                )
            p_aligned, q_aligned = _align_prob_vectors(window_shape, baseline_shape)
            if (
                p_aligned.size == 0
                or not psd_is_usable(p_aligned)
                or not psd_is_usable(q_aligned)
            ):
                js_values.append(0.0)
            else:
                with np.errstate(invalid="ignore"):
                    divergence = float(jensenshannon(p_aligned, q_aligned))
                js_values.append(divergence if math.isfinite(divergence) else 0.0)
                bins = top_abs_diff_bins(
                    p_aligned,
                    q_aligned,
                    baseline_freqs if baseline_freqs.size else window_freqs,
                    bucket_seconds,
                    top_k=top_js_bins,
                )

        window_start = _ensure_utc(bucket_starts[start_idx])
        window_end = _ensure_utc(bucket_starts[end_idx]) + timedelta(
            seconds=bucket_seconds
        )
        window_meta.append((window_start, window_end))
        window_periods.append(period_hours)
        window_bins.append(bins)

    energy_z = robust_z_scores(energies)
    shape_js_z = robust_z_scores(js_values)

    rows: list[SpectralWindowScore] = []
    last_index = len(window_meta) - 1
    for index, ((window_start, window_end), e_z, s_z, period, bins) in enumerate(
        zip(window_meta, energy_z, shape_js_z, window_periods, window_bins, strict=True)
    ):
        flagged = apply_spectral_flag(
            e_z,
            s_z,
            energy_z_threshold=energy_thr,
            shape_js_z_threshold=shape_thr,
            flag_mode=flag_mode,
        )
        if discount_last_window and index == last_index:
            flagged = False
        rows.append(
            SpectralWindowScore(
                entity_id=baseline.entity_id,
                window_start=window_start,
                window_end=window_end,
                energy_z=e_z,
                shape_js_z=s_z,
                flagged=flagged,
                dominant_period_hours=period,
                shape_top_bins=bins,
            )
        )
    return rows


def compare_shape_js_mismatched_resolution(
    counts: np.ndarray,
    window_buckets: int,
    long_nperseg: int,
    *,
    window: str = DEFAULT_FFT_WINDOW,
    min_welch_length: int = MIN_WELCH_LENGTH,
) -> float:
    """JS using long-Welch baseline without rematch (test helper for §7.5.5 #2)."""
    series = as_count_series(counts)
    if series.size < window_buckets or series_has_nonfinite(series):
        return 0.0

    segment = series[:window_buckets]
    effective = min(window_buckets, segment.size)
    effective = max(min_welch_length, effective)
    _, window_psd = welch(
        segment,
        fs=FS,
        window=window,
        nperseg=effective,
        noverlap=effective // 2,
        detrend=WELCH_DETREND,
    )
    if not psd_is_usable(window_psd):
        return 0.0
    p = window_psd / float(np.sum(window_psd))

    long_n = min(long_nperseg, series.size)
    long_n = max(min_welch_length, long_n)
    _, long_psd = welch(
        series,
        fs=FS,
        window=window,
        nperseg=long_n,
        noverlap=long_n // 2,
        detrend=WELCH_DETREND,
    )
    if not psd_is_usable(long_psd):
        return 0.0
    q = long_psd / float(np.sum(long_psd))

    p_aligned, q_aligned = _align_prob_vectors(p, q)
    if p_aligned.size == 0:
        return 0.0
    return float(jensenshannon(p_aligned, q_aligned))
