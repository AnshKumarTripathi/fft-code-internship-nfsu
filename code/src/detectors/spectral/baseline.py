"""Welch baseline PSD per entity (SDD §7.5.2).

Sampling convention: ``fs=1.0`` (one sample per bucket). Convert frequencies
to hours via ``period_hours = (1 / f) * bucket_seconds / 3600`` when ``f > 0``.

Welch uses ``detrend='constant'`` (mean removed per segment) and the configured
FFT taper (default Hann). A constant or all-zero series therefore has no
oscillatory power and this function returns ``None``.

Empty series, series shorter than ``min_welch_length``, and series containing
NaN or Inf also return ``None`` — they never raise.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
from scipy.signal import welch

from src.detectors.spectral.series import (
    DEFAULT_FFT_WINDOW,
    MIN_WELCH_LENGTH,
    WELCH_DETREND,
    as_count_series,
    psd_is_usable,
    series_has_nonfinite,
)

FS = 1.0


@dataclass(frozen=True)
class SpectralBaseline:
    entity_id: str
    computed_at: datetime
    bucket_seconds: int
    nperseg: int
    freq_grid: list[float]
    psd: list[float]
    psd_norm: list[float]


def _effective_nperseg(
    series_len: int,
    baseline_max_nperseg: int,
    min_welch_length: int,
) -> int:
    capped = min(series_len, baseline_max_nperseg)
    return max(min_welch_length, min(capped, series_len))


def compute_baseline(
    counts: np.ndarray,
    *,
    entity_id: str,
    bucket_seconds: int,
    baseline_max_nperseg: int,
    computed_at: datetime | None = None,
    window: str = DEFAULT_FFT_WINDOW,
    min_welch_length: int = MIN_WELCH_LENGTH,
) -> SpectralBaseline | None:
    """Compute Welch PSD baseline for one entity count series.

    Returns ``None`` when the series is empty, too short, non-finite, or has
    no positive finite spectral mass (including all-zero and constant series
    after mean removal).
    """
    if bucket_seconds <= 0:
        raise ValueError(f"bucket_seconds must be positive, got {bucket_seconds!r}")

    series = as_count_series(counts)
    if series.size < min_welch_length or series_has_nonfinite(series):
        return None

    nperseg = _effective_nperseg(
        series.size, baseline_max_nperseg, min_welch_length
    )
    if series.size < nperseg:
        return None

    noverlap = nperseg // 2
    freqs, psd = welch(
        series,
        fs=FS,
        window=window,
        nperseg=nperseg,
        noverlap=noverlap,
        detrend=WELCH_DETREND,
    )
    if not psd_is_usable(psd):
        return None

    total = float(np.sum(psd))
    psd_norm = psd / total
    ts = computed_at or datetime.now(timezone.utc)
    return SpectralBaseline(
        entity_id=entity_id,
        computed_at=ts,
        bucket_seconds=bucket_seconds,
        nperseg=int(nperseg),
        freq_grid=[float(v) for v in freqs],
        psd=[float(v) for v in psd],
        psd_norm=[float(v) for v in psd_norm],
    )
