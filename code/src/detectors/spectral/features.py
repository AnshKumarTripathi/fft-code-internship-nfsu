"""Compact spectral fingerprints from baselines (SDD §7.5.6)."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np

from src.detectors.spectral.baseline import SpectralBaseline


@dataclass(frozen=True)
class EntitySpectralFeatures:
    entity_id: str
    dominant_period_hours: float
    dominant_power_frac: float
    spectral_entropy: float
    total_power: float
    computed_at: datetime


def dominant_ac_peak(
    freqs: np.ndarray,
    psd_norm: np.ndarray,
    bucket_seconds: int,
) -> tuple[float, float]:
    """Skip DC; return ``(period_hours, power_frac)``. Period is 0 if no AC peak."""
    freq_arr = np.asarray(freqs, dtype=np.float64)
    psd_arr = np.asarray(psd_norm, dtype=np.float64)
    if psd_arr.size == 0:
        return 0.0, 0.0
    if psd_arr.size <= 1:
        dominant_idx = 0
    else:
        search = psd_arr.copy()
        search[0] = -1.0
        dominant_idx = int(np.argmax(search))
        if search[dominant_idx] < 0:
            dominant_idx = int(np.argmax(psd_arr))
    dominant_freq = float(freq_arr[dominant_idx]) if freq_arr.size else 0.0
    if dominant_freq > 0.0:
        period_hours = (1.0 / dominant_freq) * bucket_seconds / 3600.0
    else:
        period_hours = 0.0
    power_frac = float(psd_arr[dominant_idx]) if psd_arr.size else 0.0
    return period_hours, power_frac


def spectral_summary_features(
    baseline: SpectralBaseline,
    *,
    computed_at: datetime | None = None,
) -> EntitySpectralFeatures:
    """Derive scalar features from a baseline PSD row."""
    psd = np.asarray(baseline.psd, dtype=np.float64)
    psd_norm = np.asarray(baseline.psd_norm, dtype=np.float64)
    freqs = np.asarray(baseline.freq_grid, dtype=np.float64)

    total_power = float(np.sum(psd))
    dominant_period_hours, dominant_power_frac = dominant_ac_peak(
        freqs, psd_norm, baseline.bucket_seconds
    )

    positive = psd_norm[psd_norm > 0]
    if positive.size:
        spectral_entropy = float(-np.sum(positive * np.log(positive)))
    else:
        spectral_entropy = 0.0

    if math.isnan(spectral_entropy):
        spectral_entropy = 0.0

    ts = computed_at or baseline.computed_at or datetime.now(timezone.utc)
    return EntitySpectralFeatures(
        entity_id=baseline.entity_id,
        dominant_period_hours=dominant_period_hours,
        dominant_power_frac=dominant_power_frac,
        spectral_entropy=spectral_entropy,
        total_power=total_power,
        computed_at=ts,
    )
