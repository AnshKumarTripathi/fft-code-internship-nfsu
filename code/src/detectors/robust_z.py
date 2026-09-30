"""Robust median/MAD z-scores shared across detectors (SDD §7.5.4).

Phase 5 (statistical) and Phase 6 (spectral) both use this neutral module.
No detector-specific imports belong here.
"""

from __future__ import annotations

from typing import Sequence

import numpy as np

MAD_TO_STD_CONSTANT = 0.6745
ROBUST_Z_EPSILON = 1e-9


def robust_z_scores(values: Sequence[float]) -> list[float]:
    """Return per-element robust z-scores for ``values``.

    Formula: ``z = 0.6745 * (x - median(x)) / (median(|x - median(x)|) + ε)``

    When MAD is zero and every value equals the median (constant series),
    every z-score is ``0.0``. When MAD collapses because many windows tie at
    the median but outliers exist, fall back to std scaling so rare bursts
    remain scorable.
    """
    if not values:
        return []

    arr = np.asarray(values, dtype=np.float64)
    if arr.size == 1:
        return [0.0]

    median = float(np.median(arr))
    mad = float(np.median(np.abs(arr - median)))
    if mad == 0.0:
        if np.all(arr == median):
            return [0.0] * arr.size
        scale = float(np.std(arr))
        if scale <= ROBUST_Z_EPSILON:
            return [0.0] * arr.size
        z = (arr - median) / (scale + ROBUST_Z_EPSILON)
        return [float(v) for v in z]

    z = MAD_TO_STD_CONSTANT * (arr - median) / (mad + ROBUST_Z_EPSILON)
    return [float(v) for v in z]
