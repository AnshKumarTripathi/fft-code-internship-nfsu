"""Shared count-series contracts for Welch / STFT.

Sampling is one sample per bucket (``fs=1``). The Nyquist period is two
buckets: activity faster than ``bucket_seconds`` is folded into a single bin
and cannot appear as a spectral peak.
"""

from __future__ import annotations

from typing import Sequence

import numpy as np

MIN_WELCH_LENGTH = 4
WELCH_DETREND = "constant"
DEFAULT_FFT_WINDOW = "hann"

# Hann is the SciPy default: moderate leakage, good for unknown log rhythms.
# Hamming is similar with a slightly different sidelobe floor. Boxcar (rectangular)
# has the narrowest main lobe and the worst leakage — only use it when you need
# maximum frequency resolution and can tolerate spectral bleed.
ALLOWED_FFT_WINDOWS = frozenset(
    {"hann", "hamming", "boxcar", "blackman", "bartlett"}
)


def as_count_series(counts: Sequence[float] | np.ndarray) -> np.ndarray:
    """Return a 1-d float64 view of ``counts`` (empty array if ``counts`` is empty)."""
    series = np.asarray(counts, dtype=np.float64)
    if series.size == 0:
        return np.array([], dtype=np.float64)
    return np.reshape(series, -1)


def series_has_nonfinite(series: np.ndarray) -> bool:
    """True when any value is NaN or Inf. Empty series is finite."""
    return series.size > 0 and not bool(np.all(np.isfinite(series)))


def psd_is_usable(psd: np.ndarray) -> bool:
    """False when a periodogram is empty, non-finite, or has non-positive mass."""
    if psd.size == 0 or not bool(np.all(np.isfinite(psd))):
        return False
    total = float(np.sum(psd))
    return bool(np.isfinite(total) and total > 0.0)


def nyquist_period_seconds(bucket_seconds: int) -> int:
    """Shortest oscillation period a bucketed series can represent."""
    if bucket_seconds <= 0:
        raise ValueError(f"bucket_seconds must be positive, got {bucket_seconds!r}")
    return 2 * bucket_seconds
