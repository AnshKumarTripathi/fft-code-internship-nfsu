"""Capped STFT power matrix for UI heatmaps (Phase 60).

Compute-on-read from ``entity_bucket_counts``. Hard caps keep response size
bounded (default 128 freq × 200 time). Missing / unusable cells are ``None``,
never silent zeros for “no data”.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

import numpy as np
from scipy.signal import stft

from src.detectors.spectral.baseline import FS
from src.detectors.spectral.series import (
    DEFAULT_FFT_WINDOW,
    WELCH_DETREND,
    as_count_series,
    series_has_nonfinite,
)

# UI / API hard caps (Phase 60). Documented in KNOWN_LIMITATIONS.md.
STFT_UI_MAX_FREQ_BINS = 128
STFT_UI_MAX_TIME_BINS = 200
STFT_UI_MAX_INPUT_BUCKETS = 50_000


@dataclass(frozen=True)
class StftMatrixResult:
    freqs: list[float]
    period_hours: list[float | None]
    time_starts: list[datetime | None]
    power: list[list[float | None]]
    n_freq: int
    n_time: int
    capped: bool
    truncated_input: bool
    empty_reason: str | None
    window_buckets: int
    step_buckets: int
    bucket_seconds: int
    input_buckets: int
    gap_fraction: float | None


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _period_hours(freq: float, bucket_seconds: int) -> float | None:
    if freq <= 0.0 or bucket_seconds <= 0:
        return None
    return (1.0 / freq) * bucket_seconds / 3600.0


def _subsample_indices(length: int, max_bins: int) -> np.ndarray:
    if length <= max_bins:
        return np.arange(length, dtype=np.int64)
    return np.linspace(0, length - 1, num=max_bins, dtype=np.int64)


def compute_stft_power_matrix(
    counts: Sequence[float] | np.ndarray,
    bucket_starts: Sequence[datetime],
    *,
    bucket_seconds: int,
    window_buckets: int,
    step_buckets: int,
    window: str = DEFAULT_FFT_WINDOW,
    max_freq_bins: int = STFT_UI_MAX_FREQ_BINS,
    max_time_bins: int = STFT_UI_MAX_TIME_BINS,
    max_input_buckets: int = STFT_UI_MAX_INPUT_BUCKETS,
) -> StftMatrixResult:
    """Return a capped STFT power matrix (freq × time)."""
    if bucket_seconds <= 0:
        raise ValueError("bucket_seconds must be positive")
    if window_buckets <= 0 or step_buckets <= 0:
        raise ValueError("window_buckets and step_buckets must be positive")
    if max_freq_bins < 1 or max_time_bins < 1:
        raise ValueError("max_freq_bins and max_time_bins must be >= 1")

    empty = StftMatrixResult(
        freqs=[],
        period_hours=[],
        time_starts=[],
        power=[],
        n_freq=0,
        n_time=0,
        capped=False,
        truncated_input=False,
        empty_reason=None,
        window_buckets=window_buckets,
        step_buckets=step_buckets,
        bucket_seconds=bucket_seconds,
        input_buckets=0,
        gap_fraction=None,
    )

    series = as_count_series(counts)
    if series.size != len(bucket_starts):
        raise ValueError("counts and bucket_starts must have equal length")
    if series.size == 0:
        return StftMatrixResult(**{**empty.__dict__, "empty_reason": "no_buckets"})
    if series.size < window_buckets:
        return StftMatrixResult(
            **{
                **empty.__dict__,
                "input_buckets": int(series.size),
                "empty_reason": "insufficient_history",
            }
        )
    if series_has_nonfinite(series):
        return StftMatrixResult(
            **{
                **empty.__dict__,
                "input_buckets": int(series.size),
                "empty_reason": "nonfinite",
            }
        )

    truncated_input = False
    starts = list(bucket_starts)
    if series.size > max_input_buckets:
        series = series[-max_input_buckets:]
        starts = starts[-max_input_buckets:]
        truncated_input = True

    zero_frac = float(np.mean(series == 0.0)) if series.size else None
    noverlap = max(0, window_buckets - step_buckets)

    freqs, times, zxx = stft(
        series,
        fs=FS,
        window=window,
        nperseg=window_buckets,
        noverlap=noverlap,
        boundary=None,
        detrend=WELCH_DETREND,
    )
    if zxx.size == 0 or zxx.shape[1] == 0:
        return StftMatrixResult(
            **{
                **empty.__dict__,
                "input_buckets": int(series.size),
                "gap_fraction": zero_frac,
                "empty_reason": "no_windows",
                "truncated_input": truncated_input,
            }
        )

    power = np.abs(zxx) ** 2
    # Mark non-finite STFT bins as missing (never coerce to 0.0).
    power = power.astype(np.float64, copy=True)
    bad = ~np.isfinite(power)
    power_obj: np.ndarray = power.astype(object)
    power_obj[bad] = None

    freq_idx = _subsample_indices(power.shape[0], max_freq_bins)
    time_idx = _subsample_indices(power.shape[1], max_time_bins)
    capped = bool(
        power.shape[0] > max_freq_bins or power.shape[1] > max_time_bins
    )

    freqs_out = [float(freqs[i]) for i in freq_idx]
    periods = [_period_hours(f, bucket_seconds) for f in freqs_out]

    bucket_delta = timedelta(seconds=bucket_seconds)
    origin = _ensure_utc(starts[0])
    time_starts: list[datetime | None] = []
    for col in time_idx:
        # SciPy STFT times are in samples (buckets) from series start when fs=1.
        sample = float(times[col]) if col < len(times) else float(col)
        if not np.isfinite(sample):
            time_starts.append(None)
            continue
        bucket_i = int(round(sample))
        if bucket_i < 0 or bucket_i >= len(starts):
            time_starts.append(origin + bucket_delta * sample)
        else:
            time_starts.append(_ensure_utc(starts[bucket_i]))

    matrix: list[list[float | None]] = []
    for fi in freq_idx:
        row: list[float | None] = []
        for ti in time_idx:
            cell = power_obj[fi, ti]
            if cell is None:
                row.append(None)
            else:
                row.append(float(cell))
        matrix.append(row)

    return StftMatrixResult(
        freqs=freqs_out,
        period_hours=periods,
        time_starts=time_starts,
        power=matrix,
        n_freq=len(freqs_out),
        n_time=len(time_starts),
        capped=capped,
        truncated_input=truncated_input,
        empty_reason=None,
        window_buckets=window_buckets,
        step_buckets=step_buckets,
        bucket_seconds=bucket_seconds,
        input_buckets=int(series.size),
        gap_fraction=zero_frac,
    )


def stft_matrix_to_dict(result: StftMatrixResult, *, entity_id: str) -> dict[str, Any]:
    return {
        "entity_id": entity_id,
        "bucket_seconds": result.bucket_seconds,
        "window_buckets": result.window_buckets,
        "step_buckets": result.step_buckets,
        "freqs": result.freqs,
        "period_hours": result.period_hours,
        "time_starts": [
            ts.isoformat() if isinstance(ts, datetime) else None
            for ts in result.time_starts
        ],
        "power": result.power,
        "n_freq": result.n_freq,
        "n_time": result.n_time,
        "capped": result.capped,
        "truncated_input": result.truncated_input,
        "empty_reason": result.empty_reason,
        "input_buckets": result.input_buckets,
        "gap_fraction": result.gap_fraction,
        "cap_max_freq": STFT_UI_MAX_FREQ_BINS,
        "cap_max_time": STFT_UI_MAX_TIME_BINS,
    }
