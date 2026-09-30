"""R1 analytic ground-truth and numeric edge contracts for the spectral path."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from src.detectors.spectral.baseline import SpectralBaseline, compute_baseline
from src.detectors.spectral.features import spectral_summary_features
from src.detectors.spectral.persist import SpectralEntityWork, compute_entity_spectral
from src.detectors.spectral.series import MIN_WELCH_LENGTH, nyquist_period_seconds
from src.detectors.spectral.windowed import windowed_deviation
from src.timeseries.bucketing import bucket_events
from tests.fixtures.synthetic_entities import generate_periodic_counts

BUCKET_SECONDS = 600
ENTITY = "alice"
Z_THRESHOLD = 4.0
UTC = timezone.utc
DAILY_PERIOD_BUCKETS = 24 * 3600 // BUCKET_SECONDS
FIXED_AT = datetime(2024, 1, 1, tzinfo=UTC)


def _baseline_kwargs() -> dict:
    return {
        "entity_id": ENTITY,
        "bucket_seconds": BUCKET_SECONDS,
        "baseline_max_nperseg": 1440,
        "computed_at": FIXED_AT,
    }


def _dummy_baseline() -> SpectralBaseline:
    return SpectralBaseline(
        entity_id=ENTITY,
        computed_at=FIXED_AT,
        bucket_seconds=BUCKET_SECONDS,
        nperseg=MIN_WELCH_LENGTH,
        freq_grid=[0.0, 0.5],
        psd=[1.0, 0.0],
        psd_norm=[1.0, 0.0],
    )


def _dominant_ac_frequency(baseline: SpectralBaseline) -> float:
    freqs = np.asarray(baseline.freq_grid, dtype=np.float64)
    psd_norm = np.asarray(baseline.psd_norm, dtype=np.float64)
    search = psd_norm.copy()
    search[0] = -1.0
    return float(freqs[int(np.argmax(search))])


def test_pure_sinusoid_has_one_clean_spectral_peak() -> None:
    """Raised sine of period P buckets has its AC peak at f = 1/P cycles/bucket.

    Frequency resolution is ``df = 1 / nperseg``. The recovered bin must lie
    within one bin of the analytic frequency.
    """
    period_buckets = DAILY_PERIOD_BUCKETS
    _, counts = generate_periodic_counts(
        n_buckets=2000,
        period_buckets=period_buckets,
        bucket_seconds=BUCKET_SECONDS,
    )
    baseline = compute_baseline(counts, **_baseline_kwargs())
    assert baseline is not None
    assert np.all(np.isfinite(baseline.psd_norm))

    expected_freq = 1.0 / period_buckets
    df = 1.0 / baseline.nperseg
    recovered = _dominant_ac_frequency(baseline)
    assert abs(recovered - expected_freq) <= df

    features = spectral_summary_features(baseline, computed_at=FIXED_AT)
    expected_hours = period_buckets * BUCKET_SECONDS / 3600.0
    assert features.dominant_period_hours == pytest.approx(expected_hours, rel=0.0, abs=expected_hours * df / expected_freq)


def test_all_zero_series_returns_no_baseline() -> None:
    counts = np.zeros(2000, dtype=np.float64)
    assert compute_baseline(counts, **_baseline_kwargs()) is None


def test_constant_series_returns_no_baseline_and_does_not_flag() -> None:
    """Welch mean-removes each segment, so a constant has no oscillatory mass.

    No baseline is written, and windowed scoring on the same series yields no
    flags (empty result, not a false peak at ``z_threshold``).
    """
    n_buckets = 2000
    starts, _ = generate_periodic_counts(
        n_buckets=n_buckets,
        period_buckets=DAILY_PERIOD_BUCKETS,
        bucket_seconds=BUCKET_SECONDS,
    )
    counts = np.full(n_buckets, 5.0, dtype=np.float64)
    assert compute_baseline(counts, **_baseline_kwargs()) is None

    rows = windowed_deviation(
        counts,
        starts,
        _dummy_baseline(),
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=DAILY_PERIOD_BUCKETS * 3,
        step_buckets=DAILY_PERIOD_BUCKETS,
        z_threshold=Z_THRESHOLD,
    )
    assert rows == [] or all(not row.flagged for row in rows)


def test_stationary_sine_does_not_flag_interior_windows() -> None:
    """A stable raised sine is not an attack. The final STFT column can be a
    short remainder with inflated energy_z; interior windows must stay quiet.
    """
    starts, counts = generate_periodic_counts(
        n_buckets=4000,
        period_buckets=DAILY_PERIOD_BUCKETS,
        bucket_seconds=BUCKET_SECONDS,
    )
    baseline = compute_baseline(counts, **_baseline_kwargs())
    assert baseline is not None
    rows = windowed_deviation(
        counts,
        starts,
        baseline,
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=DAILY_PERIOD_BUCKETS * 3,
        step_buckets=DAILY_PERIOD_BUCKETS,
        z_threshold=Z_THRESHOLD,
    )
    assert len(rows) > 2
    interior = rows[:-1]
    assert all(not row.flagged for row in interior)


def test_two_tone_series_recovers_both_analytic_peaks() -> None:
    period_a = DAILY_PERIOD_BUCKETS
    period_b = period_a // 3
    n_buckets = 3000
    phase = np.arange(n_buckets, dtype=np.float64)
    counts = np.sin(2 * np.pi * phase / period_a) + np.sin(2 * np.pi * phase / period_b)
    baseline = compute_baseline(counts, **_baseline_kwargs())
    assert baseline is not None

    freqs = np.asarray(baseline.freq_grid, dtype=np.float64)
    psd_norm = np.asarray(baseline.psd_norm, dtype=np.float64)
    search = psd_norm.copy()
    search[0] = -1.0
    top_two = set(np.argsort(search)[-2:])
    df = 1.0 / baseline.nperseg
    recovered = [float(freqs[i]) for i in top_two]
    for expected in (1.0 / period_a, 1.0 / period_b):
        assert any(abs(freq - expected) <= df for freq in recovered)


def test_empty_and_short_series_return_none_without_raising() -> None:
    assert compute_baseline(np.array([], dtype=np.float64), **_baseline_kwargs()) is None
    assert compute_baseline(np.array([1.0, 2.0, 3.0]), **_baseline_kwargs()) is None
    short = np.zeros(MIN_WELCH_LENGTH - 1, dtype=np.float64)
    assert compute_baseline(short, **_baseline_kwargs()) is None


def test_empty_entity_windowed_returns_empty_without_raising() -> None:
    assert (
        windowed_deviation(
            np.array([], dtype=np.float64),
            [],
            _dummy_baseline(),
            bucket_seconds=BUCKET_SECONDS,
            window_buckets=DAILY_PERIOD_BUCKETS * 3,
            step_buckets=DAILY_PERIOD_BUCKETS,
            z_threshold=Z_THRESHOLD,
        )
        == []
    )


def test_series_shorter_than_window_returns_empty() -> None:
    starts, counts = generate_periodic_counts(
        n_buckets=20,
        period_buckets=8,
        bucket_seconds=BUCKET_SECONDS,
    )
    rows = windowed_deviation(
        counts,
        starts,
        _dummy_baseline(),
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=72,
        step_buckets=24,
        z_threshold=Z_THRESHOLD,
    )
    assert rows == []


@pytest.mark.parametrize("poison", [np.nan, np.inf, -np.inf])
def test_nonfinite_counts_do_not_produce_baseline_or_flags(poison: float) -> None:
    starts, counts = generate_periodic_counts(
        n_buckets=2000,
        period_buckets=DAILY_PERIOD_BUCKETS,
        bucket_seconds=BUCKET_SECONDS,
    )
    poisoned = counts.copy()
    poisoned[10] = poison

    assert compute_baseline(poisoned, **_baseline_kwargs()) is None

    clean = compute_baseline(counts, **_baseline_kwargs())
    assert clean is not None
    rows = windowed_deviation(
        poisoned,
        starts,
        clean,
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=DAILY_PERIOD_BUCKETS * 3,
        step_buckets=DAILY_PERIOD_BUCKETS,
        z_threshold=Z_THRESHOLD,
    )
    assert rows == []
    assert not any(row.flagged for row in rows)


def test_nonfinite_entity_is_skipped_not_flagged() -> None:
    starts, counts = generate_periodic_counts(
        n_buckets=500,
        period_buckets=DAILY_PERIOD_BUCKETS,
        bucket_seconds=BUCKET_SECONDS,
    )
    event_counts = tuple(float(v) for v in counts)
    poisoned = event_counts[:10] + (float("nan"),) + event_counts[11:]
    work = SpectralEntityWork(
        entity_id=ENTITY,
        bucket_starts=tuple(starts),
        event_counts=poisoned,
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=DAILY_PERIOD_BUCKETS * 3,
        step_buckets=DAILY_PERIOD_BUCKETS,
        z_threshold=Z_THRESHOLD,
        baseline_max_nperseg=1440,
        fft_window="hann",
        min_welch_length=4,
        max_buckets_per_entity=100_000,
    )
    result = compute_entity_spectral(work)
    assert result.skip_reason == "non_finite"
    assert result.baseline is None
    assert result.window_rows == ()


def test_sub_bucket_beacon_cannot_appear_as_spectral_peak() -> None:
    """Nyquist period is two buckets (20 minutes at the default 600 s width).

    A perfectly regular 60-second beacon lands as a near-constant count per
    10-minute bin (~10 events). After mean removal there is no AC peak at
    60 seconds — that frequency is above Nyquist and is not in the series.
    """
    start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    beacon_seconds = 60
    n_events = 7 * 24 * 60
    timestamps = [
        start + timedelta(seconds=beacon_seconds * i) for i in range(n_events)
    ]
    rows = bucket_events(timestamps, BUCKET_SECONDS, entity_id=ENTITY)
    counts = np.array([row.event_count for row in rows], dtype=np.float64)
    assert np.all(np.isfinite(counts))

    baseline = compute_baseline(counts, **_baseline_kwargs())
    beacon_hours = beacon_seconds / 3600.0
    nyquist_hours = nyquist_period_seconds(BUCKET_SECONDS) / 3600.0
    if baseline is None:
        return
    features = spectral_summary_features(baseline, computed_at=FIXED_AT)
    assert abs(features.dominant_period_hours - beacon_hours) > nyquist_hours / 2


def test_internal_zero_fill_is_silence_not_nan() -> None:
    """Gaps between first and last event are stored as 0.0, not missing/NaN.

    Spectral code therefore cannot tell 'no logs arrived' from 'no activity'.
    """
    base = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    rows = bucket_events(
        [base, base + timedelta(seconds=3600)],
        BUCKET_SECONDS,
        entity_id=ENTITY,
    )
    counts = [row.event_count for row in rows]
    assert any(count == 0.0 for count in counts)
    assert all(np.isfinite(count) for count in counts)
    assert not any(count != count for count in counts)


def test_zero_gap_in_periodic_series_stays_finite_and_does_not_invent_nan_peak() -> None:
    starts, counts = generate_periodic_counts(
        n_buckets=2000,
        period_buckets=DAILY_PERIOD_BUCKETS,
        bucket_seconds=BUCKET_SECONDS,
    )
    gapped = counts.copy()
    gapped[800:1100] = 0.0
    assert np.all(np.isfinite(gapped))

    baseline = compute_baseline(gapped, **_baseline_kwargs())
    assert baseline is not None
    assert np.all(np.isfinite(baseline.psd_norm))
    features = spectral_summary_features(baseline, computed_at=FIXED_AT)
    expected_hours = DAILY_PERIOD_BUCKETS * BUCKET_SECONDS / 3600.0
    assert abs(features.dominant_period_hours - expected_hours) < 2.0
