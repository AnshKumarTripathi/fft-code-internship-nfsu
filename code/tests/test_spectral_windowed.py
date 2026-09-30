"""Unit tests for windowed_deviation including §7.5.5 regressions."""

from __future__ import annotations

import numpy as np

from tests.fixtures.synthetic_entities import (
    generate_periodic_counts,
    inject_rhythm_attack,
)
from src.detectors.spectral.baseline import compute_baseline
from src.detectors.spectral.windowed import (
    compare_shape_js_mismatched_resolution,
    recompute_baseline_shape_at_nperseg,
    windowed_deviation,
)

BUCKET_SECONDS = 600
ENTITY = "alice"
Z_THRESHOLD = 4.0


def _daily_period_buckets() -> int:
    return 24 * 3600 // BUCKET_SECONDS


def _build_attacked_series(n_buckets: int = 5000):
    period = _daily_period_buckets()
    starts, counts = generate_periodic_counts(
        n_buckets=n_buckets,
        period_buckets=period,
        bucket_seconds=BUCKET_SECONDS,
    )
    attacked = inject_rhythm_attack(
        counts,
        start=n_buckets // 2,
        length=period * 2,
        new_period_buckets=max(4, period // 6),
    )
    baseline = compute_baseline(
        attacked,
        entity_id=ENTITY,
        bucket_seconds=BUCKET_SECONDS,
        baseline_max_nperseg=1440,
    )
    assert baseline is not None
    return starts, attacked, baseline


def test_too_short_window_fails_to_separate_attack() -> None:
    starts, counts, baseline = _build_attacked_series()
    period = _daily_period_buckets()
    short_window = max(4, period // 4)

    rows = windowed_deviation(
        counts,
        starts,
        baseline,
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=short_window,
        step_buckets=max(1, short_window // 3),
        z_threshold=Z_THRESHOLD,
    )
    assert rows

    attack_start = len(counts) // 2
    attack_rows = [
        i
        for i, row in enumerate(rows)
        if attack_start <= i * max(1, short_window // 3) <= attack_start + period
    ]
    normal_rows = [i for i in range(len(rows)) if i not in attack_rows[: max(1, len(attack_rows))]]

    if attack_rows and normal_rows:
        attack_shape = [rows[i].shape_js_z for i in attack_rows]
        normal_shape = [rows[i].shape_js_z for i in normal_rows[:50]]
        separation = max(attack_shape) - float(np.median(normal_shape))
        assert separation < Z_THRESHOLD


def test_good_window_separates_attack() -> None:
    starts, counts, baseline = _build_attacked_series()
    period = _daily_period_buckets()
    good_window = period * 3

    rows = windowed_deviation(
        counts,
        starts,
        baseline,
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=good_window,
        step_buckets=max(1, good_window // 3),
        z_threshold=Z_THRESHOLD,
    )
    assert rows
    assert any(row.flagged for row in rows)
    assert max(row.shape_js_z for row in rows) > 0.0


def test_resolution_mismatch_elevated_js_rematch_near_zero() -> None:
    period = _daily_period_buckets()
    _, counts = generate_periodic_counts(
        n_buckets=3000,
        period_buckets=period,
        bucket_seconds=BUCKET_SECONDS,
    )
    window_buckets = period
    long_nperseg = period * 4

    mismatched = compare_shape_js_mismatched_resolution(
        counts, window_buckets, long_nperseg
    )
    from scipy.signal import welch
    from scipy.spatial.distance import jensenshannon

    _, rematched = recompute_baseline_shape_at_nperseg(counts, window_buckets)
    segment = counts[:window_buckets]
    _, window_psd = welch(
        segment,
        fs=1.0,
        nperseg=window_buckets,
        noverlap=window_buckets // 2,
    )
    window_shape = window_psd / float(np.sum(window_psd))
    matched = float(jensenshannon(window_shape[: rematched.size], rematched))

    assert mismatched > matched
    assert matched < 0.15


def test_flag_or_logic_energy_only() -> None:
    period = _daily_period_buckets()
    starts, counts = generate_periodic_counts(
        n_buckets=4000,
        period_buckets=period,
        bucket_seconds=BUCKET_SECONDS,
    )
    burst_center = 2000
    counts[burst_center : burst_center + 50] = 100.0

    baseline = compute_baseline(
        counts,
        entity_id=ENTITY,
        bucket_seconds=BUCKET_SECONDS,
        baseline_max_nperseg=1440,
    )
    assert baseline is not None

    rows = windowed_deviation(
        counts,
        starts,
        baseline,
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=period * 3,
        step_buckets=period,
        z_threshold=2.0,
    )
    assert any(row.flagged for row in rows)
