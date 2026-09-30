"""Unit tests for compute_baseline."""

from __future__ import annotations

from tests.fixtures.synthetic_entities import generate_periodic_counts
from src.detectors.spectral.baseline import compute_baseline

BUCKET_SECONDS = 600
ENTITY = "alice"


def test_periodic_baseline_normalization() -> None:
    period_buckets = 144
    _, counts = generate_periodic_counts(
        n_buckets=2000,
        period_buckets=period_buckets,
        bucket_seconds=BUCKET_SECONDS,
    )
    baseline = compute_baseline(
        counts,
        entity_id=ENTITY,
        bucket_seconds=BUCKET_SECONDS,
        baseline_max_nperseg=1440,
    )
    assert baseline is not None
    assert abs(sum(baseline.psd_norm) - 1.0) < 1e-6
    assert baseline.nperseg <= 1440


def test_short_series_returns_none() -> None:
    _, counts = generate_periodic_counts(
        n_buckets=3,
        period_buckets=2,
        bucket_seconds=BUCKET_SECONDS,
    )
    assert (
        compute_baseline(
            counts,
            entity_id=ENTITY,
            bucket_seconds=BUCKET_SECONDS,
            baseline_max_nperseg=1440,
        )
        is None
    )


def test_nperseg_cap_respected() -> None:
    _, counts = generate_periodic_counts(
        n_buckets=5000,
        period_buckets=200,
        bucket_seconds=BUCKET_SECONDS,
    )
    baseline = compute_baseline(
        counts,
        entity_id=ENTITY,
        bucket_seconds=BUCKET_SECONDS,
        baseline_max_nperseg=256,
    )
    assert baseline is not None
    assert baseline.nperseg <= 256


def test_fft_window_changes_psd_shape() -> None:
    period_buckets = 144
    _, counts = generate_periodic_counts(
        n_buckets=2000,
        period_buckets=period_buckets,
        bucket_seconds=BUCKET_SECONDS,
    )
    hann = compute_baseline(
        counts,
        entity_id=ENTITY,
        bucket_seconds=BUCKET_SECONDS,
        baseline_max_nperseg=1440,
        window="hann",
    )
    boxcar = compute_baseline(
        counts,
        entity_id=ENTITY,
        bucket_seconds=BUCKET_SECONDS,
        baseline_max_nperseg=1440,
        window="boxcar",
    )
    assert hann is not None
    assert boxcar is not None
    assert hann.psd_norm != boxcar.psd_norm
