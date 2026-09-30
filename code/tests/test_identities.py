"""R5 stable UUID5 identities (ingest_row_id, event_id, cluster_run_id)."""

from __future__ import annotations

from datetime import datetime, timezone

from src.detectors.spectral.clustering import stable_cluster_run_id
from src.detectors.spectral.features import EntitySpectralFeatures
from src.identities import stable_event_id, stable_ingest_row_id


def test_ingest_row_id_stable_for_same_file_hash_and_line() -> None:
    first = stable_ingest_row_id("abc123", 7)
    second = stable_ingest_row_id("abc123", 7)
    assert first == second
    assert first != stable_ingest_row_id("abc123", 8)
    assert first != stable_ingest_row_id("abc124", 7)


def test_event_id_is_positive_bigint_and_stable() -> None:
    first = stable_event_id("empty", "deadbeef", 3, "/tmp/auth.log")
    second = stable_event_id("empty", "deadbeef", 3, "/tmp/auth.log")
    assert first == second
    assert first > 0
    assert first < 2**63
    assert first != stable_event_id("other", "deadbeef", 3, "/tmp/auth.log")


def test_cluster_run_id_ignores_computed_at() -> None:
    ts_a = datetime(2024, 1, 1, tzinfo=timezone.utc)
    ts_b = datetime(2025, 6, 1, tzinfo=timezone.utc)
    rows_a = [
        EntitySpectralFeatures("e1", 24.0, 0.4, 2.0, 10.0, ts_a),
        EntitySpectralFeatures("e2", 12.0, 0.2, 1.5, 8.0, ts_a),
    ]
    rows_b = [
        EntitySpectralFeatures("e2", 12.0, 0.2, 1.5, 8.0, ts_b),
        EntitySpectralFeatures("e1", 24.0, 0.4, 2.0, 10.0, ts_b),
    ]
    kwargs = {
        "cluster_eps": 1.2,
        "cluster_min_samples": 2,
        "cluster_min_entities": 20,
    }
    assert stable_cluster_run_id(rows_a, **kwargs) == stable_cluster_run_id(
        rows_b, **kwargs
    )
    assert stable_cluster_run_id(rows_a, **kwargs) != stable_cluster_run_id(
        rows_a, cluster_eps=2.0, cluster_min_samples=2, cluster_min_entities=20
    )
