"""Unit tests for cluster_entities."""

from __future__ import annotations

from datetime import datetime, timezone

from src.detectors.spectral.clustering import cluster_entities
from src.detectors.spectral.features import EntitySpectralFeatures

UTC = timezone.utc
RUN_ID = "test-run"


def _feature(
    entity_id: str,
    period: float,
    power_frac: float,
    entropy: float,
    total: float,
) -> EntitySpectralFeatures:
    return EntitySpectralFeatures(
        entity_id=entity_id,
        dominant_period_hours=period,
        dominant_power_frac=power_frac,
        spectral_entropy=entropy,
        total_power=total,
        computed_at=datetime(2024, 1, 1, tzinfo=UTC),
    )


def test_planted_outlier_gets_cluster_minus_one() -> None:
    peers = [
        _feature(f"peer{i}", 24.0, 0.4, 2.5, 100.0 + i)
        for i in range(5)
    ]
    outlier = _feature("outlier", 500.0, 0.01, 0.1, 9999.0)
    assignments = cluster_entities(
        peers + [outlier],
        cluster_eps=1.2,
        cluster_min_samples=2,
        cluster_run_id=RUN_ID,
    )
    by_entity = {row.entity_id: row.cluster_id for row in assignments}
    assert by_entity["outlier"] == -1
    assert any(cid >= 0 for eid, cid in by_entity.items() if eid != "outlier")


def test_extreme_eps_does_not_crash() -> None:
    rows = [
        _feature("a", 1.0, 0.2, 1.0, 10.0),
        _feature("b", 2.0, 0.3, 1.1, 11.0),
    ]
    assignments = cluster_entities(
        rows,
        cluster_eps=100.0,
        cluster_min_samples=2,
        cluster_run_id=RUN_ID,
    )
    assert len(assignments) == 2
