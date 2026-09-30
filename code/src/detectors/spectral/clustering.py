"""DBSCAN peer-group clustering over spectral features (SDD §7.5.7)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from src.detectors.spectral.features import EntitySpectralFeatures
from src.identities import CLUSTER_RUN_NS, uuid5_str


def stable_cluster_run_id(
    feature_rows: Sequence[EntitySpectralFeatures],
    *,
    cluster_eps: float,
    cluster_min_samples: int,
    cluster_min_entities: int,
) -> str:
    """UUID5 of sorted feature fingerprint + clustering knobs (not uuid4)."""
    hasher_parts = [
        f"eps={cluster_eps!r}",
        f"min_samples={cluster_min_samples}",
        f"min_entities={cluster_min_entities}",
    ]
    for row in sorted(feature_rows, key=lambda item: item.entity_id):
        hasher_parts.append(
            "|".join(
                (
                    row.entity_id,
                    repr(row.dominant_period_hours),
                    repr(row.dominant_power_frac),
                    repr(row.spectral_entropy),
                    repr(row.total_power),
                )
            )
        )
    return uuid5_str(CLUSTER_RUN_NS, "\n".join(hasher_parts))


@dataclass(frozen=True)
class EntityClusterAssignment:
    entity_id: str
    cluster_run_id: str
    cluster_id: int
    computed_at: datetime


def cluster_entities(
    feature_rows: Sequence[EntitySpectralFeatures],
    *,
    cluster_eps: float,
    cluster_min_samples: int,
    cluster_run_id: str,
    computed_at: datetime | None = None,
) -> list[EntityClusterAssignment]:
    """Cluster entities by compact spectral feature vectors."""
    if not feature_rows:
        return []
    if cluster_min_samples <= 0:
        raise ValueError("cluster_min_samples must be positive")

    ts = computed_at or datetime.now(timezone.utc)
    matrix = np.array(
        [
            [
                row.dominant_period_hours,
                row.dominant_power_frac,
                row.spectral_entropy,
                row.total_power,
            ]
            for row in feature_rows
        ],
        dtype=np.float64,
    )

    if matrix.shape[0] == 1:
        return [
            EntityClusterAssignment(
                entity_id=feature_rows[0].entity_id,
                cluster_run_id=cluster_run_id,
                cluster_id=0,
                computed_at=ts,
            )
        ]

    scaled = StandardScaler().fit_transform(matrix)
    labels = DBSCAN(eps=cluster_eps, min_samples=cluster_min_samples).fit_predict(
        scaled
    )

    return [
        EntityClusterAssignment(
            entity_id=row.entity_id,
            cluster_run_id=cluster_run_id,
            cluster_id=int(label),
            computed_at=ts,
        )
        for row, label in zip(feature_rows, labels, strict=True)
    ]
