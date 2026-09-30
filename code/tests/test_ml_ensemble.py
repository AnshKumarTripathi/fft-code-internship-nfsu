"""Unit tests for IF + AE ML ensemble fusion."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.detectors.ml.ensemble import fuse_ml_window_scores
from src.detectors.ml.isolation_forest import MlWindowScore

UTC = timezone.utc


def _row(
    *,
    entity: str = "u1",
    start: datetime | None = None,
    score: float = 1.0,
    flagged: bool = False,
    mad_z: float | None = 4.5,
    snapshot: str | None = "snap",
    attribution: dict | None = None,
) -> MlWindowScore:
    window_start = start or datetime(2024, 1, 1, tzinfo=UTC)
    return MlWindowScore(
        entity_id=entity,
        window_start=window_start,
        window_end=datetime(2024, 1, 1, 1, tzinfo=UTC),
        model_score=score,
        flagged=flagged,
        model_snapshot_id=snapshot,
        mad_z=mad_z,
        attribution=attribution,
    )


def test_majority_requires_both_for_two_models() -> None:
    start = datetime(2024, 1, 1, tzinfo=UTC)
    if_rows = [
        _row(start=start, score=9.0, flagged=True, snapshot="if1"),
        _row(
            start=datetime(2024, 1, 1, 1, tzinfo=UTC),
            score=2.0,
            flagged=False,
            snapshot="if1",
        ),
    ]
    ae_rows = [
        _row(start=start, score=3.0, flagged=False, snapshot="ae1"),
        _row(
            start=datetime(2024, 1, 1, 1, tzinfo=UTC),
            score=8.0,
            flagged=True,
            snapshot="ae1",
        ),
    ]
    fused = fuse_ml_window_scores(
        {"isolation_forest": if_rows, "autoencoder": ae_rows},
        fusion="majority",
    )
    assert len(fused) == 2
    assert fused[0].flagged is False
    assert fused[1].flagged is False
    assert fused[0].attribution["ensemble"]["votes"] == {
        "autoencoder": False,
        "isolation_forest": True,
    }


def test_majority_flags_when_both_agree() -> None:
    start = datetime(2024, 1, 1, tzinfo=UTC)
    fused = fuse_ml_window_scores(
        {
            "isolation_forest": [
                _row(start=start, score=9.0, flagged=True, snapshot="if1")
            ],
            "autoencoder": [
                _row(start=start, score=7.0, flagged=True, snapshot="ae1")
            ],
        },
        fusion="majority",
    )
    assert len(fused) == 1
    assert fused[0].flagged is True
    assert fused[0].model_score == 9.0
    assert fused[0].attribution["ensemble"]["fusion"] == "majority"
    assert fused[0].attribution["ensemble"]["snapshot_ids"]["autoencoder"] == "ae1"


def test_any_flags_on_single_vote() -> None:
    start = datetime(2024, 1, 1, tzinfo=UTC)
    fused = fuse_ml_window_scores(
        {
            "isolation_forest": [_row(start=start, flagged=True, score=5.0)],
            "autoencoder": [_row(start=start, flagged=False, score=1.0)],
        },
        fusion="any",
    )
    assert fused[0].flagged is True


def test_unanimous_clears_on_disagreement() -> None:
    start = datetime(2024, 1, 1, tzinfo=UTC)
    fused = fuse_ml_window_scores(
        {
            "isolation_forest": [_row(start=start, flagged=True)],
            "autoencoder": [_row(start=start, flagged=False)],
        },
        fusion="unanimous",
    )
    assert fused[0].flagged is False


def test_fusion_rejects_unknown_policy() -> None:
    start = datetime(2024, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="fusion"):
        fuse_ml_window_scores(
            {
                "isolation_forest": [_row(start=start)],
                "autoencoder": [_row(start=start)],
            },
            fusion="weighted",
        )
