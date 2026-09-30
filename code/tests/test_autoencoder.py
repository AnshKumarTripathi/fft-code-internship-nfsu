"""Unit tests for Phase 53 sequence-window autoencoder."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.detectors.ml.autoencoder import (
    fit_autoencoder_bundle,
    fit_score_autoencoder_windows,
    score_windows_with_autoencoder,
)
from src.detectors.ml.isolation_forest import TemplateWindow
from src.detectors.ml.snapshots import (
    load_autoencoder_snapshot,
    save_autoencoder_snapshot,
)


def _windows(n: int = 24) -> list[TemplateWindow]:
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    rows: list[TemplateWindow] = []
    for i in range(n):
        templates = ("t_a", "t_b", "t_a", "t_b", "t_a")
        if i == n - 1:
            templates = ("t_rare",) * 5
        rows.append(
            TemplateWindow(
                entity_id="user:bob",
                window_start=start + timedelta(hours=i),
                window_end=start + timedelta(hours=i + 1),
                template_ids=templates,
            )
        )
    return rows


def test_autoencoder_fit_score_deterministic() -> None:
    windows = _windows()
    a = fit_score_autoencoder_windows(windows, mad_k=4.0, flagging="mad_threshold")
    b = fit_score_autoencoder_windows(windows, mad_k=4.0, flagging="mad_threshold")
    assert len(a) == len(b) == len(windows)
    assert all(row.model_score >= 0.0 for row in a)
    assert [row.model_score for row in a] == [row.model_score for row in b]


def test_autoencoder_snapshot_round_trip(tmp_path) -> None:
    windows = _windows()
    fitted = fit_autoencoder_bundle(windows)
    assert fitted is not None
    bundle, raw_scores, residuals = fitted
    snapshot_id = save_autoencoder_snapshot(tmp_path, bundle)
    loaded = load_autoencoder_snapshot(tmp_path, snapshot_id)
    rows = score_windows_with_autoencoder(
        windows,
        loaded,
        flagging="mad_threshold",
        mad_k=4.0,
        model_snapshot_id=snapshot_id,
    )
    assert len(rows) == len(windows)
    assert all(row.model_snapshot_id == snapshot_id for row in rows)
    # Scores should be finite and non-negative
    assert all(row.model_score >= 0.0 for row in rows)
    assert len(raw_scores) == len(residuals)


def test_autoencoder_attribution_on_flagged() -> None:
    windows = _windows(30)
    rows = fit_score_autoencoder_windows(
        windows, flagging="mad_threshold", mad_k=0.5, top_k_features=3
    )
    flagged = [row for row in rows if row.flagged]
    assert flagged, "expected at least one flag at mad_k=0.5"
    assert flagged[0].attribution is not None
    features = flagged[0].attribution.get("top_contributing_features") or []
    assert features
    assert "name" in features[0]
    assert "contribution" in features[0]
