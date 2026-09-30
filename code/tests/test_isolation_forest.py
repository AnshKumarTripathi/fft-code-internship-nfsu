"""Unit tests for IsolationForest template-sequence scoring."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.detectors.ml.isolation_forest import (
    MIN_EVENTS,
    TemplateWindow,
    fit_score_windows,
    slice_entity_windows,
)


def _ts(hour: int, minute: int = 0) -> datetime:
    return datetime(2024, 1, 1, hour, minute, tzinfo=timezone.utc)


def test_slice_entity_windows_skips_short_and_aligns() -> None:
    window_seconds = 3600
    events = [
        (_ts(0, 0), "A"),
        (_ts(0, 1), "B"),
        (_ts(0, 2), "A"),
        (_ts(0, 3), "B"),
        # only 4 events in first hour — skipped when min_events=5
        (_ts(1, 0), "A"),
        (_ts(1, 1), "B"),
        (_ts(1, 2), "A"),
        (_ts(1, 3), "B"),
        (_ts(1, 4), "A"),
    ]
    windows = slice_entity_windows(
        events,
        entity_id="alice",
        window_seconds=window_seconds,
        min_events=MIN_EVENTS,
    )
    assert len(windows) == 1
    assert windows[0].window_start == _ts(1, 0)
    assert windows[0].window_end == _ts(2, 0)
    assert len(windows[0].template_ids) == 5


def test_weird_sequences_score_higher_than_normal() -> None:
    """Repetitive ABAB… windows vs rare-template bursts."""
    normal_seq = tuple(["A", "B"] * 10)  # 20 events
    weird_seq = tuple(["X", "Y", "Z", "Q", "R"] * 4)  # rare templates

    windows: list[TemplateWindow] = []
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    # Many normal windows
    for i in range(40):
        windows.append(
            TemplateWindow(
                entity_id="normal",
                window_start=start + timedelta(hours=i),
                window_end=start + timedelta(hours=i + 1),
                template_ids=normal_seq,
            )
        )
    # Few weird windows
    weird_indices = []
    for j in range(2):
        idx = 40 + j
        weird_indices.append(idx)
        windows.append(
            TemplateWindow(
                entity_id="weird",
                window_start=start + timedelta(hours=idx),
                window_end=start + timedelta(hours=idx + 1),
                template_ids=weird_seq,
            )
        )

    scores = fit_score_windows(windows, contamination=0.05)
    assert len(scores) == len(windows)

    normal_scores = [s.model_score for s in scores if s.entity_id == "normal"]
    weird_scores = [s.model_score for s in scores if s.entity_id == "weird"]

    assert weird_scores
    assert normal_scores
    assert sum(weird_scores) / len(weird_scores) > sum(normal_scores) / len(
        normal_scores
    )

    # At least one weird window should be among the highest scores
    top = sorted(scores, key=lambda s: s.model_score, reverse=True)[:3]
    assert any(s.entity_id == "weird" for s in top)
