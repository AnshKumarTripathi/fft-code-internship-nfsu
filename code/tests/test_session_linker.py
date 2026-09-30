"""Unit tests for session_linker."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.correlation.merge_scores import AnomalyEvent, make_anomaly_id
from src.correlation.session_linker import (
    ParsedEventRef,
    attach_anomalies_to_sessions,
    build_sessions,
)


def _ts(hour: int, minute: int = 0) -> datetime:
    return datetime(2024, 1, 1, hour, minute, tzinfo=timezone.utc)


def test_session_gap_splits() -> None:
    events = [
        ParsedEventRef(1, "alice", _ts(10, 0), {}),
        ParsedEventRef(2, "alice", _ts(10, 10), {}),
        ParsedEventRef(3, "alice", _ts(12, 0), {}),  # >30 min gap
    ]
    sessions = build_sessions(events, session_gap_minutes=30)
    assert len(sessions) == 2
    assert sessions[0].event_ids == (1, 2)
    assert sessions[1].event_ids == (3,)


def test_attach_anomaly_to_overlapping_session() -> None:
    events = [
        ParsedEventRef(1, "alice", _ts(10, 0), {}),
        ParsedEventRef(2, "alice", _ts(10, 20), {}),
        ParsedEventRef(3, "alice", _ts(10, 40), {}),
    ]
    sessions = build_sessions(events, session_gap_minutes=30)
    anomaly = AnomalyEvent(
        anomaly_id=make_anomaly_id("statistical", "alice", _ts(10, 0)),
        entity_id="alice",
        window_start=_ts(10, 0),
        window_end=_ts(11, 0),
        source_detector="statistical",
        score=4.0,
        metadata={},
    )
    attached = attach_anomalies_to_sessions([anomaly], sessions)
    assert attached[anomaly.anomaly_id]
    assert attached[anomaly.anomaly_id][0] == sessions[0].session_id


def test_far_anomaly_not_attached() -> None:
    events = [
        ParsedEventRef(1, "alice", _ts(1, 0), {}),
        ParsedEventRef(2, "alice", _ts(1, 10), {}),
    ]
    sessions = build_sessions(events, session_gap_minutes=30)
    anomaly = AnomalyEvent(
        anomaly_id=make_anomaly_id("statistical", "alice", _ts(20, 0)),
        entity_id="alice",
        window_start=_ts(20, 0),
        window_end=_ts(21, 0),
        source_detector="statistical",
        score=4.0,
        metadata={},
    )
    attached = attach_anomalies_to_sessions([anomaly], sessions)
    assert attached[anomaly.anomaly_id] == []


def test_events_far_apart_different_sessions() -> None:
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    events = [
        ParsedEventRef(1, "alice", base, {}),
        ParsedEventRef(2, "alice", base + timedelta(hours=2), {}),
    ]
    sessions = build_sessions(events, session_gap_minutes=30)
    assert len(sessions) == 2
