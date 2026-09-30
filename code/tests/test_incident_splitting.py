"""Time-split incidents: entity-chain gap is a hard split."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.correlation.graph_builder import build_graph
from src.correlation.merge_scores import AnomalyEvent, make_anomaly_id
from src.correlation.session_linker import (
    ParsedEventRef,
    Session,
    SessionLinkResult,
    make_session_id,
)


def _flag(
    *,
    start: datetime,
    entity: str = "alice",
    source: str = "statistical",
    duration_minutes: int = 30,
) -> AnomalyEvent:
    return AnomalyEvent(
        anomaly_id=make_anomaly_id(source, entity, start),
        entity_id=entity,
        window_start=start,
        window_end=start + timedelta(minutes=duration_minutes),
        source_detector=source,
        score=4.0,
        metadata={},
    )


def _empty_link(*anomalies: AnomalyEvent) -> SessionLinkResult:
    return SessionLinkResult(
        sessions=[],
        events=[],
        anomaly_sessions={a.anomaly_id: [] for a in anomalies},
    )


def test_two_day_gap_yields_two_incidents() -> None:
    first = datetime(2024, 1, 1, 10, tzinfo=timezone.utc)
    second = first + timedelta(days=2)
    a = _flag(start=first)
    b = _flag(start=second)
    graph = build_graph(
        [a, b],
        _empty_link(a, b),
        same_ip_link=False,
        same_host_link=False,
        incident_gap_minutes=360,
    )
    assert len(graph.incidents) == 2


def test_thirty_minute_gap_yields_one_incident() -> None:
    first = datetime(2024, 1, 1, 10, tzinfo=timezone.utc)
    second = first + timedelta(minutes=30)
    a = _flag(start=first)
    b = _flag(start=second)
    graph = build_graph(
        [a, b],
        _empty_link(a, b),
        same_ip_link=False,
        same_host_link=False,
        incident_gap_minutes=360,
    )
    assert len(graph.incidents) == 1


def test_session_spanning_gap_does_not_merge_same_entity_chains() -> None:
    first = datetime(2024, 1, 1, 10, tzinfo=timezone.utc)
    second = first + timedelta(days=2)
    a = _flag(start=first)
    b = _flag(start=second)
    sid = make_session_id("alice", first - timedelta(hours=1))
    events = [
        ParsedEventRef(1, "alice", first, {}),
        ParsedEventRef(2, "alice", second, {}),
    ]
    session = Session(
        session_id=sid,
        entity_id="alice",
        start_time=first,
        end_time=second + timedelta(minutes=30),
        event_ids=(1, 2),
    )
    link = SessionLinkResult(
        sessions=[session],
        events=events,
        anomaly_sessions={a.anomaly_id: [sid], b.anomaly_id: [sid]},
    )
    graph = build_graph(
        [a, b],
        link,
        same_ip_link=False,
        same_host_link=False,
        incident_gap_minutes=360,
    )
    assert len(graph.incidents) == 2
