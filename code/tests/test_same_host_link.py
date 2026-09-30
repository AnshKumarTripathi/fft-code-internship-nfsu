"""same_host edges are created only inside ip_link_horizon_hours."""

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


def _ts(hour: int) -> datetime:
    return datetime(2024, 1, 1, hour, tzinfo=timezone.utc)


def _anomaly() -> AnomalyEvent:
    start = _ts(10)
    return AnomalyEvent(
        anomaly_id=make_anomaly_id("statistical", "alice", start),
        entity_id="alice",
        window_start=start,
        window_end=start + timedelta(minutes=30),
        source_detector="statistical",
        score=4.0,
        metadata={},
    )


def _graph_with_peer_event(peer_timestamp: datetime, *, horizon_hours: int):
    anomaly = _anomaly()
    sid = make_session_id("alice", _ts(10))
    alice_event = ParsedEventRef(1, "alice", _ts(10), {"hostname": "LabSZ"})
    bob_event = ParsedEventRef(2, "bob", peer_timestamp, {"hostname": "LabSZ"})
    session = Session(
        session_id=sid,
        entity_id="alice",
        start_time=_ts(10),
        end_time=_ts(10) + timedelta(minutes=30),
        event_ids=(1,),
    )
    link = SessionLinkResult(
        sessions=[session],
        events=[alice_event, bob_event],
        anomaly_sessions={anomaly.anomaly_id: [sid]},
    )
    return build_graph(
        [anomaly],
        link,
        same_ip_link=False,
        same_host_link=True,
        ip_link_horizon_hours=horizon_hours,
    )


def test_same_host_48h_away_creates_no_edge() -> None:
    graph = _graph_with_peer_event(_ts(10) + timedelta(hours=48), horizon_hours=24)
    assert not any(edge.relation_type == "same_host" for edge in graph.edges)


def test_same_host_1h_away_creates_edge() -> None:
    graph = _graph_with_peer_event(_ts(10) + timedelta(hours=1), horizon_hours=24)
    assert any(edge.relation_type == "same_host" for edge in graph.edges)
