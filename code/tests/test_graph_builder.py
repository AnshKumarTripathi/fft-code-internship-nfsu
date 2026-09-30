"""Unit tests for graph_builder severity and edges."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.correlation.graph_builder import (
    MAX_PRECEDING_EVENTS,
    build_graph,
    build_summary,
    compute_severity,
    filter_incidents_by_agreement,
)
from src.correlation.merge_scores import AnomalyEvent, make_anomaly_id
from src.correlation.session_linker import (
    ParsedEventRef,
    Session,
    SessionLinkResult,
    make_session_id,
)


def _ts(hour: int) -> datetime:
    return datetime(2024, 1, 1, hour, tzinfo=timezone.utc)


def _anomaly(
    source: str,
    entity: str = "alice",
    hour: int = 10,
    score: float = 4.0,
    duration_minutes: int = 30,
) -> AnomalyEvent:
    start = _ts(hour)
    return AnomalyEvent(
        anomaly_id=make_anomaly_id(source, entity, start),
        entity_id=entity,
        window_start=start,
        window_end=start + timedelta(minutes=duration_minutes),
        source_detector=source,
        score=score,
        metadata={},
    )


def test_severity_single_low() -> None:
    assert compute_severity([_anomaly("statistical")]) == "low"


def test_severity_medium_many() -> None:
    assert (
        compute_severity(
            [_anomaly("statistical", hour=10), _anomaly("statistical", hour=11)]
        )
        == "medium"
    )


def test_severity_medium_long_span() -> None:
    assert (
        compute_severity([_anomaly("statistical", duration_minutes=90)]) == "medium"
    )


def test_severity_high_multi_detector() -> None:
    assert (
        compute_severity(
            [_anomaly("statistical"), _anomaly("ml", hour=10)]
        )
        == "high"
    )


def test_severity_critical_with_cluster() -> None:
    assert (
        compute_severity(
            [
                _anomaly("statistical"),
                _anomaly("cluster_outlier", hour=10),
            ]
        )
        == "critical"
    )


def test_severity_critical_privileged() -> None:
    assert (
        compute_severity(
            [_anomaly("statistical", entity="web1"), _anomaly("ml", entity="web1")],
            entity_type="host",
        )
        == "critical"
    )


def test_severity_single_statistical_ten_minute_window_low() -> None:
    assert compute_severity([_anomaly("statistical", duration_minutes=10)]) == "low"


def test_severity_two_statistical_flags_same_chain_medium() -> None:
    assert (
        compute_severity(
            [
                _anomaly("statistical", hour=10, duration_minutes=10),
                _anomaly("statistical", hour=11, duration_minutes=10),
            ]
        )
        == "medium"
    )


def test_severity_statistical_plus_spectral_high() -> None:
    assert (
        compute_severity(
            [_anomaly("statistical"), _anomaly("spectral", hour=10)]
        )
        == "high"
    )


def test_severity_ml_and_cluster_different_chains_not_merged() -> None:
    ml = _anomaly("ml", hour=10)
    cluster = _anomaly("cluster_outlier", hour=20)
    link = SessionLinkResult(
        sessions=[],
        events=[],
        anomaly_sessions={ml.anomaly_id: [], cluster.anomaly_id: []},
    )
    graph = build_graph(
        [ml, cluster],
        link,
        same_ip_link=False,
        same_host_link=False,
        incident_gap_minutes=360,
    )
    assert len(graph.incidents) == 2
    severities = {incident.severity for incident in graph.incidents}
    assert "high" not in severities
    assert "critical" not in severities
    assert severities <= {"low", "medium"}


def test_build_summary_names_detector_roles() -> None:
    statistical = _anomaly("statistical", score=5.2)
    spectral = _anomaly("spectral", hour=10, score=4.0)
    summary = build_summary(
        [statistical, spectral],
        entity_id="alice",
        entity_type="user",
        start=statistical.window_start,
        end=spectral.window_end,
        ip_link=True,
        host_link=False,
    )
    assert summary == (
        "User alice: 2 anomalies from rate and rhythm detectors "
        "(2024-01-01 10:00–2024-01-01 10:30 UTC). "
        "IP linkage present; no host linkage. Highest score 5.20."
    )


def test_precedes_and_same_session_edges() -> None:
    anomaly = _anomaly("statistical", hour=10)
    sid = make_session_id("alice", _ts(9))
    events = [
        ParsedEventRef(1, "alice", _ts(9), {"src_ip": "1.1.1.1"}),
        ParsedEventRef(2, "alice", _ts(10), {"src_ip": "1.1.1.1"}),
        ParsedEventRef(3, "alice", datetime(2024, 1, 1, 10, 30, tzinfo=timezone.utc), {}),
    ]
    session = Session(
        session_id=sid,
        entity_id="alice",
        start_time=_ts(9),
        end_time=datetime(2024, 1, 1, 10, 30, tzinfo=timezone.utc),
        event_ids=(1, 2, 3),
    )
    link = SessionLinkResult(
        sessions=[session],
        events=events,
        anomaly_sessions={anomaly.anomaly_id: [sid]},
    )
    graph = build_graph(
        [anomaly],
        link,
        same_ip_link=False,
        same_host_link=False,
    )
    relation_types = {e.relation_type for e in graph.edges}
    assert "precedes" in relation_types
    assert "same_session" in relation_types
    assert len(graph.incidents) == 1
    assert graph.incidents[0].severity == "low"


def test_preceding_events_capped() -> None:
    anomaly = _anomaly("statistical", hour=12)
    sid = make_session_id("alice", _ts(0))
    events = [
        ParsedEventRef(i, "alice", _ts(0) + timedelta(minutes=i), {})
        for i in range(80)
    ]
    # all within window_end (hour 13)
    session = Session(
        session_id=sid,
        entity_id="alice",
        start_time=events[0].event_timestamp,
        end_time=events[-1].event_timestamp,
        event_ids=tuple(e.event_id for e in events),
    )
    link = SessionLinkResult(
        sessions=[session],
        events=events,
        anomaly_sessions={anomaly.anomaly_id: [sid]},
    )
    graph = build_graph(
        [anomaly], link, same_ip_link=False, same_host_link=False
    )
    assert len(graph.edges) <= MAX_PRECEDING_EVENTS


def test_multi_detector_one_incident() -> None:
    a = _anomaly("statistical", hour=10)
    b = _anomaly("ml", hour=10)
    link = SessionLinkResult(sessions=[], events=[], anomaly_sessions={a.anomaly_id: [], b.anomaly_id: []})
    graph = build_graph([a, b], link, same_ip_link=False, same_host_link=False)
    assert len(graph.incidents) == 1
    assert graph.incidents[0].severity == "high"
    assert len(graph.incidents[0].contributing_anomaly_ids) == 2


def test_severity_boost_threshold_three_two_detectors_not_high() -> None:
    """severity_boost with min_detectors=3: two detectors stay on single-path."""
    assert (
        compute_severity(
            [_anomaly("statistical"), _anomaly("ml", hour=10)],
            agreement_threshold=3,
        )
        == "medium"
    )


def test_severity_boost_threshold_three_three_detectors_high() -> None:
    assert (
        compute_severity(
            [
                _anomaly("statistical"),
                _anomaly("ml", hour=10),
                _anomaly("spectral", hour=10),
            ],
            agreement_threshold=3,
        )
        == "high"
    )


def test_severity_boost_threshold_three_critical_with_cluster() -> None:
    assert (
        compute_severity(
            [
                _anomaly("statistical"),
                _anomaly("ml", hour=10),
                _anomaly("cluster_outlier", hour=10),
            ],
            agreement_threshold=3,
        )
        == "critical"
    )


def test_build_graph_passes_agreement_threshold() -> None:
    a = _anomaly("statistical", hour=10)
    b = _anomaly("ml", hour=10)
    link = SessionLinkResult(
        sessions=[],
        events=[],
        anomaly_sessions={a.anomaly_id: [], b.anomaly_id: []},
    )
    graph = build_graph(
        [a, b],
        link,
        same_ip_link=False,
        same_host_link=False,
        agreement_threshold=3,
    )
    assert len(graph.incidents) == 1
    assert graph.incidents[0].severity == "medium"


def test_filter_incidents_by_agreement_drops_under_threshold() -> None:
    single = _anomaly("statistical", hour=10)
    multi_a = _anomaly("statistical", entity="bob", hour=10)
    multi_b = _anomaly("ml", entity="bob", hour=10)
    link = SessionLinkResult(
        sessions=[],
        events=[],
        anomaly_sessions={
            single.anomaly_id: [],
            multi_a.anomaly_id: [],
            multi_b.anomaly_id: [],
        },
    )
    graph = build_graph(
        [single, multi_a, multi_b],
        link,
        same_ip_link=False,
        same_host_link=False,
    )
    assert len(graph.incidents) == 2
    kept = filter_incidents_by_agreement(
        graph.incidents, [single, multi_a, multi_b], min_detectors=2
    )
    assert len(kept) == 1
    assert kept[0].entity_id == "bob"
    assert {aid for aid in kept[0].contributing_anomaly_ids} == {
        multi_a.anomaly_id,
        multi_b.anomaly_id,
    }