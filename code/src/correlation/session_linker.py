"""Sessionize parsed_events by entity/time gap (SDD §7.7)."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from src.correlation.merge_scores import AnomalyEvent

SESSION_NAMESPACE = uuid.UUID("5e5510a1-1111-4222-8333-444455556666")


@dataclass(frozen=True)
class ParsedEventRef:
    event_id: int
    entity_id: str
    event_timestamp: datetime
    raw_fields: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Session:
    session_id: str
    entity_id: str
    start_time: datetime
    end_time: datetime
    event_ids: tuple[int, ...]


@dataclass
class SessionLinkResult:
    sessions: list[Session]
    events: list[ParsedEventRef]
    anomaly_sessions: dict[str, list[str]]  # anomaly_id -> session_ids


def make_session_id(entity_id: str, session_start: datetime) -> str:
    key = f"{entity_id}|{_ensure_utc(session_start).isoformat()}"
    return str(uuid.uuid5(SESSION_NAMESPACE, key))


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _parse_raw_fields(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def load_events_for_entities(
    connection: Any,
    entity_ids: Sequence[str],
) -> list[ParsedEventRef]:
    """Load parsed_events for the given entities, ordered by entity/time."""
    if not entity_ids:
        return []
    unique = sorted(set(entity_ids))
    placeholders = ", ".join("?" for _ in unique)
    rows = connection.execute(
        f"""
        SELECT event_id, entity_id, event_timestamp, raw_fields
        FROM parsed_events
        WHERE entity_id IN ({placeholders})
        ORDER BY entity_id, event_timestamp
        """,
        list(unique),
    ).fetchall()

    events: list[ParsedEventRef] = []
    for event_id, entity_id, event_timestamp, raw_fields in rows:
        if not isinstance(event_timestamp, datetime):
            continue
        events.append(
            ParsedEventRef(
                event_id=int(event_id),
                entity_id=str(entity_id),
                event_timestamp=_ensure_utc(event_timestamp),
                raw_fields=_parse_raw_fields(raw_fields),
            )
        )
    return events


def build_sessions(
    events: Sequence[ParsedEventRef],
    *,
    session_gap_minutes: int,
) -> list[Session]:
    """Split per-entity event streams into sessions by max gap."""
    if session_gap_minutes <= 0:
        raise ValueError(
            f"session_gap_minutes must be positive, got {session_gap_minutes!r}"
        )
    gap = timedelta(minutes=session_gap_minutes)
    sessions: list[Session] = []

    by_entity: dict[str, list[ParsedEventRef]] = {}
    for event in events:
        by_entity.setdefault(event.entity_id, []).append(event)

    for entity_id, entity_events in by_entity.items():
        if not entity_events:
            continue
        current: list[ParsedEventRef] = [entity_events[0]]
        for event in entity_events[1:]:
            if event.event_timestamp - current[-1].event_timestamp > gap:
                sessions.append(_finalize_session(entity_id, current))
                current = [event]
            else:
                current.append(event)
        sessions.append(_finalize_session(entity_id, current))

    return sessions


def _finalize_session(entity_id: str, events: list[ParsedEventRef]) -> Session:
    start = events[0].event_timestamp
    end = events[-1].event_timestamp
    return Session(
        session_id=make_session_id(entity_id, start),
        entity_id=entity_id,
        start_time=start,
        end_time=end,
        event_ids=tuple(e.event_id for e in events),
    )


def attach_anomalies_to_sessions(
    anomalies: Sequence[AnomalyEvent],
    sessions: Sequence[Session],
) -> dict[str, list[str]]:
    """Map each anomaly_id to overlapping same-entity session_ids."""
    by_entity: dict[str, list[Session]] = {}
    for session in sessions:
        by_entity.setdefault(session.entity_id, []).append(session)

    result: dict[str, list[str]] = {}
    for anomaly in anomalies:
        matches: list[str] = []
        for session in by_entity.get(anomaly.entity_id, []):
            if _overlaps(
                anomaly.window_start,
                anomaly.window_end,
                session.start_time,
                session.end_time,
            ):
                matches.append(session.session_id)
        result[anomaly.anomaly_id] = matches
    return result


def link_sessions(
    connection: Any,
    anomalies: Sequence[AnomalyEvent],
    *,
    session_gap_minutes: int,
) -> SessionLinkResult:
    """Load events, build sessions, attach anomalies."""
    entity_ids = [a.entity_id for a in anomalies]
    events = load_events_for_entities(connection, entity_ids)
    sessions = build_sessions(events, session_gap_minutes=session_gap_minutes)
    anomaly_sessions = attach_anomalies_to_sessions(anomalies, sessions)
    return SessionLinkResult(
        sessions=sessions,
        events=events,
        anomaly_sessions=anomaly_sessions,
    )


def _overlaps(
    a_start: datetime,
    a_end: datetime,
    b_start: datetime,
    b_end: datetime,
) -> bool:
    return a_start <= b_end and b_start <= a_end
