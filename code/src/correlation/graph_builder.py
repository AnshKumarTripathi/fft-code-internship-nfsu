"""Build correlation_edges and incidents from anomalies + sessions (SDD §7.7)."""

from __future__ import annotations

import hashlib
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

from src.correlation.merge_scores import AnomalyEvent
from src.correlation.session_linker import ParsedEventRef, SessionLinkResult

EDGE_NAMESPACE = uuid.UUID("ed9e0001-1111-4222-8333-444455556666")
INCIDENT_NAMESPACE = uuid.UUID("1ac1de01-1111-4222-8333-444455556666")

MAX_PRECEDING_EVENTS = 50
MAX_IP_HOST_EDGES = 20
DEFAULT_INCIDENT_GAP_MINUTES = 360
DEFAULT_IP_LINK_HORIZON_HOURS = 24


@dataclass(frozen=True)
class CorrelationEdge:
    edge_id: str
    src_event_id: int
    dst_anomaly_id: str
    relation_type: str
    session_id: str


@dataclass(frozen=True)
class Incident:
    incident_id: str
    entity_id: str
    start_time: datetime
    end_time: datetime
    severity: str
    summary_text: str
    contributing_anomaly_ids: tuple[str, ...]


@dataclass
class GraphResult:
    edges: list[CorrelationEdge]
    incidents: list[Incident]


class _UnionFind:
    def __init__(self, items: Sequence[str]) -> None:
        self.parent = {item: item for item in items}

    def find(self, item: str) -> str:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def make_edge_id(
    src_event_id: int,
    dst_anomaly_id: str,
    relation_type: str,
    session_id: str,
) -> str:
    key = f"{src_event_id}|{dst_anomaly_id}|{relation_type}|{session_id}"
    return str(uuid.uuid5(EDGE_NAMESPACE, key))


def make_incident_id(
    primary_entity: str,
    start: datetime,
    end: datetime,
    anomaly_ids: Sequence[str],
) -> str:
    """Stable UUID5 of primary entity, span, and hashed anomaly set."""
    hashed = hashlib.sha256(
        "|".join(sorted(anomaly_ids)).encode("utf-8")
    ).hexdigest()
    key = f"{primary_entity}|{start.isoformat()}|{end.isoformat()}|{hashed}"
    return str(uuid.uuid5(INCIDENT_NAMESPACE, key))


def split_entity_chains(
    anomalies: Sequence[AnomalyEvent],
    incident_gap_minutes: int,
) -> list[list[AnomalyEvent]]:
    """Group by entity, sort by window_start, split when the gap exceeds the budget."""
    by_entity: dict[str, list[AnomalyEvent]] = defaultdict(list)
    for anomaly in anomalies:
        by_entity[anomaly.entity_id].append(anomaly)

    gap = timedelta(minutes=incident_gap_minutes)
    chains: list[list[AnomalyEvent]] = []
    for group in by_entity.values():
        ordered = sorted(group, key=lambda item: (item.window_start, item.anomaly_id))
        current = [ordered[0]]
        for anomaly in ordered[1:]:
            prev_end = current[-1].window_end
            if anomaly.window_start - prev_end > gap:
                chains.append(current)
                current = [anomaly]
            else:
                current.append(anomaly)
        chains.append(current)
    return chains


DETECTOR_ROLES = {
    "statistical": "rate",
    "spectral": "rhythm",
    "ml": "sequence",
    "cluster_outlier": "peer-outlier",
    "changepoint": "level-shift",
    "seasonal": "seasonal-residual",
}

SUMMARY_ROLES = {
    "statistical": "rate",
    "spectral": "rhythm",
    "ml": "sequence",
    "cluster_outlier": "peer",
    "changepoint": "level-shift",
    "seasonal": "seasonal-residual",
}

SUMMARY_ROLE_ORDER = (
    "statistical",
    "spectral",
    "ml",
    "cluster_outlier",
    "changepoint",
    "seasonal",
)

ENTITY_KIND_WORDS = {
    "user": "User",
    "host": "Host",
    "ip": "IP",
    "service": "Service",
}


def compute_severity(
    anomalies: Sequence[AnomalyEvent],
    *,
    entity_type: str | None = None,
    agreement_threshold: int = 2,
) -> str:
    """MVP severity heuristic from phase_8 §6.5.

    ``agreement_threshold`` is the minimum distinct ``source_detector`` count
    required for the multi-detector high/critical branch (Phase 54).
    """
    if not anomalies:
        return "low"

    sources = {a.source_detector for a in anomalies}
    n = len(anomalies)
    span = max(a.window_end for a in anomalies) - min(a.window_start for a in anomalies)
    threshold = max(1, int(agreement_threshold))
    multi = len(sources) >= threshold
    has_cluster = "cluster_outlier" in sources
    privileged = entity_type in ("host", "service")

    if multi and (has_cluster or privileged):
        return "critical"
    if multi:
        return "high"
    if n >= 2 or span >= timedelta(hours=1):
        return "medium"
    return "low"


def incident_detector_count(
    incident: Incident,
    anomalies_by_id: dict[str, AnomalyEvent],
) -> int:
    """Distinct source_detector values among an incident's contributing anomalies."""
    sources: set[str] = set()
    for anomaly_id in incident.contributing_anomaly_ids:
        anomaly = anomalies_by_id.get(anomaly_id)
        if anomaly is not None:
            sources.add(anomaly.source_detector)
    return len(sources)


def filter_incidents_by_agreement(
    incidents: Sequence[Incident],
    anomalies: Sequence[AnomalyEvent],
    min_detectors: int,
) -> list[Incident]:
    """Keep only incidents whose distinct detector count meets ``min_detectors``."""
    threshold = max(1, int(min_detectors))
    by_id = {a.anomaly_id: a for a in anomalies}
    return [
        incident
        for incident in incidents
        if incident_detector_count(incident, by_id) >= threshold
    ]


def _fmt_summary_ts(value: datetime | None) -> str:
    if value is None:
        return "n/a"
    aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M")


def _kind_label(entity_type: str | None) -> str:
    if not entity_type:
        return "Entity"
    return ENTITY_KIND_WORDS.get(entity_type, entity_type.replace("_", " ").title())


def _role_phrase(sources: Sequence[str]) -> str:
    roles = [SUMMARY_ROLES.get(name, name) for name in sources]
    if not roles:
        return "no detectors"
    if len(roles) == 1:
        return f"{roles[0]} detector"
    if len(roles) == 2:
        return f"{roles[0]} and {roles[1]} detectors"
    return f"{', '.join(roles[:-1])}, and {roles[-1]} detectors"


def build_summary(
    anomalies: Sequence[AnomalyEvent],
    *,
    entity_id: str | None = None,
    entity_type: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    ip_link: bool = False,
    host_link: bool = False,
) -> str:
    present = {a.source_detector for a in anomalies}
    sources = [name for name in SUMMARY_ROLE_ORDER if name in present]
    sources.extend(sorted(name for name in present if name not in SUMMARY_ROLES))
    n = len(anomalies)
    primary = entity_id
    if primary is None and anomalies:
        primary = anomalies[0].entity_id
    if not primary:
        primary = "unknown"
    top_score = max((a.score for a in anomalies), default=0.0)
    if start is None and anomalies:
        start = min(a.window_start for a in anomalies)
    if end is None and anomalies:
        end = max(a.window_end for a in anomalies)
    kind = _kind_label(entity_type)
    anomaly_word = "anomaly" if n == 1 else "anomalies"
    span = f"{_fmt_summary_ts(start)}–{_fmt_summary_ts(end)} UTC"
    ip_clause = "IP linkage present" if ip_link else "no IP linkage"
    host_clause = "host linkage present" if host_link else "no host linkage"
    return (
        f"{kind} {primary}: {n} {anomaly_word} from {_role_phrase(sources)} "
        f"({span}). {ip_clause}; {host_clause}. Highest score {top_score:.2f}."
    )


def build_graph(
    anomalies: Sequence[AnomalyEvent],
    link_result: SessionLinkResult,
    *,
    same_ip_link: bool,
    same_host_link: bool,
    entity_types: dict[str, str] | None = None,
    incident_gap_minutes: int = DEFAULT_INCIDENT_GAP_MINUTES,
    ip_link_horizon_hours: int = DEFAULT_IP_LINK_HORIZON_HOURS,
    agreement_threshold: int = 2,
) -> GraphResult:
    """Build edges and incident subgraphs."""
    entity_types = entity_types or {}
    sessions_by_id = {s.session_id: s for s in link_result.sessions}
    events_by_id = {e.event_id: e for e in link_result.events}
    horizon = timedelta(hours=ip_link_horizon_hours)

    edges: list[CorrelationEdge] = []
    seen_edge_keys: set[str] = set()

    def add_edge(
        src_event_id: int,
        dst_anomaly_id: str,
        relation_type: str,
        session_id: str,
    ) -> None:
        key = f"{src_event_id}|{dst_anomaly_id}|{relation_type}|{session_id}"
        if key in seen_edge_keys:
            return
        seen_edge_keys.add(key)
        edges.append(
            CorrelationEdge(
                edge_id=make_edge_id(
                    src_event_id, dst_anomaly_id, relation_type, session_id
                ),
                src_event_id=src_event_id,
                dst_anomaly_id=dst_anomaly_id,
                relation_type=relation_type,
                session_id=session_id,
            )
        )

    for anomaly in anomalies:
        session_ids = link_result.anomaly_sessions.get(anomaly.anomaly_id, [])
        session_events: list[tuple[ParsedEventRef, str]] = []
        for sid in session_ids:
            session = sessions_by_id.get(sid)
            if session is None:
                continue
            for eid in session.event_ids:
                event = events_by_id.get(eid)
                if event is None:
                    continue
                session_events.append((event, sid))

        session_events.sort(key=lambda pair: pair[0].event_timestamp)
        preceding = [
            (e, sid)
            for e, sid in session_events
            if e.event_timestamp <= anomaly.window_end
        ][-MAX_PRECEDING_EVENTS:]

        for event, sid in preceding:
            if event.event_timestamp < anomaly.window_start:
                add_edge(event.event_id, anomaly.anomaly_id, "precedes", sid)
            elif anomaly.window_start <= event.event_timestamp <= anomaly.window_end:
                add_edge(event.event_id, anomaly.anomaly_id, "same_session", sid)

        if same_ip_link or same_host_link:
            _add_ip_host_edges(
                anomaly,
                session_events,
                link_result.events,
                same_ip_link=same_ip_link,
                same_host_link=same_host_link,
                horizon=horizon,
                add_edge=add_edge,
            )

    ids = [a.anomaly_id for a in anomalies]
    uf = _UnionFind(ids)
    anomaly_by_id = {a.anomaly_id: a for a in anomalies}
    chains = split_entity_chains(anomalies, incident_gap_minutes)
    chain_index: dict[str, int] = {}
    for index, chain in enumerate(chains):
        for anomaly in chain:
            chain_index[anomaly.anomaly_id] = index
        for other in chain[1:]:
            uf.union(chain[0].anomaly_id, other.anomaly_id)

    session_to_anomalies: dict[str, list[str]] = defaultdict(list)
    for anomaly_id, sids in link_result.anomaly_sessions.items():
        for sid in sids:
            session_to_anomalies[sid].append(anomaly_id)
    for group in session_to_anomalies.values():
        unique = list(dict.fromkeys(group))
        for i, aid in enumerate(unique):
            a = anomaly_by_id.get(aid)
            if a is None:
                continue
            for bid in unique[i + 1 :]:
                b = anomaly_by_id.get(bid)
                if b is None:
                    continue
                if _same_entity_different_chain(a, b, chain_index):
                    continue
                uf.union(aid, bid)

    if same_ip_link or same_host_link:
        _union_by_ip_host(
            uf,
            anomalies,
            edges,
            events_by_id,
            horizon=horizon,
            chain_index=chain_index,
        )

    components: dict[str, list[AnomalyEvent]] = defaultdict(list)
    for anomaly in anomalies:
        components[uf.find(anomaly.anomaly_id)].append(anomaly)

    incidents: list[Incident] = []
    for group in components.values():
        entity_counts = Counter(a.entity_id for a in group)
        primary_entity = entity_counts.most_common(1)[0][0]
        start = min(a.window_start for a in group)
        end = max(a.window_end for a in group)
        contrib = tuple(sorted(a.anomaly_id for a in group))
        group_ids = set(contrib)
        ip_link = any(
            edge.relation_type == "same_ip" and edge.dst_anomaly_id in group_ids
            for edge in edges
        )
        host_link = any(
            edge.relation_type == "same_host" and edge.dst_anomaly_id in group_ids
            for edge in edges
        )
        severity = compute_severity(
            group,
            entity_type=entity_types.get(primary_entity),
            agreement_threshold=agreement_threshold,
        )
        incidents.append(
            Incident(
                incident_id=make_incident_id(primary_entity, start, end, contrib),
                entity_id=primary_entity,
                start_time=start,
                end_time=end,
                severity=severity,
                summary_text=build_summary(
                    group,
                    entity_id=primary_entity,
                    entity_type=entity_types.get(primary_entity) or "unknown",
                    start=start,
                    end=end,
                    ip_link=ip_link,
                    host_link=host_link,
                ),
                contributing_anomaly_ids=contrib,
            )
        )

    return GraphResult(edges=edges, incidents=incidents)


def _same_entity_different_chain(
    a: AnomalyEvent,
    b: AnomalyEvent,
    chain_index: dict[str, int],
) -> bool:
    if a.entity_id != b.entity_id:
        return False
    return chain_index.get(a.anomaly_id) != chain_index.get(b.anomaly_id)


def _field_value(raw_fields: dict, *keys: str) -> str | None:
    for key in keys:
        value = raw_fields.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _add_ip_host_edges(
    anomaly: AnomalyEvent,
    session_events: list[tuple[ParsedEventRef, str]],
    all_events: Sequence[ParsedEventRef],
    *,
    same_ip_link: bool,
    same_host_link: bool,
    horizon: timedelta,
    add_edge,
) -> None:
    lo = anomaly.window_start - horizon
    hi = anomaly.window_end + horizon
    ips: set[str] = set()
    hosts: set[str] = set()
    primary_sid = session_events[0][1] if session_events else ""
    for event, _sid in session_events:
        if event.event_timestamp < lo or event.event_timestamp > hi:
            continue
        if same_ip_link:
            ip = _field_value(event.raw_fields, "src_ip")
            if ip:
                ips.add(ip)
        if same_host_link:
            host = _field_value(event.raw_fields, "hostname", "host")
            if host:
                hosts.add(host)

    if not ips and not hosts:
        return

    link_sid = primary_sid or f"cross:{anomaly.entity_id}"
    ip_added = 0
    host_added = 0
    for event in all_events:
        if event.entity_id == anomaly.entity_id:
            continue
        if event.event_timestamp < lo or event.event_timestamp > hi:
            continue
        if same_ip_link and ip_added < MAX_IP_HOST_EDGES:
            ip = _field_value(event.raw_fields, "src_ip")
            if ip and ip in ips:
                add_edge(event.event_id, anomaly.anomaly_id, "same_ip", link_sid)
                ip_added += 1
        if same_host_link and host_added < MAX_IP_HOST_EDGES:
            host = _field_value(event.raw_fields, "hostname", "host")
            if host and host in hosts:
                add_edge(event.event_id, anomaly.anomaly_id, "same_host", link_sid)
                host_added += 1


def _union_by_ip_host(
    uf: _UnionFind,
    anomalies: Sequence[AnomalyEvent],
    edges: Sequence[CorrelationEdge],
    events_by_id: dict[int, ParsedEventRef],
    *,
    horizon: timedelta,
    chain_index: dict[str, int],
) -> None:
    anomaly_by_id = {a.anomaly_id: a for a in anomalies}
    ip_to_anomalies: dict[str, list[str]] = defaultdict(list)
    host_to_anomalies: dict[str, list[str]] = defaultdict(list)

    for edge in edges:
        if edge.relation_type not in ("same_ip", "same_host", "precedes", "same_session"):
            continue
        event = events_by_id.get(edge.src_event_id)
        if event is None:
            continue
        if edge.relation_type == "same_ip" or edge.relation_type in (
            "precedes",
            "same_session",
        ):
            ip = _field_value(event.raw_fields, "src_ip")
            if ip and edge.relation_type == "same_ip":
                ip_to_anomalies[ip].append(edge.dst_anomaly_id)
        if edge.relation_type == "same_host":
            host = _field_value(event.raw_fields, "hostname", "host")
            if host:
                host_to_anomalies[host].append(edge.dst_anomaly_id)

    def maybe_union(group: list[str]) -> None:
        unique = list(dict.fromkeys(group))
        for i, aid in enumerate(unique):
            a = anomaly_by_id.get(aid)
            if a is None:
                continue
            for bid in unique[i + 1 :]:
                b = anomaly_by_id.get(bid)
                if b is None:
                    continue
                if _same_entity_different_chain(a, b, chain_index):
                    continue
                if abs(a.window_start - b.window_start) <= horizon:
                    uf.union(aid, bid)

    for group in ip_to_anomalies.values():
        maybe_union(group)
    for group in host_to_anomalies.values():
        maybe_union(group)
