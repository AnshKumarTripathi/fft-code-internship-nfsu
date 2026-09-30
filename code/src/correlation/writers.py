"""DuckDB writers for Phase 8 correlation tables."""

from __future__ import annotations

import json
from typing import Any, Sequence

from src.correlation.graph_builder import CorrelationEdge, Incident
from src.correlation.merge_scores import AnomalyEvent


def clear_correlation_tables(connection: Any) -> None:
    """Full refresh: wipe incidents, edges, then anomaly_events (FK order)."""
    connection.execute("DELETE FROM incidents")
    connection.execute("DELETE FROM correlation_edges")
    connection.execute("DELETE FROM anomaly_events")


def insert_anomaly_events(
    connection: Any,
    anomalies: Sequence[AnomalyEvent],
) -> int:
    if not anomalies:
        return 0
    for row in anomalies:
        connection.execute(
            """
            INSERT INTO anomaly_events (
                anomaly_id, entity_id, window_start, window_end,
                source_detector, score, metadata
            )
            VALUES (?, ?, ?, ?, ?, ?, ?::JSON)
            """,
            [
                row.anomaly_id,
                row.entity_id,
                row.window_start,
                row.window_end,
                row.source_detector,
                row.score,
                json.dumps(row.metadata),
            ],
        )
    return len(anomalies)


def insert_correlation_edges(
    connection: Any,
    edges: Sequence[CorrelationEdge],
) -> int:
    if not edges:
        return 0
    for row in edges:
        connection.execute(
            """
            INSERT INTO correlation_edges (
                edge_id, src_event_id, dst_anomaly_id, relation_type, session_id
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                row.edge_id,
                row.src_event_id,
                row.dst_anomaly_id,
                row.relation_type,
                row.session_id,
            ],
        )
    return len(edges)


def insert_incidents(
    connection: Any,
    incidents: Sequence[Incident],
) -> int:
    if not incidents:
        return 0
    for row in incidents:
        connection.execute(
            """
            INSERT INTO incidents (
                incident_id, entity_id, start_time, end_time,
                severity, summary_text, contributing_anomaly_ids
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                row.incident_id,
                row.entity_id,
                row.start_time,
                row.end_time,
                row.severity,
                row.summary_text,
                list(row.contributing_anomaly_ids),
            ],
        )
    return len(incidents)
