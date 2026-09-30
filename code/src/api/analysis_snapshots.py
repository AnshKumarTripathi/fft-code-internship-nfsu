"""Phase 66 B2: triage snapshots under ``paths.analyses_dir/{analysis_id}/``.

Live warehouse remains single-writer (correlate still clears live incidents).
Each successful correlate archives a JSON triage snapshot so prior analyses
stay browseable.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

from src.api.queries import (
    DEFAULT_INCIDENT_LIMIT,
    MAX_INCIDENT_LIMIT,
    clamp_limit,
    count_incidents,
    incident_kpis,
    list_incidents,
)
from src.api.schemas import AnalysisItem, IncidentItem, IncidentKpis, LogSourceCount
from src.config import DEFAULT_ANALYSES_DIR, ensure_data_directories

UTC = timezone.utc

TRIAGE_FILENAME = "triage.json"
_SAFE_ANALYSIS_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def analyses_dir_from_config(config: dict[str, Any]) -> Path:
    paths = config.get("paths") or {}
    raw = paths.get("analyses_dir") if isinstance(paths, dict) else None
    if isinstance(raw, str) and raw.strip():
        return Path(raw.strip())
    return Path(DEFAULT_ANALYSES_DIR)


def snapshot_dir(config: dict[str, Any], analysis_id: str) -> Path:
    if not _SAFE_ANALYSIS_ID.match(analysis_id):
        raise ValueError(f"invalid analysis_id for snapshot path: {analysis_id!r}")
    return analyses_dir_from_config(config) / analysis_id


def triage_snapshot_path(config: dict[str, Any], analysis_id: str) -> Path:
    return snapshot_dir(config, analysis_id) / TRIAGE_FILENAME


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def write_triage_snapshot(
    connection: duckdb.DuckDBPyConnection,
    analysis: AnalysisItem,
    config: dict[str, Any],
) -> Path:
    """Archive live triage for ``analysis`` into ``triage.json``."""
    ensure_data_directories(config)
    # Cap snapshot size for MVP (full list without disposition filter).
    items = list_incidents(
        connection,
        disposition="any",
        limit=MAX_INCIDENT_LIMIT,
        offset=0,
        sort="severity",
        order="desc",
    )
    total = count_incidents(connection, disposition="any")
    # If warehouse has more than the cap, still record the true total.
    kpis = incident_kpis(connection)
    payload = {
        "schema_version": 1,
        "analysis_id": analysis.analysis_id,
        "label": analysis.label,
        "status": analysis.status,
        "corpus_digest": analysis.corpus_digest,
        "file_count": analysis.file_count,
        "job_id": analysis.job_id,
        "correlate_run_id": analysis.correlate_run_id,
        "captured_at": datetime.now(UTC).isoformat(),
        "incident_total": total,
        "kpis": kpis.model_dump(mode="json"),
        "incidents": [item.model_dump(mode="json") for item in items],
    }
    path = triage_snapshot_path(config, analysis.analysis_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, default=_json_default) + "\n",
        encoding="utf-8",
    )
    return path


def read_triage_snapshot(
    config: dict[str, Any], analysis_id: str
) -> dict[str, Any] | None:
    path = triage_snapshot_path(config, analysis_id)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def snapshot_exists(config: dict[str, Any], analysis_id: str) -> bool:
    return triage_snapshot_path(config, analysis_id).is_file()


def latest_ready_analysis_id(
    connection: duckdb.DuckDBPyConnection,
) -> str | None:
    from src.api.analyses import analyses_table_exists

    if not analyses_table_exists(connection):
        return None
    row = connection.execute(
        """
        SELECT analysis_id
        FROM analyses
        WHERE status = 'ready'
        ORDER BY updated_at DESC NULLS LAST, created_at DESC
        LIMIT 1
        """
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return str(row[0])


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _incident_from_dict(raw: dict[str, Any]) -> IncidentItem:
    return IncidentItem(
        incident_id=str(raw.get("incident_id") or ""),
        entity_id=str(raw.get("entity_id") or ""),
        start_time=_parse_dt(raw.get("start_time")),
        end_time=_parse_dt(raw.get("end_time")),
        severity=str(raw.get("severity") or "low"),
        summary_text=raw.get("summary_text"),
        contributing_anomaly_ids=[
            str(x) for x in (raw.get("contributing_anomaly_ids") or [])
        ],
        detector_set=[str(x) for x in (raw.get("detector_set") or [])],
        anomaly_count=int(raw.get("anomaly_count") or 0),
    )


def _kpis_from_dict(raw: dict[str, Any] | None) -> IncidentKpis:
    data = raw or {}
    log_sources: list[LogSourceCount] = []
    for row in data.get("log_source_counts") or []:
        if isinstance(row, dict):
            log_sources.append(
                LogSourceCount(
                    log_source=str(row.get("log_source") or ""),
                    count=int(row.get("count") or 0),
                )
            )
    return IncidentKpis(
        total=int(data.get("total") or 0),
        critical=int(data.get("critical") or 0),
        high=int(data.get("high") or 0),
        medium=int(data.get("medium") or 0),
        low=int(data.get("low") or 0),
        last_correlate_at=_parse_dt(data.get("last_correlate_at")),
        last_report_at=_parse_dt(data.get("last_report_at")),
        detector_counts={
            str(k): int(v) for k, v in (data.get("detector_counts") or {}).items()
        },
        log_source_counts=log_sources,
    )


def filter_snapshot_incidents(
    payload: dict[str, Any],
    *,
    severity: str | None = None,
    entity_id: str | None = None,
    q: str | None = None,
    start_after: datetime | None = None,
    end_before: datetime | None = None,
    detectors: list[str] | None = None,
    min_detectors: int | None = None,
    sort: str | None = None,
    order: str | None = None,
    limit: int = DEFAULT_INCIDENT_LIMIT,
    offset: int = 0,
) -> tuple[list[IncidentItem], int]:
    items = [_incident_from_dict(row) for row in (payload.get("incidents") or []) if isinstance(row, dict)]
    severity_f = (severity or "").strip().lower() or None
    entity_f = (entity_id or "").strip() or None
    q_f = (q or "").strip().lower() or None
    detector_set = {d.lower() for d in (detectors or []) if d}
    min_det = int(min_detectors) if min_detectors and min_detectors >= 1 else None

    filtered: list[IncidentItem] = []
    for item in items:
        if severity_f and item.severity.lower() != severity_f:
            continue
        if entity_f and item.entity_id != entity_f:
            continue
        if q_f:
            hay = f"{item.summary_text or ''} {item.entity_id} {item.incident_id}".lower()
            if q_f not in hay:
                continue
        if start_after and item.start_time and item.start_time < start_after:
            continue
        if end_before and item.end_time and item.end_time > end_before:
            continue
        if detector_set:
            item_dets = {d.lower() for d in item.detector_set}
            if not detector_set.intersection(item_dets):
                continue
        if min_det is not None and len(item.detector_set) < min_det:
            continue
        filtered.append(item)

    sort_key = (sort or "severity").strip().lower()
    reverse = (order or "desc").strip().lower() != "asc"

    def _key(item: IncidentItem) -> tuple:
        if sort_key == "start_time":
            return (item.start_time or datetime.min.replace(tzinfo=UTC), item.incident_id)
        if sort_key == "anomaly_count":
            return (item.anomaly_count, item.incident_id)
        rank = SEVERITY_RANK.get(item.severity.lower(), 99)
        return (rank, item.incident_id)

    filtered.sort(key=_key, reverse=reverse)
    limit = clamp_limit(limit, DEFAULT_INCIDENT_LIMIT, MAX_INCIDENT_LIMIT)
    offset = max(0, int(offset))
    total = len(filtered)
    return filtered[offset : offset + limit], total


def snapshot_kpis(payload: dict[str, Any]) -> IncidentKpis:
    return _kpis_from_dict(payload.get("kpis") if isinstance(payload.get("kpis"), dict) else None)


def maybe_write_snapshot_on_finalize(
    connection: duckdb.DuckDBPyConnection,
    analysis: AnalysisItem,
    config: dict[str, Any],
) -> Path | None:
    """Write snapshot when finalize left the analysis ready with a correlate run."""
    if analysis.status != "ready" or not analysis.correlate_run_id:
        return None
    return write_triage_snapshot(connection, analysis, config)
