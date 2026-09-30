"""v1 incident JSON routes."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api.deps import get_db, load_app_config
from src.api.queries import (
    DEFAULT_INCIDENT_TIMELINE_LIMIT,
    MAX_TIMELINE_LIMIT,
    clamp_limit,
    count_incidents,
    get_incident_detail,
    list_incident_edges,
    list_incident_timeline,
    list_incidents,
    parse_detector_filters,
)
from src.api.routes.v1._common import OFFSET_QUERY, clamped_page, envelope
from src.api.schemas import (
    IncidentDetail,
    IncidentEdgeItem,
    IncidentItem,
    IncidentTimelineEvent,
    ListEnvelope,
)
from src.config import ui_honesty_settings

router = APIRouter(tags=["v1-incidents"])

DispositionParam = Literal["open", "dismissed", "any"]
SortParam = Literal["severity", "start_time", "anomaly_count"]
OrderParam = Literal["asc", "desc"]


@router.get("/incidents", response_model=ListEnvelope[IncidentItem])
def v1_list_incidents(
    request: Request,
    severity: str | None = Query(default=None),
    entity_id: str | None = Query(default=None),
    q: str | None = Query(default=None),
    start_after: datetime | None = Query(default=None),
    end_before: datetime | None = Query(default=None),
    detector: list[str] | None = Query(default=None),
    min_detectors: int | None = Query(default=None, ge=1),
    disposition: DispositionParam | None = Query(default=None),
    sort: SortParam | None = Query(default=None),
    order: OrderParam | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> ListEnvelope[IncidentItem]:
    q_f = q.strip() if q and q.strip() else None
    detectors = parse_detector_filters(detector)
    resolved_limit, offset = clamped_page(request, limit=limit, offset=offset)
    filter_kwargs = {
        "severity": severity,
        "entity_id": entity_id,
        "q": q_f,
        "start_after": start_after,
        "end_before": end_before,
        "detectors": detectors or None,
        "min_detectors": min_detectors,
        "disposition": disposition,
    }
    items = list_incidents(
        connection,
        **filter_kwargs,
        sort=sort,
        order=order,
        limit=resolved_limit,
        offset=offset,
    )
    total = count_incidents(connection, **filter_kwargs)
    return envelope(items, total=total, limit=resolved_limit, offset=offset)


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def v1_get_incident(
    request: Request,
    incident_id: str,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> IncidentDetail:
    policy = ui_honesty_settings(load_app_config(request))
    detail = get_incident_detail(
        connection, incident_id, warn_band=policy["warn_band"]
    )
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")
    return detail


@router.get(
    "/incidents/{incident_id}/timeline",
    response_model=ListEnvelope[IncidentTimelineEvent],
)
def v1_incident_timeline(
    incident_id: str,
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> ListEnvelope[IncidentTimelineEvent]:
    resolved = clamp_limit(
        limit, DEFAULT_INCIDENT_TIMELINE_LIMIT, MAX_TIMELINE_LIMIT
    )
    result = list_incident_timeline(
        connection, incident_id, limit=resolved, offset=offset
    )
    if result is None:
        raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")
    items, total = result
    return envelope(items, total=total, limit=resolved, offset=offset)


@router.get(
    "/incidents/{incident_id}/edges",
    response_model=ListEnvelope[IncidentEdgeItem],
)
def v1_incident_edges(
    incident_id: str,
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> ListEnvelope[IncidentEdgeItem]:
    resolved = clamp_limit(
        limit, DEFAULT_INCIDENT_TIMELINE_LIMIT, MAX_TIMELINE_LIMIT
    )
    result = list_incident_edges(
        connection, incident_id, limit=resolved, offset=offset
    )
    if result is None:
        raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")
    return envelope(
        result.edges, total=result.total, limit=resolved, offset=offset
    )
