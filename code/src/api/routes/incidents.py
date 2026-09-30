"""JSON incidents routes."""

from __future__ import annotations

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.deps import get_db
from src.api.queries import (
    DEFAULT_INCIDENT_LIMIT,
    MAX_INCIDENT_LIMIT,
    list_incident_edges,
    list_incidents,
)
from src.api.schemas import IncidentEdgeItem, IncidentItem

router = APIRouter(prefix="/api", tags=["incidents"])


@router.get("/incidents", response_model=list[IncidentItem])
def api_list_incidents(
    severity: str | None = Query(default=None),
    entity_id: str | None = Query(default=None),
    limit: int = Query(default=DEFAULT_INCIDENT_LIMIT, ge=1, le=MAX_INCIDENT_LIMIT),
    offset: int = Query(default=0, ge=0),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> list[IncidentItem]:
    return list_incidents(
        connection,
        severity=severity,
        entity_id=entity_id,
        limit=limit,
        offset=offset,
    )


@router.get("/incidents/{incident_id}/edges", response_model=list[IncidentEdgeItem])
def api_incident_edges(
    incident_id: str,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> list[IncidentEdgeItem]:
    result = list_incident_edges(connection, incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")
    return result.edges
