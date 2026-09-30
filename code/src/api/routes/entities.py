"""JSON entity timeline and spectrum routes."""

from __future__ import annotations

from datetime import datetime

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.deps import get_db
from src.api.queries import (
    DEFAULT_TIMELINE_LIMIT,
    MAX_TIMELINE_LIMIT,
    entity_exists,
    get_entity_spectrum,
    list_entity_timeline,
)
from src.api.schemas import SpectrumResponse, TimelineEvent

router = APIRouter(prefix="/api/entities", tags=["entities"])


@router.get("/{entity_id}/timeline", response_model=list[TimelineEvent])
def api_entity_timeline(
    entity_id: str,
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    limit: int = Query(default=DEFAULT_TIMELINE_LIMIT, ge=1, le=MAX_TIMELINE_LIMIT),
    order: str | None = Query(default=None),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> list[TimelineEvent]:
    if not entity_exists(connection, entity_id):
        raise HTTPException(status_code=404, detail=f"Entity not found: {entity_id}")
    return list_entity_timeline(
        connection,
        entity_id,
        start=start,
        end=end,
        limit=limit,
        order=order,
    )


@router.get("/{entity_id}/spectrum", response_model=SpectrumResponse)
def api_entity_spectrum(
    entity_id: str,
    downsample: bool = Query(default=True),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> SpectrumResponse:
    if not entity_exists(connection, entity_id):
        raise HTTPException(status_code=404, detail=f"Entity not found: {entity_id}")
    spectrum = get_entity_spectrum(
        connection,
        entity_id,
        downsample=downsample,
    )
    if spectrum is None:
        raise HTTPException(
            status_code=404,
            detail=f"No spectral baseline or features for entity: {entity_id}",
        )
    return spectrum
