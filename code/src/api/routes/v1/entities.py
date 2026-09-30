"""v1 entity JSON routes."""

from __future__ import annotations

from datetime import datetime

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api.deps import get_db, load_app_config
from src.api.queries import (
    DEFAULT_BUCKET_LIMIT,
    DEFAULT_ENTITY_RANK_LIMIT,
    DEFAULT_ENTITY_SEARCH_LIMIT,
    DEFAULT_TIMELINE_LIMIT,
    MAX_ENTITY_RANK_LIMIT,
    MAX_ENTITY_SEARCH_LIMIT,
    MAX_INCIDENT_LIMIT,
    MAX_TIMELINE_LIMIT,
    clamp_limit,
    count_entities,
    count_entity_buckets,
    count_entity_timeline,
    count_incidents,
    get_entity_bucket_seconds,
    get_entity_meta,
    get_entity_spectrum,
    get_entity_stft,
    list_entity_buckets,
    list_entity_incidents,
    list_entity_timeline,
    list_flagged_windows,
    list_top_entities_by_anomaly_count,
    search_entities,
)
from src.api.routes.v1._common import OFFSET_QUERY, envelope, require_entity
from src.api.schemas import (
    BucketSeriesResponse,
    EntityAnomalyRank,
    EntityMeta,
    IncidentItem,
    ListEnvelope,
    SpectrumResponse,
    StftMatrixResponse,
    TimelineEvent,
)
from src.config import ui_honesty_settings

router = APIRouter(tags=["v1-entities"])


@router.get("/entities", response_model=ListEnvelope[EntityMeta])
def v1_search_entities(
    q: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> ListEnvelope[EntityMeta]:
    query = q.strip() if q and q.strip() else None
    resolved = clamp_limit(
        limit, DEFAULT_ENTITY_SEARCH_LIMIT, MAX_ENTITY_SEARCH_LIMIT
    )
    items = search_entities(connection, query, limit=resolved, offset=offset)
    total = count_entities(connection, query)
    return envelope(items, total=total, limit=resolved, offset=offset)


@router.get("/entities/top", response_model=ListEnvelope[EntityAnomalyRank])
def v1_entities_top_by_anomalies(
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> ListEnvelope[EntityAnomalyRank]:
    """Rank entities by anomaly_events count (then incident count)."""
    resolved = clamp_limit(limit, DEFAULT_ENTITY_RANK_LIMIT, MAX_ENTITY_RANK_LIMIT)
    items = list_top_entities_by_anomaly_count(
        connection, limit=resolved, offset=offset
    )
    total = count_entities(connection, None)
    return envelope(items, total=total, limit=resolved, offset=offset)


@router.get("/entities/{entity_id}", response_model=EntityMeta)
def v1_get_entity(
    entity_id: str,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> EntityMeta:
    require_entity(connection, entity_id)
    meta = get_entity_meta(connection, entity_id)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"Entity not found: {entity_id}")
    return meta


@router.get(
    "/entities/{entity_id}/timeline",
    response_model=ListEnvelope[TimelineEvent],
)
def v1_entity_timeline(
    entity_id: str,
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
    order: str | None = Query(default=None),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> ListEnvelope[TimelineEvent]:
    require_entity(connection, entity_id)
    resolved = clamp_limit(limit, DEFAULT_TIMELINE_LIMIT, MAX_TIMELINE_LIMIT)
    items = list_entity_timeline(
        connection,
        entity_id,
        start=start,
        end=end,
        limit=resolved,
        offset=offset,
        order=order,
    )
    total = count_entity_timeline(
        connection, entity_id, start=start, end=end
    )
    return envelope(items, total=total, limit=resolved, offset=offset)


@router.get("/entities/{entity_id}/spectrum", response_model=SpectrumResponse)
def v1_entity_spectrum(
    request: Request,
    entity_id: str,
    downsample: bool = Query(default=True),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> SpectrumResponse:
    require_entity(connection, entity_id)
    policy = ui_honesty_settings(load_app_config(request))
    spectrum = get_entity_spectrum(
        connection,
        entity_id,
        downsample=downsample,
        z_threshold=policy["spectral_z_threshold"],
        warn_band=policy["warn_band"],
    )
    if spectrum is None:
        raise HTTPException(
            status_code=404,
            detail=f"No spectral baseline or features for entity: {entity_id}",
        )
    return spectrum


@router.get("/entities/{entity_id}/stft", response_model=StftMatrixResponse)
def v1_entity_stft(
    request: Request,
    entity_id: str,
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> StftMatrixResponse:
    """Capped STFT power matrix for heatmap UI (Phase 60)."""
    require_entity(connection, entity_id)
    config = load_app_config(request)
    return get_entity_stft(
        connection,
        entity_id,
        config=config,
        start=start,
        end=end,
    )


@router.get(
    "/entities/{entity_id}/buckets",
    response_model=BucketSeriesResponse,
)
def v1_entity_buckets(
    entity_id: str,
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
    order: str | None = Query(default=None),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> BucketSeriesResponse:
    require_entity(connection, entity_id)
    resolved = clamp_limit(limit, DEFAULT_BUCKET_LIMIT, DEFAULT_BUCKET_LIMIT)
    items = list_entity_buckets(
        connection,
        entity_id,
        start=start,
        end=end,
        limit=resolved,
        offset=offset,
        order=order,
    )
    total = count_entity_buckets(
        connection, entity_id, start=start, end=end
    )
    overlays = list_flagged_windows(
        connection, entity_id, start=start, end=end
    )
    return BucketSeriesResponse(
        items=items,
        total=total,
        limit=resolved,
        offset=offset,
        overlays=overlays,
        bucket_seconds=get_entity_bucket_seconds(connection, entity_id),
    )


@router.get(
    "/entities/{entity_id}/incidents",
    response_model=ListEnvelope[IncidentItem],
)
def v1_entity_incidents(
    entity_id: str,
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> ListEnvelope[IncidentItem]:
    require_entity(connection, entity_id)
    resolved = clamp_limit(limit, 50, MAX_INCIDENT_LIMIT)
    items = list_entity_incidents(
        connection, entity_id, limit=resolved, offset=offset
    )
    total = count_incidents(connection, entity_id=entity_id)
    return envelope(items, total=total, limit=resolved, offset=offset)
