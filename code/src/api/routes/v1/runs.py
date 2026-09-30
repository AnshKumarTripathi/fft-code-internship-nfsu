"""v1 pipeline_runs JSON route."""

from __future__ import annotations

import duckdb
from fastapi import APIRouter, Depends, Query

from src.api.deps import get_db
from src.api.queries import (
    DEFAULT_RUNS_LIMIT,
    MAX_RUNS_LIMIT,
    clamp_limit,
    count_pipeline_runs,
    list_pipeline_runs,
)
from src.api.routes.v1._common import OFFSET_QUERY, envelope
from src.api.schemas import ListEnvelope, PipelineRunItem

router = APIRouter(tags=["v1-runs"])


@router.get("/runs", response_model=ListEnvelope[PipelineRunItem])
def v1_list_runs(
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> ListEnvelope[PipelineRunItem]:
    resolved = clamp_limit(limit, DEFAULT_RUNS_LIMIT, MAX_RUNS_LIMIT)
    items = list_pipeline_runs(connection, limit=resolved, offset=offset)
    total = count_pipeline_runs(connection)
    return envelope(items, total=total, limit=resolved, offset=offset)
