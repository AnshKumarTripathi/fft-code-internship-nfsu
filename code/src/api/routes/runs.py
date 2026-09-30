"""JSON pipeline_runs routes."""

from __future__ import annotations

import duckdb
from fastapi import APIRouter, Depends, Query

from src.api.deps import get_db
from src.api.queries import list_pipeline_runs
from src.api.schemas import PipelineRunItem

router = APIRouter(prefix="/api", tags=["runs"])


@router.get("/runs", response_model=list[PipelineRunItem])
def api_list_runs(
    limit: int = Query(default=50, ge=1, le=200),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> list[PipelineRunItem]:
    return list_pipeline_runs(connection, limit=limit)
