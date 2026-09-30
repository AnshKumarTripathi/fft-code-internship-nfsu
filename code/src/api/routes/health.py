"""Health endpoint."""

from __future__ import annotations

import duckdb
from fastapi import APIRouter, Depends

from src.api.deps import get_db
from src.api.queries import db_reachable
from src.api.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness: process is up; warehouse is not opened."""
    return HealthResponse(status="ok", db="not_checked")


@router.get("/health/ready", response_model=HealthResponse)
def health_ready(
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> HealthResponse:
    """Readiness: warehouse opens read-only."""
    reachable = db_reachable(connection)
    return HealthResponse(
        status="ok" if reachable else "degraded",
        db="reachable" if reachable else "unreachable",
    )
