"""v1 KPI JSON route."""

from __future__ import annotations

import duckdb
from fastapi import APIRouter, Depends

from src.api.deps import get_db
from src.api.queries import incident_kpis
from src.api.schemas import IncidentKpis

router = APIRouter(tags=["v1-kpis"])


@router.get("/kpis", response_model=IncidentKpis)
def v1_kpis(
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> IncidentKpis:
    return incident_kpis(connection)
