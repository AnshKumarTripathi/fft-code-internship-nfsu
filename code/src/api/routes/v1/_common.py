"""Shared helpers for `/api/v1` routes."""

from __future__ import annotations

from typing import TypeVar

import duckdb
from fastapi import HTTPException, Query, Request

from src.api.deps import load_app_config
from src.api.queries import clamp_limit, entity_exists
from src.api.schemas import ListEnvelope
from src.config import dashboard_settings

T = TypeVar("T")

OFFSET_QUERY = Query(default=0, ge=0)


def envelope(
    items: list[T],
    *,
    total: int,
    limit: int,
    offset: int,
) -> ListEnvelope[T]:
    return ListEnvelope(items=items, total=total, limit=limit, offset=offset)


def clamped_page(
    request: Request,
    *,
    limit: int | None,
    offset: int,
    default_key: str = "default_incident_limit",
    max_key: str = "max_incident_limit",
) -> tuple[int, int]:
    settings = dashboard_settings(load_app_config(request))
    resolved = clamp_limit(
        limit,
        int(settings[default_key]),
        int(settings[max_key]),
    )
    return resolved, offset


def require_entity(connection: duckdb.DuckDBPyConnection, entity_id: str) -> None:
    if not entity_exists(connection, entity_id):
        raise HTTPException(status_code=404, detail=f"Entity not found: {entity_id}")
