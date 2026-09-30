"""FastAPI dependencies: config path and read-only DuckDB connection."""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path
from typing import Any

import duckdb
from fastapi import HTTPException, Request

from src.config import ConfigError, load_config
from src.db.connection import get_connection, get_read_only_connection
from src.db.writer_lock import WarehouseBusyError

DEFAULT_CONFIG_PATH = "config/pipeline.yaml"
CONFIG_ENV = "PIPELINE_CONFIG"


def resolve_config_path(request: Request | None = None) -> Path:
    """Resolve config path from app state, env, or default."""
    if request is not None:
        configured = getattr(request.app.state, "config_path", None)
        if configured:
            return Path(configured)
    env_path = os.environ.get(CONFIG_ENV)
    if env_path:
        return Path(env_path)
    return Path(DEFAULT_CONFIG_PATH)


def load_app_config(request: Request) -> dict[str, Any]:
    path = resolve_config_path(request)
    try:
        return load_config(path)
    except ConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


WAREHOUSE_BUSY_DETAIL = (
    "Warehouse is busy. If a batch job is running, wait for it to finish."
)

WAREHOUSE_MISSING_DETAIL = (
    "Warehouse not found. Stage logs and start a run from Pipeline "
    "(or the lab was cleared and no run has been started yet)."
)


def get_db(request: Request) -> Generator[duckdb.DuckDBPyConnection, None, None]:
    """Yield a read-only DuckDB connection; close after the request."""
    config = load_app_config(request)
    try:
        connection = get_read_only_connection(config)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404, detail=WAREHOUSE_MISSING_DETAIL
        ) from exc
    except WarehouseBusyError as exc:
        raise HTTPException(status_code=503, detail=WAREHOUSE_BUSY_DETAIL) from exc
    except duckdb.Error as exc:
        detail = str(exc)
        if (
            "lock" in detail.lower()
            or "different configuration" in detail.lower()
            or "IOException" in type(exc).__name__
        ):
            detail = WAREHOUSE_BUSY_DETAIL
        else:
            detail = f"Unable to open warehouse read-only: {exc}"
        raise HTTPException(status_code=503, detail=detail) from exc
    try:
        yield connection
    finally:
        connection.close()


def get_db_writer(request: Request) -> Generator[duckdb.DuckDBPyConnection, None, None]:
    """Yield a writer connection for append-only analyst actions (R9)."""
    config = load_app_config(request)
    try:
        connection = get_connection(config)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404, detail=WAREHOUSE_MISSING_DETAIL
        ) from exc
    except WarehouseBusyError as exc:
        raise HTTPException(status_code=503, detail=WAREHOUSE_BUSY_DETAIL) from exc
    except duckdb.Error as exc:
        detail = str(exc)
        if (
            "lock" in detail.lower()
            or "different configuration" in detail.lower()
            or "IOException" in type(exc).__name__
        ):
            detail = WAREHOUSE_BUSY_DETAIL
        else:
            detail = f"Unable to open warehouse for write: {exc}"
        raise HTTPException(status_code=503, detail=detail) from exc
    try:
        yield connection
    finally:
        connection.close()
