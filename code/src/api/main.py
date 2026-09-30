"""FastAPI application factory.

Run from the ``code/`` directory:

    pip install -r requirements-api.txt
    uvicorn src.api.main:app --host 127.0.0.1 --port 8000

Optional: set ``PIPELINE_CONFIG`` to an alternate ``pipeline.yaml`` path.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.api.routes import entities, health, incidents, legacy_stub, pages, runs
from src.api.routes.v1 import router as v1_router
from src.config import (
    ConfigError,
    DEFAULT_CORS_ORIGINS,
    DEFAULT_DASHBOARD,
    dashboard_settings,
    load_config,
)

API_ROOT = Path(__file__).resolve().parent
STATIC_DIR = API_ROOT / "static"
TEMPLATES_DIR = API_ROOT / "templates"
DEFAULT_CONFIG = "config/pipeline.yaml"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _dashboard_or_default(config_path: Path) -> dict:
    try:
        return dashboard_settings(load_config(config_path))
    except (ConfigError, OSError, FileNotFoundError):
        return dict(DEFAULT_DASHBOARD)


def create_app(config_path: str | Path | None = None) -> FastAPI:
    """Build the read-only JSON API with optional Jinja UI."""
    app = FastAPI(
        title="Log Anomaly Dashboard",
        description=(
            "JSON API (/api/v1). Investigation UI is Next.js on "
            "port 3000. POST /api/v1/actions is append-only analyst audit "
            "(dismiss/note/reopen). POST /api/v1/pipeline/jobs starts a "
            "background run-all (Phase 56; single-flight). "
            "POST /api/v1/pipeline/uploads stages logs under raw (Phase 57). "
            "POST /api/v1/copilot/chat is assistive Q/A (Phase 96; dual-gate). "
            "Optional Jinja when dashboard.serve_legacy_html is true. "
            "Local trusted network only — no auth."
        ),
        version="0.96.0",
    )
    resolved = Path(config_path or os.environ.get("PIPELINE_CONFIG", DEFAULT_CONFIG))
    app.state.config_path = str(resolved)
    settings = _dashboard_or_default(resolved)
    serve_legacy_html = bool(settings["serve_legacy_html"])

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.get("cors_origins") or DEFAULT_CORS_ORIGINS),
        allow_credentials=False,
        allow_methods=["GET", "HEAD", "OPTIONS", "POST", "DELETE"],
        allow_headers=["Accept", "Content-Type"],
    )

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.exception_handler(HTTPException)
    async def handle_http_exception(request: Request, exc: HTTPException):
        if exc.status_code == 503:
            path = request.url.path
            json_503 = (
                not serve_legacy_html
                or path.startswith("/api/")
                or path.startswith("/health")
            )
            if json_503:
                return await http_exception_handler(request, exc)
            return templates.TemplateResponse(
                request,
                "warehouse_busy.html",
                {},
                status_code=503,
            )
        return await http_exception_handler(request, exc)

    app.include_router(health.router)
    app.include_router(incidents.router)
    app.include_router(entities.router)
    app.include_router(runs.router)
    app.include_router(v1_router)
    if serve_legacy_html:
        app.include_router(pages.router)
    else:
        app.include_router(legacy_stub.router)
    return app


app = create_app()
