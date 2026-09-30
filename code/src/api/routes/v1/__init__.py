"""Versioned JSON API (`/api/v1`)."""

from fastapi import APIRouter

from src.api.routes.v1 import (
    actions,
    analyses,
    copilot,
    entities,
    incidents,
    kpis,
    pipeline,
    reports,
    runs,
    ui,
)

router = APIRouter(prefix="/api/v1")
router.include_router(incidents.router)
router.include_router(entities.router)
router.include_router(kpis.router)
router.include_router(runs.router)
router.include_router(reports.router)
router.include_router(ui.router)
router.include_router(actions.router)
router.include_router(pipeline.router)
router.include_router(analyses.router)
router.include_router(copilot.router)
