"""404 stubs for Jinja investigation routes when legacy HTML is off."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

LEGACY_HTML_OFF_DETAIL = (
    "Investigation UI is Next.js on http://127.0.0.1:3000. "
    "Set dashboard.serve_legacy_html: true for legacy Jinja."
)

router = APIRouter(tags=["legacy-html-off"])


def _html_off() -> None:
    raise HTTPException(status_code=404, detail=LEGACY_HTML_OFF_DETAIL)


@router.get("/")
def stub_incidents_list() -> None:
    _html_off()


@router.get("/incidents/{incident_id}")
def stub_incident_detail(incident_id: str) -> None:
    _html_off()


@router.get("/entities")
def stub_entities_index() -> None:
    _html_off()


@router.get("/entities/{entity_id}")
def stub_entity_detail(entity_id: str) -> None:
    _html_off()


@router.get("/runs")
def stub_runs() -> None:
    _html_off()


@router.get("/reports")
def stub_reports() -> None:
    _html_off()
