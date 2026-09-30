"""v1 report listing and file download."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse

from src.api.deps import load_app_config
from src.api.queries import clamp_limit
from src.api.report_files import (
    DEFAULT_REPORT_LIMIT,
    MAX_REPORT_LIMIT,
    list_report_files,
    media_type_for_report,
    resolve_report_file,
)
from src.api.routes.v1._common import OFFSET_QUERY, envelope
from src.api.schemas import ListEnvelope, ReportFileItem

router = APIRouter(tags=["v1-reports"])


def _report_dir(request: Request) -> Path:
    config = load_app_config(request)
    return Path(config["paths"]["report_dir"])


@router.get("/reports", response_model=ListEnvelope[ReportFileItem])
def v1_list_reports(
    request: Request,
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
) -> ListEnvelope[ReportFileItem]:
    resolved = clamp_limit(limit, DEFAULT_REPORT_LIMIT, MAX_REPORT_LIMIT)
    items, total = list_report_files(
        _report_dir(request), limit=resolved, offset=offset
    )
    return envelope(items, total=total, limit=resolved, offset=offset)


@router.get("/reports/{filename}")
def v1_report_file(request: Request, filename: str) -> FileResponse:
    path = resolve_report_file(_report_dir(request), filename)
    if path is None:
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(
        path,
        media_type=media_type_for_report(path.name),
        filename=path.name,
        content_disposition_type="inline",
    )
