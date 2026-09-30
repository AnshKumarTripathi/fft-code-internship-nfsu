"""HTML page routes for the analyst dashboard."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from src.api.deps import get_db, load_app_config
from src.api.queries import (
    MAX_INCIDENT_LIMIT,
    count_incidents,
    entity_exists,
    get_entity_meta,
    get_entity_spectrum,
    get_incident,
    incident_kpis,
    list_entity_buckets,
    list_entity_incidents,
    list_entity_timeline,
    list_flagged_windows,
    list_incident_edges,
    list_incidents,
    list_pipeline_runs,
    load_anomalies,
    resolve_series_order,
    search_entities,
)
from src.api.report_files import is_safe_report_filename, resolve_report_file
from src.config import dashboard_settings
from src.reporting.report_generator import report_filename

router = APIRouter(tags=["pages"])

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SEVERITIES = ("critical", "high", "medium", "low")
DETECTOR_ORDER = (
    "statistical",
    "spectral",
    "ml",
    "cluster_outlier",
    "changepoint",
    "seasonal",
)
DETECTOR_ROLES = {
    "statistical": "rate",
    "spectral": "rhythm",
    "ml": "sequence",
    "cluster_outlier": "peer-outlier",
    "changepoint": "level-shift",
    "seasonal": "seasonal-residual",
}


def entity_href(
    entity_id: object,
    start: object = None,
    end: object = None,
    pad_hours: object = None,
) -> str:
    path = "/entities/" + quote(str(entity_id), safe="")
    params: dict[str, str] = {}
    if start is not None:
        params["start"] = start.isoformat() if hasattr(start, "isoformat") else str(start)
    if end is not None:
        params["end"] = end.isoformat() if hasattr(end, "isoformat") else str(end)
    if pad_hours:
        params["pad_hours"] = str(int(pad_hours))
    if params:
        return path + "?" + urlencode(params)
    return path


templates.env.filters["entity_href"] = entity_href
templates.env.filters["detector_role"] = lambda name: DETECTOR_ROLES.get(str(name), str(name))


def _json_default(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _activity_payload(
    buckets: list[Any],
    overlays: list[Any],
) -> str:
    chart_buckets = sorted(
        buckets,
        key=lambda point: point.bucket_start
        or datetime(1970, 1, 1, tzinfo=timezone.utc),
    )
    return json.dumps(
        {
            "labels": [
                b.bucket_start.isoformat() if b.bucket_start else ""
                for b in chart_buckets
            ],
            "values": [b.event_count for b in chart_buckets],
            "overlays": [
                {
                    "start": w.window_start.isoformat() if w.window_start else "",
                    "end": w.window_end.isoformat() if w.window_end else "",
                    "source": w.source,
                }
                for w in overlays
                if w.window_start and w.window_end
            ],
        },
        default=_json_default,
    )


def _expand_window(
    start: datetime | None,
    end: datetime | None,
    pad_hours: int,
) -> tuple[datetime | None, datetime | None]:
    if pad_hours <= 0:
        return start, end
    delta = timedelta(hours=pad_hours)
    padded_start = start - delta if start is not None else None
    padded_end = end + delta if end is not None else None
    return padded_start, padded_end


def _report_dir(request: Request) -> Path:
    config = load_app_config(request)
    return Path(config["paths"]["report_dir"])


def _report_hrefs(report_dir: Path, incident_id: str) -> tuple[str | None, str | None]:
    md_name = report_filename(incident_id, suffix="md")
    html_name = report_filename(incident_id, suffix="html")
    md_href = f"/reports/{md_name}" if (report_dir / md_name).is_file() else None
    html_href = f"/reports/{html_name}" if (report_dir / html_name).is_file() else None
    return md_href, html_href


def _safe_report_file(report_dir: Path, filename: str) -> Path:
    if not is_safe_report_filename(filename):
        raise HTTPException(status_code=400, detail="Invalid report filename")
    candidate = resolve_report_file(report_dir, filename)
    if candidate is None:
        raise HTTPException(status_code=404, detail="Report file not found")
    return candidate


@router.get("/", response_class=HTMLResponse)
def page_incidents_list(
    request: Request,
    severity: str | None = Query(default=None),
    entity_id: str | None = Query(default=None),
    q: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> HTMLResponse:
    settings = dashboard_settings(load_app_config(request))
    limit = int(settings["default_incident_limit"])
    offset = (page - 1) * limit
    severity_f = severity or None
    entity_f = entity_id or None
    q_f = q.strip() if q and q.strip() else None
    total = count_incidents(
        connection, severity=severity_f, entity_id=entity_f, q=q_f
    )
    incidents = list_incidents(
        connection,
        severity=severity_f,
        entity_id=entity_f,
        q=q_f,
        limit=limit,
        offset=offset,
    )
    showing_from = offset + 1 if incidents else 0
    showing_to = offset + len(incidents)
    total_pages = max(1, (total + limit - 1) // limit) if total else 1
    kpis = incident_kpis(connection)
    filter_params = {
        key: value
        for key, value in {
            "severity": severity or "",
            "entity_id": entity_id or "",
            "q": q or "",
        }.items()
        if value
    }
    return templates.TemplateResponse(
        request,
        "incidents_list.html",
        {
            "incidents": incidents,
            "severity": severity or "",
            "entity_id": entity_id or "",
            "q": q or "",
            "severities": SEVERITIES,
            "kpis": kpis,
            "page": page,
            "total": total,
            "showing_from": showing_from,
            "showing_to": showing_to,
            "total_pages": total_pages,
            "filter_qs": urlencode(filter_params),
        },
    )


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
def page_incident_detail(
    request: Request,
    incident_id: str,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> HTMLResponse:
    incident = get_incident(connection, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")
    settings = dashboard_settings(load_app_config(request))
    pad_hours = int(settings["incident_chart_pad_hours"])
    anomalies = load_anomalies(connection, incident.contributing_anomaly_ids)
    present_detectors = {a.source_detector for a in anomalies}
    entity = get_entity_meta(connection, incident.entity_id)
    edges_result = list_incident_edges(connection, incident_id, limit=100)
    chart_start, chart_end = _expand_window(
        incident.start_time, incident.end_time, pad_hours
    )
    buckets = list_entity_buckets(
        connection,
        incident.entity_id,
        start=chart_start,
        end=chart_end,
        order="oldest",
    )
    overlays = list_flagged_windows(
        connection,
        incident.entity_id,
        start=chart_start,
        end=chart_end,
    )
    config = load_app_config(request)
    report_dir = Path(config["paths"]["report_dir"])
    report_md_href, report_html_href = _report_hrefs(report_dir, incident.incident_id)
    return templates.TemplateResponse(
        request,
        "incident_detail.html",
        {
            "incident": incident,
            "anomalies": anomalies,
            "entity": entity,
            "detector_order": DETECTOR_ORDER,
            "present_detectors": present_detectors,
            "edges": edges_result.edges if edges_result else [],
            "edges_total": edges_result.total if edges_result else 0,
            "edges_shown": len(edges_result.edges) if edges_result else 0,
            "entity_window_href": entity_href(
                incident.entity_id,
                incident.start_time,
                incident.end_time,
                pad_hours=1,
            ),
            "activity_json": _activity_payload(buckets, overlays),
            "has_buckets": bool(buckets),
            "report_md_href": report_md_href,
            "report_html_href": report_html_href,
        },
    )


@router.get("/entities", response_class=HTMLResponse)
def page_entities_index(
    request: Request,
    q: str | None = Query(default=None),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> HTMLResponse:
    query = q.strip() if q and q.strip() else None
    entities = search_entities(connection, query, limit=50)
    return templates.TemplateResponse(
        request,
        "entities_index.html",
        {"entities": entities, "q": q or ""},
    )


@router.get("/entities/{entity_id}", response_class=HTMLResponse)
def page_entity_detail(
    request: Request,
    entity_id: str,
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    order: str | None = Query(default=None),
    pad_hours: int = Query(default=0, ge=0),
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> HTMLResponse:
    if not entity_exists(connection, entity_id):
        raise HTTPException(status_code=404, detail=f"Entity not found: {entity_id}")

    entity = get_entity_meta(connection, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail=f"Entity not found: {entity_id}")

    window_start, window_end = _expand_window(start, end, pad_hours)
    settings = dashboard_settings(load_app_config(request))
    timeline_limit = int(settings["default_timeline_limit"])
    buckets = list_entity_buckets(
        connection, entity_id, start=window_start, end=window_end, order=order
    )
    timeline = list_entity_timeline(
        connection,
        entity_id,
        start=window_start,
        end=window_end,
        order=order,
        limit=timeline_limit,
    )
    spectrum = get_entity_spectrum(connection, entity_id, downsample=True)
    overlays = list_flagged_windows(
        connection, entity_id, start=window_start, end=window_end
    )
    incidents = list_entity_incidents(connection, entity_id)
    resolved_order = resolve_series_order(order, start=window_start, end=window_end)
    config = load_app_config(request)
    bucket_seconds = (
        spectrum.bucket_seconds
        if spectrum is not None and spectrum.bucket_seconds is not None
        else int(config["bucketing"]["bucket_seconds"])
    )

    psd_json = json.dumps(
        {
            "freq": [round(f, 6) for f in (spectrum.freq_grid if spectrum else [])],
            "psd": list(spectrum.psd_norm) if spectrum else [],
        }
    )

    return templates.TemplateResponse(
        request,
        "entity_detail.html",
        {
            "entity": entity,
            "buckets": buckets,
            "timeline": timeline,
            "spectrum": spectrum,
            "activity_json": _activity_payload(buckets, overlays),
            "psd_json": psd_json,
            "timeline_newest_first": resolved_order == "newest",
            "incidents": incidents,
            "window_start": window_start,
            "window_end": window_end,
            "bucket_seconds": bucket_seconds,
        },
    )


@router.get("/reports", response_class=HTMLResponse)
def page_reports_list(
    request: Request,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> HTMLResponse:
    incidents = list_incidents(connection, limit=MAX_INCIDENT_LIMIT)
    report_dir = _report_dir(request)
    rows = []
    for incident in incidents:
        md_href, html_href = _report_hrefs(report_dir, incident.incident_id)
        rows.append(
            {
                "incident": incident,
                "md_href": md_href,
                "html_href": html_href,
            }
        )
    return templates.TemplateResponse(
        request,
        "reports_list.html",
        {"rows": rows},
    )


@router.get("/reports/{filename}")
def page_report_file(
    request: Request,
    filename: str,
) -> FileResponse:
    path = _safe_report_file(_report_dir(request), filename)
    media = "text/html" if path.suffix.lower() == ".html" else "text/markdown"
    return FileResponse(
        path,
        media_type=media,
        filename=path.name,
        content_disposition_type="inline",
    )


@router.get("/runs", response_class=HTMLResponse)
def page_runs_list(
    request: Request,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> HTMLResponse:
    runs = list_pipeline_runs(connection, limit=50)
    return templates.TemplateResponse(
        request,
        "runs_list.html",
        {"runs": runs},
    )
