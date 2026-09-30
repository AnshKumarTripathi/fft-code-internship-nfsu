"""v1 analysis containers + triage snapshots (Phases 65–66)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api.analyses import (
    create_analysis,
    get_analysis,
    list_analyses,
    normalize_analysis_label,
    normalize_analysis_notes,
    update_analysis,
)
from src.api.analysis_snapshots import (
    filter_snapshot_incidents,
    latest_ready_analysis_id,
    read_triage_snapshot,
    snapshot_exists,
    snapshot_kpis,
)
from src.api.deps import get_db, get_db_writer, load_app_config
from src.api.queries import (
    count_incidents,
    incident_kpis,
    list_incidents,
    parse_detector_filters,
)
from src.api.routes.v1._common import OFFSET_QUERY, clamped_page, envelope
from src.api.schemas import (
    AnalysisCreate,
    AnalysisItem,
    AnalysisUpdate,
    IncidentItem,
    IncidentKpis,
    ListEnvelope,
)

router = APIRouter(prefix="/analyses", tags=["v1-analyses"])

DispositionParam = Literal["open", "dismissed", "any"]
SortParam = Literal["severity", "start_time", "anomaly_count"]
OrderParam = Literal["asc", "desc"]


@router.post("", response_model=AnalysisItem, status_code=201)
def v1_create_analysis(
    payload: AnalysisCreate,
    connection: duckdb.DuckDBPyConnection = Depends(get_db_writer),
) -> AnalysisItem:
    try:
        label = normalize_analysis_label(payload.label)
        notes = normalize_analysis_notes(payload.notes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return create_analysis(connection, label=label, notes=notes, status="draft")


@router.get("", response_model=ListEnvelope[AnalysisItem])
def v1_list_analyses(
    request: Request,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
) -> ListEnvelope[AnalysisItem]:
    page_limit, page_offset = clamped_page(
        request,
        limit=limit,
        offset=offset,
        default_key="default_incident_limit",
        max_key="max_incident_limit",
    )
    items, total = list_analyses(
        connection, limit=page_limit, offset=page_offset
    )
    return envelope(items, total=total, limit=page_limit, offset=page_offset)


@router.get("/{analysis_id}/incidents", response_model=ListEnvelope[IncidentItem])
def v1_list_analysis_incidents(
    analysis_id: str,
    request: Request,
    severity: str | None = Query(default=None),
    entity_id: str | None = Query(default=None),
    q: str | None = Query(default=None),
    start_after: datetime | None = Query(default=None),
    end_before: datetime | None = Query(default=None),
    detector: list[str] | None = Query(default=None),
    min_detectors: int | None = Query(default=None, ge=1),
    disposition: DispositionParam | None = Query(default=None),
    sort: SortParam | None = Query(default=None),
    order: OrderParam | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1),
    offset: int = OFFSET_QUERY,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> ListEnvelope[IncidentItem]:
    analysis = get_analysis(connection, analysis_id.strip())
    if analysis is None:
        raise HTTPException(
            status_code=404, detail=f"Analysis not found: {analysis_id}"
        )
    config = load_app_config(request)
    page_limit, page_offset = clamped_page(request, limit=limit, offset=offset)
    q_f = q.strip() if q and q.strip() else None
    detectors = parse_detector_filters(detector)

    if snapshot_exists(config, analysis.analysis_id):
        payload = read_triage_snapshot(config, analysis.analysis_id)
        if payload is None:
            raise HTTPException(
                status_code=500,
                detail=f"Snapshot unreadable for analysis: {analysis_id}",
            )
        items, total = filter_snapshot_incidents(
            payload,
            severity=severity,
            entity_id=entity_id,
            q=q_f,
            start_after=start_after,
            end_before=end_before,
            detectors=detectors or None,
            min_detectors=min_detectors,
            sort=sort,
            order=order,
            limit=page_limit,
            offset=page_offset,
        )
        return envelope(items, total=total, limit=page_limit, offset=page_offset)

    # No snapshot yet: only the latest ready analysis may fall back to live.
    latest_id = latest_ready_analysis_id(connection)
    if analysis.status == "ready" and latest_id == analysis.analysis_id:
        filter_kwargs = {
            "severity": severity,
            "entity_id": entity_id,
            "q": q_f,
            "start_after": start_after,
            "end_before": end_before,
            "detectors": detectors or None,
            "min_detectors": min_detectors,
            "disposition": disposition,
        }
        items = list_incidents(
            connection,
            **filter_kwargs,
            sort=sort,
            order=order,
            limit=page_limit,
            offset=page_offset,
        )
        total = count_incidents(connection, **filter_kwargs)
        return envelope(items, total=total, limit=page_limit, offset=page_offset)

    raise HTTPException(
        status_code=404,
        detail=(
            "No triage snapshot for this analysis yet. "
            "Snapshots are written after a successful correlate."
        ),
    )


@router.get("/{analysis_id}/kpis", response_model=IncidentKpis)
def v1_analysis_kpis(
    analysis_id: str,
    request: Request,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> IncidentKpis:
    analysis = get_analysis(connection, analysis_id.strip())
    if analysis is None:
        raise HTTPException(
            status_code=404, detail=f"Analysis not found: {analysis_id}"
        )
    config = load_app_config(request)
    if snapshot_exists(config, analysis.analysis_id):
        payload = read_triage_snapshot(config, analysis.analysis_id)
        if payload is None:
            raise HTTPException(
                status_code=500,
                detail=f"Snapshot unreadable for analysis: {analysis_id}",
            )
        return snapshot_kpis(payload)

    latest_id = latest_ready_analysis_id(connection)
    if analysis.status == "ready" and latest_id == analysis.analysis_id:
        return incident_kpis(connection)

    raise HTTPException(
        status_code=404,
        detail=(
            "No triage snapshot for this analysis yet. "
            "Snapshots are written after a successful correlate."
        ),
    )


@router.get("/{analysis_id}", response_model=AnalysisItem)
def v1_get_analysis(
    analysis_id: str,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> AnalysisItem:
    item = get_analysis(connection, analysis_id.strip())
    if item is None:
        raise HTTPException(
            status_code=404, detail=f"Analysis not found: {analysis_id}"
        )
    return item


@router.patch("/{analysis_id}", response_model=AnalysisItem)
def v1_patch_analysis(
    analysis_id: str,
    payload: AnalysisUpdate,
    connection: duckdb.DuckDBPyConnection = Depends(get_db_writer),
) -> AnalysisItem:
    if payload.label is None and payload.notes is None:
        raise HTTPException(
            status_code=422, detail="provide label and/or notes to update"
        )
    label: str | None = None
    notes: str | None = None
    notes_provided = "notes" in payload.model_fields_set
    try:
        if payload.label is not None:
            label = normalize_analysis_label(payload.label)
        if notes_provided:
            notes = normalize_analysis_notes(payload.notes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    item = update_analysis(
        connection,
        analysis_id.strip(),
        label=label,
        notes=notes,
        notes_provided=notes_provided,
    )
    if item is None:
        raise HTTPException(
            status_code=404, detail=f"Analysis not found: {analysis_id}"
        )
    return item
