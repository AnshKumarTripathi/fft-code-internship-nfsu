"""v1 append-only analyst actions (R9)."""

from __future__ import annotations

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Request

from src.api.deps import get_db, get_db_writer, load_app_config
from src.api.queries import (
    ANALYST_ACTIONS,
    MAX_ACTION_NOTE_LENGTH,
    MAX_OPERATOR_LABEL_LENGTH,
    get_incident,
    insert_analyst_action,
    list_analyst_actions,
)
from src.api.schemas import AnalystActionCreate, AnalystActionItem
from src.config import dashboard_settings

router = APIRouter(tags=["v1-actions"])


def _normalize_label(value: str | None, default: str) -> str:
    raw = (value or default or "local").strip()
    if not raw:
        raw = default or "local"
    return raw[:MAX_OPERATOR_LABEL_LENGTH]


def _normalize_note(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if len(text) > MAX_ACTION_NOTE_LENGTH:
        raise HTTPException(
            status_code=422,
            detail=f"note must be at most {MAX_ACTION_NOTE_LENGTH} characters",
        )
    return text


@router.post("/actions", response_model=AnalystActionItem)
def v1_create_action(
    payload: AnalystActionCreate,
    request: Request,
    connection: duckdb.DuckDBPyConnection = Depends(get_db_writer),
) -> AnalystActionItem:
    action = (payload.action or "").strip().lower()
    if action not in ANALYST_ACTIONS:
        raise HTTPException(
            status_code=422,
            detail=f"action must be one of {sorted(ANALYST_ACTIONS)}",
        )
    incident_id = (payload.incident_id or "").strip()
    if not incident_id:
        raise HTTPException(status_code=422, detail="incident_id is required")
    incident = get_incident(connection, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")
    anomaly_id = (payload.anomaly_id or "").strip() or None
    if action in {"dismiss", "reopen"} and not anomaly_id:
        raise HTTPException(
            status_code=422,
            detail=f"{action} requires anomaly_id",
        )
    if anomaly_id and anomaly_id not in incident.contributing_anomaly_ids:
        raise HTTPException(
            status_code=422,
            detail="anomaly_id is not a contributing anomaly of this incident",
        )
    note = _normalize_note(payload.note)
    if action == "note" and not note:
        raise HTTPException(status_code=422, detail="note action requires a note")
    settings = dashboard_settings(load_app_config(request))
    operator_label = _normalize_label(
        payload.operator_label, str(settings["operator_label"])
    )
    run_id = (payload.run_id or "").strip() or None
    return insert_analyst_action(
        connection,
        incident_id=incident_id,
        anomaly_id=anomaly_id,
        action=action,
        note=note,
        operator_label=operator_label,
        run_id=run_id,
    )


@router.get(
    "/incidents/{incident_id}/actions",
    response_model=list[AnalystActionItem],
)
def v1_list_incident_actions(
    incident_id: str,
    connection: duckdb.DuckDBPyConnection = Depends(get_db),
) -> list[AnalystActionItem]:
    incident = get_incident(connection, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")
    return list_analyst_actions(connection, incident_id)
