"""Phase 96 — assistive copilot chat (Pocket Flow + allow-listed tools)."""

from __future__ import annotations

import logging
from collections.abc import Generator
from pathlib import Path

import duckdb
from fastapi import APIRouter, Depends, HTTPException, Request

from src.api.deps import (
    WAREHOUSE_BUSY_DETAIL,
    WAREHOUSE_MISSING_DETAIL,
    load_app_config,
)
from src.api.schemas import (
    CopilotChatRequest,
    CopilotChatResponse,
    CopilotCitation,
    CopilotStatusResponse,
)
from src.config import copilot_settings, explainability_settings
from src.copilot.docs_loader import default_docs_root
from src.copilot.flow import run_chat_turn
from src.copilot.provider import CopilotProviderError, build_provider, resolve_display_model
from src.copilot.settings import (
    is_copilot_runtime_enabled,
    load_copilot_env_settings,
)
from src.copilot.tools import ToolContext
from src.db.connection import get_read_only_connection
from src.db.writer_lock import WarehouseBusyError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["v1-copilot"])


@router.get("/copilot/status", response_model=CopilotStatusResponse)
def v1_copilot_status(request: Request) -> CopilotStatusResponse:
    """Whether the assistive copilot is dual-gate enabled (no secrets)."""
    config = load_app_config(request)
    yaml_flags = copilot_settings(config)
    try:
        env = load_copilot_env_settings()
    except ValueError as exc:
        return CopilotStatusResponse(
            enabled=False,
            provider="unknown",
            model="",
            reason=str(exc),
        )
    enabled = is_copilot_runtime_enabled(
        yaml_enabled=bool(yaml_flags["enabled"]),
        env_settings=env,
    )
    return CopilotStatusResponse(
        enabled=enabled,
        provider=env.provider,
        model=resolve_display_model(env),
        reason=None if enabled else "dual_gate_off",
    )


def get_db_optional(
    request: Request,
) -> Generator[duckdb.DuckDBPyConnection | None, None, None]:
    """Yield a read-only warehouse connection, or None if the file is missing.

    Incident tools soft-fail when connection is None; docs-only chat still works.
    Busy warehouse remains HTTP 503.
    """
    config = load_app_config(request)
    try:
        connection = get_read_only_connection(config)
    except FileNotFoundError:
        yield None
        return
    except WarehouseBusyError as exc:
        raise HTTPException(status_code=503, detail=WAREHOUSE_BUSY_DETAIL) from exc
    except duckdb.Error as exc:
        detail = str(exc)
        if (
            "lock" in detail.lower()
            or "different configuration" in detail.lower()
            or "IOException" in type(exc).__name__
        ):
            raise HTTPException(status_code=503, detail=WAREHOUSE_BUSY_DETAIL) from exc
        raise HTTPException(
            status_code=503,
            detail=f"Unable to open warehouse read-only: {exc}",
        ) from exc
    try:
        yield connection
    finally:
        connection.close()


@router.post("/copilot/chat", response_model=CopilotChatResponse)
def v1_copilot_chat(
    request: Request,
    body: CopilotChatRequest,
    connection: duckdb.DuckDBPyConnection | None = Depends(get_db_optional),
) -> CopilotChatResponse:
    """Non-streaming chat turn. SSE streaming is deferred (documented in phase 96)."""
    config = load_app_config(request)
    yaml_flags = copilot_settings(config)
    try:
        env = load_copilot_env_settings()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if not is_copilot_runtime_enabled(
        yaml_enabled=bool(yaml_flags["enabled"]),
        env_settings=env,
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "Copilot disabled. Set COPILOT_ENABLED=true in code/.env and "
                "copilot.enabled: true in pipeline.yaml (dual-gate)."
            ),
        )

    if not body.messages:
        raise HTTPException(status_code=400, detail="messages must be non-empty")

    if body.incident_id and connection is None:
        raise HTTPException(status_code=404, detail=WAREHOUSE_MISSING_DETAIL)

    try:
        expl = explainability_settings(config)
        warn_band = float(expl["warn_band"])
    except Exception:
        warn_band = 0.5

    tool_ctx = ToolContext(
        connection=connection,
        config=config,
        report_dir=Path(config["paths"]["report_dir"]),
        docs_root=default_docs_root(),
        max_timeline_events=int(yaml_flags["max_timeline_events"]),
        warn_band=warn_band,
    )

    try:
        provider = build_provider(env)
    except CopilotProviderError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    messages = [{"role": m.role, "content": m.content} for m in body.messages]
    attachments = [a.model_dump() for a in body.attachments]

    try:
        result = run_chat_turn(
            messages=messages,
            attachments=attachments,
            incident_id=body.incident_id,
            analysis_id=body.analysis_id,
            tool_context=tool_ctx,
            provider=provider,
            env_settings=env,
            max_attachment_chars=int(yaml_flags["max_attachment_chars"]),
        )
    except CopilotProviderError as exc:
        logger.warning("Copilot provider failed: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Copilot chat turn failed")
        raise HTTPException(
            status_code=503,
            detail="Copilot chat failed (soft-fail)",
        ) from exc

    citations = [
        CopilotCitation(source=str(item.get("source")), ref=str(item.get("ref")))
        for item in result.get("citations") or []
        if isinstance(item, dict)
    ]
    return CopilotChatResponse(
        reply=str(result.get("reply") or ""),
        citations=citations,
        tools_used=list(result.get("tools_used") or []),
        provider=str(result.get("provider") or env.provider),
        model=str(result.get("model") or env.model),
    )
