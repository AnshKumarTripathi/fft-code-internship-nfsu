"""Analysis container CRUD + job binding (Phase 65)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import duckdb

from src.api.schemas import AnalysisItem
from src.ingestion.file_hash import merkle_sha256

UTC = timezone.utc

ANALYSIS_STATUSES = frozenset({"draft", "running", "ready", "failed"})
MAX_ANALYSIS_LABEL_LENGTH = 200
MAX_ANALYSIS_NOTES_LENGTH = 2000

_SELECT_COLS = (
    "analysis_id, label, created_at, updated_at, status, corpus_digest, "
    "file_count, job_id, correlate_run_id, notes"
)


def analyses_table_exists(connection: duckdb.DuckDBPyConnection) -> bool:
    row = connection.execute(
        """
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'main' AND lower(table_name) = 'analyses'
        LIMIT 1
        """
    ).fetchone()
    return row is not None


def _row_to_item(row: tuple[Any, ...]) -> AnalysisItem:
    return AnalysisItem(
        analysis_id=str(row[0]),
        label=str(row[1]),
        created_at=row[2] if isinstance(row[2], datetime) else None,
        updated_at=row[3] if isinstance(row[3], datetime) else None,
        status=str(row[4]),
        corpus_digest=str(row[5]) if row[5] else None,
        file_count=int(row[6]) if row[6] is not None else None,
        job_id=str(row[7]) if row[7] else None,
        correlate_run_id=str(row[8]) if row[8] else None,
        notes=str(row[9]) if row[9] else None,
    )


def normalize_analysis_label(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError("label is required")
    return text[:MAX_ANALYSIS_LABEL_LENGTH]


def normalize_analysis_notes(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if len(text) > MAX_ANALYSIS_NOTES_LENGTH:
        raise ValueError(
            f"notes must be at most {MAX_ANALYSIS_NOTES_LENGTH} characters"
        )
    return text


def corpus_digest_from_uploads(files: list[dict[str, Any]]) -> tuple[str, int]:
    digests = [str(item["sha256"]) for item in files if item.get("sha256")]
    return merkle_sha256(digests), len(files)


def default_analysis_label() -> str:
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"Analysis · {stamp}"


def create_analysis(
    connection: duckdb.DuckDBPyConnection,
    *,
    label: str,
    notes: str | None = None,
    status: str = "draft",
) -> AnalysisItem:
    if status not in ANALYSIS_STATUSES:
        raise ValueError(f"invalid analysis status: {status}")
    now = datetime.now(UTC)
    analysis_id = str(uuid.uuid4())
    connection.execute(
        """
        INSERT INTO analyses (
            analysis_id, label, created_at, updated_at, status,
            corpus_digest, file_count, job_id, correlate_run_id, notes
        )
        VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?)
        """,
        [analysis_id, label, now, now, status, notes],
    )
    return AnalysisItem(
        analysis_id=analysis_id,
        label=label,
        status=status,
        created_at=now,
        updated_at=now,
        notes=notes,
    )


def get_analysis(
    connection: duckdb.DuckDBPyConnection,
    analysis_id: str,
) -> AnalysisItem | None:
    if not analyses_table_exists(connection):
        return None
    row = connection.execute(
        f"SELECT {_SELECT_COLS} FROM analyses WHERE analysis_id = ?",
        [analysis_id],
    ).fetchone()
    if row is None:
        return None
    return _row_to_item(row)


def list_analyses(
    connection: duckdb.DuckDBPyConnection,
    *,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AnalysisItem], int]:
    if not analyses_table_exists(connection):
        return [], 0
    total_row = connection.execute("SELECT COUNT(*) FROM analyses").fetchone()
    total = int(total_row[0]) if total_row else 0
    rows = connection.execute(
        f"""
        SELECT {_SELECT_COLS}
        FROM analyses
        ORDER BY created_at DESC, analysis_id DESC
        LIMIT ? OFFSET ?
        """,
        [limit, offset],
    ).fetchall()
    return [_row_to_item(row) for row in rows], total


def update_analysis(
    connection: duckdb.DuckDBPyConnection,
    analysis_id: str,
    *,
    label: str | None = None,
    notes: str | None = None,
    notes_provided: bool = False,
) -> AnalysisItem | None:
    existing = get_analysis(connection, analysis_id)
    if existing is None:
        return None
    next_label = label if label is not None else existing.label
    next_notes = notes if notes_provided else existing.notes
    now = datetime.now(UTC)
    connection.execute(
        """
        UPDATE analyses
        SET label = ?, notes = ?, updated_at = ?
        WHERE analysis_id = ?
        """,
        [next_label, next_notes, now, analysis_id],
    )
    return get_analysis(connection, analysis_id)


def bind_analysis_to_job(
    connection: duckdb.DuckDBPyConnection,
    analysis_id: str,
    *,
    job_id: str,
    corpus_digest: str,
    file_count: int,
) -> AnalysisItem | None:
    existing = get_analysis(connection, analysis_id)
    if existing is None:
        return None
    now = datetime.now(UTC)
    connection.execute(
        """
        UPDATE analyses
        SET status = 'running',
            job_id = ?,
            corpus_digest = ?,
            file_count = ?,
            correlate_run_id = NULL,
            updated_at = ?
        WHERE analysis_id = ?
        """,
        [job_id, corpus_digest, file_count, now, analysis_id],
    )
    return get_analysis(connection, analysis_id)


def latest_successful_correlate_run_id(
    connection: duckdb.DuckDBPyConnection,
    *,
    not_before: datetime | None = None,
) -> str | None:
    try:
        if not_before is not None:
            # Compare as naive UTC string so DuckDB TIMESTAMP filters stay simple.
            bound = not_before.astimezone(UTC).replace(tzinfo=None)
            row = connection.execute(
                """
                SELECT run_id
                FROM pipeline_runs
                WHERE stage = 'correlate'
                  AND status = 'success'
                  AND finished_at IS NOT NULL
                  AND finished_at >= ?
                ORDER BY finished_at DESC NULLS LAST
                LIMIT 1
                """,
                [bound],
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT run_id
                FROM pipeline_runs
                WHERE stage = 'correlate' AND status = 'success'
                ORDER BY finished_at DESC NULLS LAST
                LIMIT 1
                """
            ).fetchone()
    except duckdb.Error:
        return None
    if row is None or row[0] is None:
        return None
    return str(row[0])


def finalize_analysis_for_job(
    connection: duckdb.DuckDBPyConnection,
    analysis_id: str,
    *,
    job_succeeded: bool,
    job_started_at: datetime | None = None,
    config: dict[str, Any] | None = None,
) -> AnalysisItem | None:
    existing = get_analysis(connection, analysis_id)
    if existing is None:
        return None
    status = "ready" if job_succeeded else "failed"
    correlate_run_id = None
    if job_succeeded:
        try:
            correlate_run_id = latest_successful_correlate_run_id(
                connection, not_before=job_started_at
            )
        except Exception:  # noqa: BLE001 — optional enrichment
            correlate_run_id = None
    now = datetime.now(UTC)
    connection.execute(
        """
        UPDATE analyses
        SET status = ?,
            correlate_run_id = ?,
            updated_at = ?
        WHERE analysis_id = ?
        """,
        [status, correlate_run_id, now, analysis_id],
    )
    updated = get_analysis(connection, analysis_id)
    if updated is not None and config is not None:
        from src.api.analysis_snapshots import maybe_write_snapshot_on_finalize

        try:
            maybe_write_snapshot_on_finalize(connection, updated, config)
        except Exception:  # noqa: BLE001 — snapshot is best-effort after ready
            pass
    return updated


def get_analysis_by_job_id(
    connection: duckdb.DuckDBPyConnection,
    job_id: str,
) -> AnalysisItem | None:
    if not analyses_table_exists(connection):
        return None
    row = connection.execute(
        f"""
        SELECT {_SELECT_COLS}
        FROM analyses
        WHERE job_id = ?
        ORDER BY updated_at DESC NULLS LAST
        LIMIT 1
        """,
        [job_id],
    ).fetchone()
    if row is None:
        return None
    return _row_to_item(row)
