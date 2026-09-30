"""Parquet + DuckDB writers for Phase 3 parsed_events and templates."""

from __future__ import annotations

import json
import logging
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from src.db.parquet_shards import insert_from_readable_parquet
from src.parsing.schema import ParsedEvent, Template

logger = logging.getLogger(__name__)

EVENTS_SUBDIR = "events"


def events_output_dir(config: dict[str, Any]) -> Path:
    return Path(config["paths"]["parsed_dir"]) / EVENTS_SUBDIR


def clear_parsed_events(config: dict[str, Any]) -> Path:
    """Delete and recreate ``parsed_dir/events/`` only (never ingest_staging)."""
    events_dir = events_output_dir(config)
    if events_dir.exists():
        shutil.rmtree(events_dir)
    events_dir.mkdir(parents=True, exist_ok=True)
    return events_dir


def _utc_event_date(ts: datetime) -> str:
    if ts.tzinfo is None:
        aware = ts.replace(tzinfo=timezone.utc)
    else:
        aware = ts.astimezone(timezone.utc)
    return aware.date().isoformat()


def write_parsed_batch(
    events_dir: Path,
    rows: list[ParsedEvent],
    part_index: int,
) -> list[Path]:
    """Write one part file per event_date partition; return paths written."""
    if not rows:
        return []

    by_date: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        payload = row.model_dump()
        payload["raw_fields"] = json.dumps(payload["raw_fields"])
        payload["event_timestamp"] = payload["event_timestamp"].isoformat()
        payload["ingested_at"] = payload["ingested_at"].isoformat()
        event_date = _utc_event_date(row.event_timestamp)
        by_date[event_date].append(payload)

    written: list[Path] = []
    for event_date, records in by_date.items():
        partition_dir = events_dir / f"event_date={event_date}"
        partition_dir.mkdir(parents=True, exist_ok=True)
        path = partition_dir / f"part-{part_index:05d}.parquet"
        frame = pd.DataFrame.from_records(records)
        frame.to_parquet(path, index=False)
        written.append(path)
    return written


def replace_templates(
    connection: Any,
    aggregates: dict[str, Template],
) -> int:
    """Replace all rows in ``templates`` with this run's aggregates."""
    connection.execute("DELETE FROM templates")
    for template in aggregates.values():
        connection.execute(
            """
            INSERT INTO templates (
                template_id, template_string, first_seen, last_seen, occurrence_count
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                template.template_id,
                template.template_string,
                template.first_seen,
                template.last_seen,
                template.occurrence_count,
            ],
        )
    return len(aggregates)


def upsert_templates(
    connection: Any,
    aggregates: dict[str, Template],
) -> int:
    """Merge template aggregates (Phase 89 append parse) without wiping prior rows."""
    for template in aggregates.values():
        connection.execute(
            """
            INSERT INTO templates (
                template_id, template_string, first_seen, last_seen, occurrence_count
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (template_id) DO UPDATE SET
              template_string = coalesce(
                nullif(excluded.template_string, ''),
                templates.template_string
              ),
              first_seen = least(templates.first_seen, excluded.first_seen),
              last_seen = greatest(templates.last_seen, excluded.last_seen),
              occurrence_count = templates.occurrence_count + excluded.occurrence_count
            """,
            [
                template.template_id,
                template.template_string,
                template.first_seen,
                template.last_seen,
                template.occurrence_count,
            ],
        )
    count = connection.execute("SELECT COUNT(*) FROM templates").fetchone()[0]
    return int(count)


def next_event_part_index(events_dir: Path) -> int:
    """Highest ``part-NNNNN`` under any event_date partition, plus one."""
    highest = -1
    if events_dir.is_dir():
        for path in events_dir.glob("**/part-*.parquet"):
            stem = path.stem
            try:
                highest = max(highest, int(stem.split("-", 1)[1]))
            except (IndexError, ValueError):
                continue
    return highest + 1


def clear_parsed_events_table(connection: Any) -> None:
    """Delete all rows from the native ``parsed_events`` table (full refresh)."""
    connection.execute("DELETE FROM parsed_events")


def sync_parsed_events_from_parquet(
    connection: Any,
    events_dir: Path,
    *,
    run_id: str | None = None,
    config: dict[str, Any] | None = None,
    parquet_files: list[Path] | None = None,
) -> int:
    """Load §6 columns from hive Parquet into the native ``parsed_events`` table.

    By default loads every ``**/*.parquet`` under ``events_dir`` (caller should
    clear the table first). Pass ``parquet_files`` to insert only new shards
    (Phase 89 append parse).
    """
    files = (
        list(parquet_files)
        if parquet_files is not None
        else list(events_dir.glob("**/*.parquet"))
    )
    if not files:
        return 0
    insert_from_readable_parquet(
        connection,
        files,
        """
        INSERT INTO parsed_events (
            event_id, entity_id, template_id, event_timestamp,
            log_source, raw_fields, ingested_at, parser_snapshot_id
        )
        SELECT
            event_id,
            entity_id,
            template_id,
            CAST(event_timestamp AS TIMESTAMP) AS event_timestamp,
            log_source,
            raw_fields::JSON AS raw_fields,
            CAST(ingested_at AS TIMESTAMP) AS ingested_at,
            CAST(parser_snapshot_id AS VARCHAR) AS parser_snapshot_id
        FROM {from_clause}
        """,
        run_id=run_id,
        stage="parse",
        config=config,
        hive_partitioning=False,
    )
    count = connection.execute("SELECT COUNT(*) FROM parsed_events").fetchone()[0]
    return int(count)


def insert_parsed_events(connection: Any, rows: list[ParsedEvent]) -> None:
    """Insert validated events into the native ``parsed_events`` table."""
    for row in rows:
        connection.execute(
            """
            INSERT INTO parsed_events (
                event_id, entity_id, template_id, event_timestamp,
                log_source, raw_fields, ingested_at, parser_snapshot_id
            )
            VALUES (?, ?, ?, ?, ?, ?::JSON, ?, ?)
            """,
            [
                row.event_id,
                row.entity_id,
                row.template_id,
                row.event_timestamp,
                row.log_source,
                json.dumps(row.raw_fields),
                row.ingested_at,
                row.parser_snapshot_id,
            ],
        )


def refresh_entity_last_seen(
    connection: Any,
    last_seen_by_entity: dict[str, datetime],
) -> int:
    """Bump ``entities.last_seen`` for parsed entities (no inserts)."""
    updated = 0
    for entity_id, last_seen in last_seen_by_entity.items():
        result = connection.execute(
            """
            UPDATE entities
            SET last_seen = greatest(last_seen, ?)
            WHERE entity_id = ?
            """,
            [last_seen, entity_id],
        )
        # duckdb returns a relation; treat successful execute as one touch
        _ = result
        updated += 1
    return updated


def accumulate_template(
    aggregates: dict[str, Template],
    template_id: str,
    template_string: str,
    event_timestamp: datetime,
) -> None:
    """Update in-memory template aggregates for one occurrence."""
    prior = aggregates.get(template_id)
    if prior is None:
        aggregates[template_id] = Template(
            template_id=template_id,
            template_string=template_string,
            first_seen=event_timestamp,
            last_seen=event_timestamp,
            occurrence_count=1,
        )
        return
    aggregates[template_id] = Template(
        template_id=template_id,
        template_string=template_string or prior.template_string,
        first_seen=min(prior.first_seen, event_timestamp),
        last_seen=max(prior.last_seen, event_timestamp),
        occurrence_count=prior.occurrence_count + 1,
    )
