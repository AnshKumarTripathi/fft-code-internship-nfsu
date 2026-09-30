"""Orchestrate Phase 3 parse: staging → Drain3 → parsed_events + templates."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config import ConfigError, parse_settings
from src.correlation.writers import clear_correlation_tables
from src.db.connection import (
    get_connection,
    record_run_finish,
    record_run_start,
    register_parquet_views,
)
from src.identities import stable_event_id
from src.ingestion.persist import ingest_staging_dir
from src.db.parquet_shards import (
    parquet_list_sql,
    partition_readable_parquet,
    raise_if_shards_required,
    record_pipeline_errors,
)
from src.parsing.drain3_wrapper import Drain3Miner, resolve_drain3_ini
from src.parsing.schema import ParsedEvent, RawEvent, Template
from src.parsing.snapshots import ParserSnapshotError, prepare_parser_state, save_parser_snapshot
from src.parsing.writers import (
    accumulate_template,
    clear_parsed_events,
    clear_parsed_events_table,
    events_output_dir,
    next_event_part_index,
    refresh_entity_last_seen,
    replace_templates,
    sync_parsed_events_from_parquet,
    upsert_templates,
    write_parsed_batch,
)

logger = logging.getLogger(__name__)

BATCH_SIZE = 10_000


@dataclass
class ParseSummary:
    staging_rows_read: int = 0
    events_written: int = 0
    rows_skipped_missing_entity_or_ts: int = 0
    templates_total: int = 0
    event_parts: int = 0
    parser_snapshot_id: str = ""
    parser_trained_snapshot_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ParseError(Exception):
    """Raised when parse cannot proceed (e.g. missing staging)."""


def _staging_parquet_paths(config: dict[str, Any]) -> list[Path]:
    staging = ingest_staging_dir(config)
    if not staging.is_dir():
        return []
    return sorted(staging.glob("*.parquet"))


def _parse_staging_timestamp(value: Any) -> datetime | None:
    if value is None or (isinstance(value, float) and value != value):  # NaN
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text or text.lower() in {"none", "nat", "null"}:
        return None
    # fromisoformat handles offsets; Z → +00:00
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _parse_raw_fields(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        if not value.strip():
            return {}
        loaded = json.loads(value)
        return loaded if isinstance(loaded, dict) else {}
    return {}


def _nullable_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, float) and value != value:  # NaN
        return None
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "nan"}:
        return None
    return text


def _row_to_raw_event(row: dict[str, Any]) -> RawEvent:
    return RawEvent(
        raw_line=str(row.get("raw_line") or ""),
        entity_id=_nullable_str(row.get("entity_id")),
        event_timestamp=_parse_staging_timestamp(row.get("event_timestamp")),
        log_source=str(row.get("log_source") or "unknown"),
        raw_fields=_parse_raw_fields(row.get("raw_fields")),
        ingested_at=_parse_staging_timestamp(row.get("ingested_at"))
        or datetime.now(timezone.utc),
        ingest_row_id=_nullable_str(row.get("ingest_row_id")),
        source_path=_nullable_str(row.get("source_path")),
        content_hash=_nullable_str(row.get("content_hash")),
        entity_type=_nullable_str(row.get("entity_type")),
        extraction_ok=row.get("extraction_ok"),
        failure_reason=_nullable_str(row.get("failure_reason")),
        line_number=_coerce_line_number(row.get("line_number")),
    )


def _coerce_line_number(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, float) and value != value:  # NaN
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def run_parse(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
    clear_outputs: bool = True,
    staging_files: list[Path] | None = None,
    extra_params: dict[str, Any] | None = None,
) -> ParseSummary:
    """Orchestrate Drain3 parse over ingest staging Parquet.

    Phase 89 append mode: ``clear_outputs=False`` keeps prior events/templates
    and only mines ``staging_files`` (new shard parts), merging templates.
    """
    if staging_files is None:
        staging_files = _staging_parquet_paths(config)
    else:
        staging_files = [Path(p) for p in staging_files]
    if not staging_files:
        raise ParseError("No ingest staging found; run ingest first")

    try:
        settings = parse_settings(config)
    except ConfigError as exc:
        raise ParseError(str(exc)) from exc

    connection = get_connection(config)
    summary = ParseSummary()
    events_dir = events_output_dir(config)
    params: dict[str, Any] = {
        "config_path": config_path,
        "staging_dir": str(ingest_staging_dir(config)),
        "events_dir": str(events_dir),
        "parse_mode": settings["mode"],
        "parse_start_empty": settings["start_empty"],
        "parse_snapshot_id": settings["snapshot_id"],
        "clear_outputs": clear_outputs,
    }
    if extra_params:
        params.update(extra_params)
    run_id = record_run_start(connection, stage="parse", params=params)
    newly_written: list[Path] = []

    try:
        if clear_outputs:
            clear_parsed_events(config)
            # Edges reference parsed_events.event_id; drop correlate outputs first.
            clear_correlation_tables(connection)
            clear_parsed_events_table(connection)
            connection.execute("DELETE FROM templates")
            part_index = 0
        else:
            events_dir.mkdir(parents=True, exist_ok=True)
            part_index = next_event_part_index(events_dir)

        try:
            starting_snapshot_id = prepare_parser_state(
                config["paths"]["baseline_dir"],
                mode=str(settings["mode"]),
                start_empty=bool(settings["start_empty"]),
                snapshot_id=settings["snapshot_id"],
            )
        except ParserSnapshotError as exc:
            raise ParseError(str(exc)) from exc

        summary.parser_snapshot_id = starting_snapshot_id
        params["manifest"]["parser_snapshot_id"] = starting_snapshot_id

        drain3_ini = resolve_drain3_ini(config_path)
        miner = Drain3Miner(
            baseline_dir=config["paths"]["baseline_dir"],
            drain3_ini_path=drain3_ini,
        )

        template_aggregates: dict[str, Template] = {}
        entity_last_seen: dict[str, datetime] = {}
        buffer: list[ParsedEvent] = []
        staging_order = "ORDER BY source_path, line_number, ingest_row_id"
        good_staging, staging_errors = partition_readable_parquet(
            connection, staging_files
        )
        record_pipeline_errors(
            connection, staging_errors, run_id=run_id, stage="parse"
        )
        raise_if_shards_required(staging_errors, config, ParseError)
        if not good_staging:
            raise ParseError("No readable ingest staging found; run ingest first")
        relation = connection.execute(
            f"SELECT * FROM read_parquet({parquet_list_sql(good_staging)}) {staging_order}"
        )

        columns = [desc[0] for desc in relation.description]
        staging_rows = relation.fetchall()

        for values in staging_rows:
            row = dict(zip(columns, values, strict=True))
            summary.staging_rows_read += 1
            raw = _row_to_raw_event(row)

            if not raw.entity_id or raw.event_timestamp is None:
                summary.rows_skipped_missing_entity_or_ts += 1
                continue

            template_id, template_string = miner.add_log_message(raw.raw_line)
            line_number = raw.line_number if raw.line_number is not None else 0
            event = ParsedEvent(
                event_id=stable_event_id(
                    starting_snapshot_id,
                    raw.content_hash or "",
                    line_number,
                    raw.source_path or "",
                ),
                entity_id=raw.entity_id,
                template_id=template_id,
                event_timestamp=raw.event_timestamp,
                log_source=raw.log_source,
                raw_fields=raw.raw_fields,
                ingested_at=raw.ingested_at,
                parser_snapshot_id=starting_snapshot_id,
            )
            buffer.append(event)
            summary.events_written += 1

            accumulate_template(
                template_aggregates,
                template_id,
                template_string,
                raw.event_timestamp,
            )
            prior_seen = entity_last_seen.get(raw.entity_id)
            if prior_seen is None or raw.event_timestamp > prior_seen:
                entity_last_seen[raw.entity_id] = raw.event_timestamp

            if len(buffer) >= BATCH_SIZE:
                written = write_parsed_batch(events_dir, buffer, part_index)
                newly_written.extend(written)
                part_index += 1
                summary.event_parts += 1
                refresh_entity_last_seen(connection, entity_last_seen)
                entity_last_seen.clear()
                buffer.clear()

        if buffer:
            written = write_parsed_batch(events_dir, buffer, part_index)
            newly_written.extend(written)
            summary.event_parts += 1
            refresh_entity_last_seen(connection, entity_last_seen)
            buffer.clear()
        elif entity_last_seen:
            refresh_entity_last_seen(connection, entity_last_seen)

        miner.flush()
        if settings["mode"] == "train_and_snapshot":
            trained_id = save_parser_snapshot(config["paths"]["baseline_dir"])
            summary.parser_trained_snapshot_id = trained_id
            if trained_id:
                params["manifest"]["parser_trained_snapshot_id"] = trained_id
        if clear_outputs:
            summary.templates_total = replace_templates(connection, template_aggregates)
            if summary.events_written > 0:
                sync_parsed_events_from_parquet(
                    connection, events_dir, run_id=run_id, config=config
                )
        else:
            summary.templates_total = upsert_templates(connection, template_aggregates)
            if newly_written:
                sync_parsed_events_from_parquet(
                    connection,
                    events_dir,
                    run_id=run_id,
                    config=config,
                    parquet_files=newly_written,
                )
        register_parquet_views(connection, config)

        params_with_summary = {**params, "summary": summary.as_dict()}
        connection.execute(
            """
            UPDATE pipeline_runs
            SET params_json = ?::JSON
            WHERE run_id = ?
            """,
            [json.dumps(params_with_summary), run_id],
        )
        record_run_finish(connection, run_id, "success")

        logger.info("parse summary: %s", summary.as_dict())
        print("parse summary:")
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    except Exception:
        record_run_finish(connection, run_id, "failed")
        raise
    finally:
        connection.close()