"""Persist ingest staging Parquet and upsert entities.

Staging lives under ``paths.parsed_dir/ingest_staging/`` (internal, not §6).
Each normal ingest run fully refreshes that directory. Sharded ingest (Phase 89)
may append with a shared Policy A ``ContentHashSet``.
"""

from __future__ import annotations

import json
import logging
import shutil
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from src.config import ingestion_settings
from src.identities import stable_ingest_row_id
from src.db.connection import (
    get_connection,
    record_run_finish,
    record_run_start,
    register_parquet_views,
)
from src.ingestion.dedup import ContentHashSet
from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.file_hash import SourceFileDigest, hash_file_bytes, merkle_sha256
from src.ingestion.loaders import iter_raw_log_paths, read_log_files
from src.ingestion.models import IngestStagingRow
from src.ingestion.syslog_time import SyslogYearState

logger = logging.getLogger(__name__)

BATCH_SIZE = 10_000
STAGING_SUBDIR = "ingest_staging"
DEAD_LETTER_SUBDIR = "ingest_dead_letter"


@dataclass
class IngestSummary:
    files: int = 0
    lines_read: int = 0
    lines_kept: int = 0
    lines_deduped: int = 0
    lines_empty_skipped: int = 0
    entities_upserted: int = 0
    timestamp_parse_failures: int = 0
    extraction_failures: int = 0
    staging_parts: int = 0
    dedup_backend_used: str = "memory"
    dedup_spilled: bool = False
    year_policy: str = "carry"
    extraction_ok_rate: float = 0.0
    evidence_line_hash: bool = False
    staging_merkle_sha256: str | None = None
    lines_dead_lettered: int = 0
    files_dead_lettered: int = 0
    append_mode: bool = False
    staging_parts_written: list[str] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def ingest_staging_dir(config: dict[str, Any]) -> Path:
    return Path(config["paths"]["parsed_dir"]) / STAGING_SUBDIR


def ingest_dead_letter_dir(config: dict[str, Any]) -> Path:
    return Path(config["paths"]["parsed_dir"]) / DEAD_LETTER_SUBDIR


def clear_ingest_dead_letter(config: dict[str, Any]) -> Path:
    dead_letter = ingest_dead_letter_dir(config)
    if dead_letter.exists():
        shutil.rmtree(dead_letter)
    dead_letter.mkdir(parents=True, exist_ok=True)
    return dead_letter


def clear_ingest_staging(config: dict[str, Any]) -> Path:
    staging = ingest_staging_dir(config)
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)
    return staging


def next_staging_part_index(staging_dir: Path) -> int:
    """Return the next ``part-NNNNN`` index (0 if none)."""
    highest = -1
    if staging_dir.is_dir():
        for path in staging_dir.glob("part-*.parquet"):
            stem = path.stem  # part-00000
            try:
                highest = max(highest, int(stem.split("-", 1)[1]))
            except (IndexError, ValueError):
                continue
    return highest + 1


def write_staging_batch(
    staging_dir: Path, rows: list[IngestStagingRow], part_index: int
) -> Path:
    records = []
    for row in rows:
        payload = row.model_dump()
        payload["raw_fields"] = json.dumps(payload["raw_fields"])
        if payload["event_timestamp"] is not None:
            payload["event_timestamp"] = payload["event_timestamp"].isoformat()
        payload["ingested_at"] = payload["ingested_at"].isoformat()
        records.append(payload)

    frame = pd.DataFrame.from_records(records)
    path = staging_dir / f"part-{part_index:05d}.parquet"
    frame.to_parquet(path, index=False)
    return path


def upsert_entities(
    connection: Any,
    rows: list[IngestStagingRow],
) -> int:
    """Upsert entities for rows with a non-null entity_id. Returns unique count touched."""
    aggregates: dict[str, tuple[str | None, datetime, datetime]] = {}
    for row in rows:
        if not row.entity_id:
            continue
        ts = row.event_timestamp or row.ingested_at
        prior = aggregates.get(row.entity_id)
        if prior is None:
            aggregates[row.entity_id] = (row.entity_type, ts, ts)
            continue
        entity_type, first_seen, last_seen = prior
        aggregates[row.entity_id] = (
            entity_type or row.entity_type,
            min(first_seen, ts),
            max(last_seen, ts),
        )

    for entity_id, (entity_type, first_seen, last_seen) in aggregates.items():
        connection.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
            VALUES (?, ?, ?, ?, NULL)
            ON CONFLICT (entity_id) DO UPDATE SET
              last_seen = greatest(entities.last_seen, excluded.last_seen),
              first_seen = least(entities.first_seen, excluded.first_seen),
              entity_type = coalesce(entities.entity_type, excluded.entity_type)
            """,
            [entity_id, entity_type, first_seen, last_seen],
        )
    return len(aggregates)


def persist_ingest_source_files(
    connection: Any,
    run_id: str,
    digests: list[SourceFileDigest],
) -> None:
    for digest in digests:
        connection.execute(
            """
            INSERT INTO ingest_source_files
              (run_id, source_path, sha256, size_bytes, mtime_utc)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                run_id,
                digest.source_path,
                digest.sha256,
                digest.size_bytes,
                digest.mtime_utc,
            ],
        )


def _hash_raw_corpus(raw_log_dir: Path) -> list[SourceFileDigest]:
    if not raw_log_dir.is_dir():
        return []
    return [hash_file_bytes(path) for path in iter_raw_log_paths(raw_log_dir)]


def _hash_source_paths(paths: Sequence[Path]) -> list[SourceFileDigest]:
    return [hash_file_bytes(path) for path in paths]


def _staging_fingerprint(staging_dir: Path) -> dict[str, Any]:
    parts: list[dict[str, Any]] = []
    part_hashes: list[str] = []
    for path in sorted(staging_dir.glob("*.parquet")):
        digest = hash_file_bytes(path)
        parts.append(
            {
                "name": path.name,
                "sha256": digest.sha256,
                "size_bytes": digest.size_bytes,
            }
        )
        part_hashes.append(digest.sha256)
    return {
        "part_count": len(parts),
        "merkle_sha256": merkle_sha256(part_hashes),
        "parts": parts,
    }


def run_ingest(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
    source_paths: Sequence[Path | str] | None = None,
    append: bool = False,
    hash_set: ContentHashSet | None = None,
    close_hash_set: bool = True,
    extra_params: dict[str, Any] | None = None,
) -> IngestSummary:
    """Orchestrate load → extract → persist for the ingest stage.

    ``append=True`` keeps existing staging parts and continues part indexes
    (Phase 89). Pass a shared ``hash_set`` so Policy A spans shards; set
    ``close_hash_set=False`` until the last shard.
    """
    connection = get_connection(config)
    summary = IngestSummary(append_mode=append)
    resolved_sources = (
        [Path(p) for p in source_paths] if source_paths is not None else None
    )
    params: dict[str, Any] = {
        "config_path": config_path,
        "raw_log_dir": config["paths"]["raw_log_dir"],
        "staging_dir": str(ingest_staging_dir(config)),
        "append": append,
    }
    if resolved_sources is not None:
        params["source_paths"] = [str(p) for p in resolved_sources]
    if extra_params:
        params.update(extra_params)
    run_id = record_run_start(connection, stage="ingest", params=params)
    owned_hash_set = hash_set is None
    active_hash_set = hash_set
    dead_letter_fh = None
    parts_written: list[str] = []

    try:
        if append:
            staging_dir = ingest_staging_dir(config)
            staging_dir.mkdir(parents=True, exist_ok=True)
            ingest_dead_letter_dir(config).mkdir(parents=True, exist_ok=True)
            part_index = next_staging_part_index(staging_dir)
            dead_letter_mode = "a"
        else:
            staging_dir = clear_ingest_staging(config)
            clear_ingest_dead_letter(config)
            part_index = 0
            dead_letter_mode = "w"

        settings = ingestion_settings(config)
        year_policy = str(settings["syslog_year_policy"])
        evidence_line_hash = bool(settings["evidence_line_hash"])
        max_line_bytes = int(settings["max_line_bytes"])
        summary.year_policy = year_policy
        summary.evidence_line_hash = evidence_line_hash

        if resolved_sources is not None:
            source_digests = _hash_source_paths(resolved_sources)
        else:
            source_digests = _hash_raw_corpus(Path(config["paths"]["raw_log_dir"]))
        file_sha_by_path = {
            digest.source_path: digest.sha256 for digest in source_digests
        }
        persist_ingest_source_files(connection, run_id, source_digests)

        if active_hash_set is None:
            active_hash_set = ContentHashSet(
                memory_max=int(settings["dedup_memory_max_hashes"]),
                backend=str(settings["dedup_backend"]),
                spill_dir=staging_dir,
            )
        buffer: list[IngestStagingRow] = []
        entity_buffer: list[IngestStagingRow] = []
        files_seen: set[str] = set()
        entities_touched: set[str] = set()
        year_states: dict[str, SyslogYearState] = {}
        dead_letter_path = ingest_dead_letter_dir(config) / "dead-letter.jsonl"
        dead_letter_fh = dead_letter_path.open(dead_letter_mode, encoding="utf-8")

        def on_dead_letter(event: dict[str, Any]) -> None:
            if event.get("reason") == "open_failed":
                summary.files_dead_lettered += 1
            else:
                summary.lines_dead_lettered += 1
            dead_letter_fh.write(json.dumps(event, default=str) + "\n")

        for line in read_log_files(
            config,
            evidence_line_hash=evidence_line_hash,
            max_line_bytes=max_line_bytes,
            on_dead_letter=on_dead_letter,
            source_paths=resolved_sources,
        ):
            files_seen.add(line.source_path)
            summary.lines_read += 1

            if not active_hash_set.add(line.content_hash):
                summary.lines_deduped += 1
                continue

            default_year = _default_year_for_file(
                Path(line.source_path), line.ingested_at
            )
            year_state = year_states.get(line.source_path)
            if year_state is None:
                year_state = SyslogYearState(year=default_year)
                year_states[line.source_path] = year_state
            extraction = extract_entity_and_timestamp(
                line.raw_line,
                line.log_source,
                default_year=default_year,
                year_state=year_state,
                year_policy=year_policy,
                enabled_sources=settings.get("enabled_sources") or [],
            )

            if not extraction.extraction_ok:
                summary.extraction_failures += 1
            if extraction.event_timestamp is None or extraction.raw_fields.get(
                "timestamp_parse_failed"
            ):
                summary.timestamp_parse_failures += 1

            row = IngestStagingRow(
                ingest_row_id=stable_ingest_row_id(
                    file_sha_by_path.get(line.source_path, ""),
                    line.line_number,
                ),
                source_path=line.source_path,
                log_source=line.log_source,
                line_number=line.line_number,
                raw_line=line.raw_line,
                content_hash=line.content_hash,
                entity_id=extraction.entity_id,
                entity_type=extraction.entity_type,
                event_timestamp=extraction.event_timestamp,
                raw_fields=extraction.raw_fields,
                ingested_at=line.ingested_at,
                extraction_ok=extraction.extraction_ok,
                failure_reason=extraction.failure_reason,
                evidence_hash=line.evidence_hash,
            )
            buffer.append(row)
            entity_buffer.append(row)
            summary.lines_kept += 1
            if row.entity_id:
                entities_touched.add(row.entity_id)

            if len(buffer) >= BATCH_SIZE:
                written = write_staging_batch(staging_dir, buffer, part_index)
                parts_written.append(written.name)
                part_index += 1
                summary.staging_parts += 1
                upsert_entities(connection, entity_buffer)
                buffer.clear()
                entity_buffer.clear()

        if buffer:
            written = write_staging_batch(staging_dir, buffer, part_index)
            parts_written.append(written.name)
            summary.staging_parts += 1
            upsert_entities(connection, entity_buffer)

        summary.files = len(files_seen)
        summary.entities_upserted = len(entities_touched)
        summary.dedup_backend_used = active_hash_set.backend_used
        summary.dedup_spilled = active_hash_set.spilled
        summary.staging_parts_written = parts_written
        if summary.lines_kept:
            summary.extraction_ok_rate = (
                summary.lines_kept - summary.extraction_failures
            ) / summary.lines_kept
        register_parquet_views(connection, config)

        staging = _staging_fingerprint(staging_dir)
        summary.staging_merkle_sha256 = str(staging["merkle_sha256"])
        params_with_summary = {
            **params,
            "summary": summary.as_dict(),
            "staging": staging,
        }
        connection.execute(
            """
            UPDATE pipeline_runs
            SET params_json = ?::JSON
            WHERE run_id = ?
            """,
            [json.dumps(params_with_summary), run_id],
        )
        record_run_finish(connection, run_id, "success")

        logger.info("ingest summary: %s", summary.as_dict())
        print("ingest summary:")
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    except Exception:
        record_run_finish(connection, run_id, "failed")
        raise
    finally:
        if dead_letter_fh is not None:
            dead_letter_fh.close()
        if active_hash_set is not None and (owned_hash_set or close_hash_set):
            active_hash_set.close()
        connection.close()


def _default_year_for_file(path: Path, ingested_at: datetime) -> int:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).year
    except OSError:
        return ingested_at.astimezone(timezone.utc).year
