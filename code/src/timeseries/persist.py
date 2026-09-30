"""Orchestrate Phase 4 bucket: parsed_events → entity_bucket_counts."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from src.db.connection import (
    get_connection,
    record_run_finish,
    record_run_start,
    register_parquet_views,
)
from src.timeseries.bucketing import bucket_events
from src.timeseries.writers import (
    clear_entity_bucket_counts_table,
    clear_timeseries_output,
    sync_entity_bucket_counts_from_parquet,
    timeseries_output_dir,
    write_entity_buckets,
)

logger = logging.getLogger(__name__)


@dataclass
class BucketSummary:
    entities_processed: int = 0
    entities_skipped_empty: int = 0
    total_buckets_written: int = 0
    total_events_bucketed: int = 0
    parquet_entities: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class BucketError(Exception):
    """Raised when bucket cannot proceed (e.g. missing parsed_events)."""


def _validate_bucket_seconds(config: dict[str, Any]) -> int:
    bucket_seconds = config["bucketing"]["bucket_seconds"]
    if not isinstance(bucket_seconds, int) or bucket_seconds <= 0:
        raise BucketError(
            f"bucketing.bucket_seconds must be a positive integer, got {bucket_seconds!r}"
        )
    return bucket_seconds


def _flush_entity(
    entity_id: str,
    timestamps: list[datetime],
    bucket_seconds: int,
    timeseries_dir: Any,
    summary: BucketSummary,
) -> None:
    if not timestamps:
        summary.entities_skipped_empty += 1
        return

    rows = bucket_events(timestamps, bucket_seconds, entity_id=entity_id)
    if not rows:
        summary.entities_skipped_empty += 1
        return

    path = write_entity_buckets(timeseries_dir, entity_id, rows)
    if path is None:
        summary.entities_skipped_empty += 1
        return

    summary.entities_processed += 1
    summary.parquet_entities += 1
    summary.total_buckets_written += len(rows)
    summary.total_events_bucketed += len(timestamps)


def run_bucket(config: dict[str, Any], *, config_path: str | None = None) -> BucketSummary:
    """Build per-entity dense bucket count series from ``parsed_events``."""
    connection = get_connection(config)
    summary = BucketSummary()
    bucket_seconds = _validate_bucket_seconds(config)
    timeseries_dir = timeseries_output_dir(config)
    params = {
        "config_path": config_path,
        "timeseries_dir": str(timeseries_dir),
        "bucket_seconds": bucket_seconds,
    }
    run_id = record_run_start(connection, stage="bucket", params=params)

    try:
        event_count = connection.execute("SELECT COUNT(*) FROM parsed_events").fetchone()[0]
        if int(event_count) == 0:
            raise BucketError("No parsed_events found; run parse first")

        clear_timeseries_output(config)
        clear_entity_bucket_counts_table(connection)

        relation = connection.execute(
            """
            SELECT entity_id, event_timestamp
            FROM parsed_events
            WHERE event_timestamp IS NOT NULL
            ORDER BY entity_id, event_timestamp
            """
        )
        columns = [desc[0] for desc in relation.description]

        current_entity: str | None = None
        current_timestamps: list[datetime] = []

        while True:
            batch = relation.fetchmany(10_000)
            if not batch and current_entity is None:
                break

            for values in batch:
                row = dict(zip(columns, values, strict=True))
                entity_id = str(row["entity_id"])
                event_timestamp = row["event_timestamp"]
                if not isinstance(event_timestamp, datetime):
                    continue

                if current_entity is not None and entity_id != current_entity:
                    _flush_entity(
                        current_entity,
                        current_timestamps,
                        bucket_seconds,
                        timeseries_dir,
                        summary,
                    )
                    current_timestamps = []

                current_entity = entity_id
                current_timestamps.append(event_timestamp)

            if not batch:
                if current_entity is not None:
                    _flush_entity(
                        current_entity,
                        current_timestamps,
                        bucket_seconds,
                        timeseries_dir,
                        summary,
                    )
                break

        if summary.parquet_entities > 0:
            sync_entity_bucket_counts_from_parquet(
                connection, timeseries_dir, run_id=run_id, config=config
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

        logger.info("bucket summary: %s", summary.as_dict())
        print("bucket summary:")
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    except Exception:
        record_run_finish(connection, run_id, "failed")
        raise
    finally:
        connection.close()
