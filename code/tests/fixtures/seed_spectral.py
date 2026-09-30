"""Seed warehouse bucket history for spectral / cluster integration tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.db.connection import get_connection
from src.timeseries.bucketing import BucketCountRow
from src.timeseries.writers import (
    clear_entity_bucket_counts_table,
    clear_timeseries_output,
    timeseries_output_dir,
    write_entity_buckets,
)
from tests.fixtures.synthetic_entities import generate_periodic_counts


def _sync_seeded_entities(
    connection: Any,
    timeseries_dir: Path,
    entity_ids: list[str],
) -> None:
    """Load only the seeded hive partitions (avoid duplicate PK inserts)."""
    for entity_id in entity_ids:
        partition_dir = timeseries_dir / f"entity_id={entity_id}"
        if not partition_dir.exists():
            continue
        connection.execute(
            "DELETE FROM entity_bucket_counts WHERE entity_id = ?",
            [entity_id],
        )
        glob_path = (partition_dir / "*.parquet").as_posix()
        connection.execute(
            f"""
            INSERT INTO entity_bucket_counts (
                entity_id, bucket_start, bucket_seconds, event_count
            )
            SELECT
                entity_id,
                CAST(bucket_start AS TIMESTAMP) AS bucket_start,
                CAST(bucket_seconds AS INTEGER) AS bucket_seconds,
                CAST(event_count AS DOUBLE) AS event_count
            FROM read_parquet('{glob_path}', hive_partitioning=true)
            """
        )


def seed_entity_bucket_series(
    config: dict[str, Any],
    entity_ids: list[str],
    *,
    n_buckets: int = 5000,
    replace_existing: bool = False,
) -> None:
    """Write synthetic dense bucket series and sync ``entity_bucket_counts``."""
    connection = get_connection(config)
    try:
        if replace_existing:
            clear_timeseries_output(config)
            clear_entity_bucket_counts_table(connection)

        timeseries_dir = timeseries_output_dir(config)
        bucket_seconds = config["bucketing"]["bucket_seconds"]
        period = 24 * 3600 // bucket_seconds

        for entity_id in entity_ids:
            starts, counts = generate_periodic_counts(
                n_buckets=n_buckets,
                period_buckets=period,
                bucket_seconds=bucket_seconds,
            )
            connection.execute(
                """
                INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
                VALUES (?, 'user', ?, ?, ?)
                ON CONFLICT (entity_id) DO NOTHING
                """,
                [entity_id, starts[0], starts[-1], entity_id],
            )
            bucket_rows = [
                BucketCountRow(
                    entity_id=entity_id,
                    bucket_start=starts[i],
                    bucket_seconds=bucket_seconds,
                    event_count=float(counts[i]),
                )
                for i in range(len(starts))
            ]
            write_entity_buckets(timeseries_dir, entity_id, bucket_rows)

        _sync_seeded_entities(connection, timeseries_dir, entity_ids)
    finally:
        connection.close()
