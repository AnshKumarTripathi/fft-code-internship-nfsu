"""Per-file Parquet reads so one corrupt hive shard cannot blank a stage (R6)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from src.config import orchestration_settings
from src.identities import PIPELINE_ERROR_NS, uuid5_str

logger = logging.getLogger(__name__)


class ShardIsolationError(Exception):
    """Raised when corrupt shards were skipped and require_complete is on."""


@dataclass(frozen=True)
class ShardReadError:
    source_path: str
    error_class: str
    message: str


def escape_sql_path(path: Path) -> str:
    return path.as_posix().replace("'", "''")


def parquet_list_sql(paths: Sequence[Path]) -> str:
    """DuckDB list literal of posix paths for ``read_parquet([...])``."""
    inner = ", ".join(f"'{escape_sql_path(path)}'" for path in paths)
    return f"[{inner}]"


def partition_readable_parquet(
    connection: Any,
    paths: Sequence[Path],
) -> tuple[list[Path], list[ShardReadError]]:
    """Probe each file with ``read_parquet``; skip corrupt shards."""
    good: list[Path] = []
    errors: list[ShardReadError] = []
    for path in paths:
        escaped = escape_sql_path(path)
        try:
            connection.execute(
                f"SELECT 1 FROM read_parquet('{escaped}') LIMIT 1"
            ).fetchall()
        except Exception as exc:  # noqa: BLE001 — isolate one bad file
            logger.warning("skipping corrupt parquet shard %s: %s", path, exc)
            errors.append(
                ShardReadError(
                    source_path=str(path),
                    error_class=type(exc).__name__,
                    message=str(exc),
                )
            )
            continue
        good.append(path)
    return good, errors


def record_pipeline_errors(
    connection: Any,
    errors: Sequence[ShardReadError],
    *,
    run_id: str | None,
    stage: str,
) -> None:
    recorded_at = datetime.now(timezone.utc)
    for error in errors:
        error_id = uuid5_str(
            PIPELINE_ERROR_NS,
            f"{stage}|{error.source_path}|{error.error_class}|{error.message}",
        )
        connection.execute(
            """
            INSERT INTO pipeline_errors (
                error_id, run_id, stage, source_path, error_class, message, recorded_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (error_id) DO UPDATE SET
                run_id = COALESCE(excluded.run_id, pipeline_errors.run_id),
                recorded_at = excluded.recorded_at
            """,
            [
                error_id,
                run_id,
                stage,
                error.source_path,
                error.error_class,
                error.message,
                recorded_at,
            ],
        )


def raise_if_shards_required(
    errors: Sequence[ShardReadError],
    config: dict[str, Any] | None,
    error_cls: type[Exception] = ShardIsolationError,
) -> None:
    if not errors or config is None:
        return
    require = bool(orchestration_settings(config)["run_all_require_complete"])
    if not require:
        return
    raise error_cls(
        f"{len(errors)} corrupt parquet shard(s) skipped; "
        "orchestration.run_all_require_complete is true"
    )


def insert_from_readable_parquet(
    connection: Any,
    files: Sequence[Path],
    insert_sql: str,
    *,
    run_id: str | None,
    stage: str,
    config: dict[str, Any] | None = None,
    hive_partitioning: bool = False,
) -> int:
    """``insert_sql`` must contain ``{from_clause}`` (a ``read_parquet(...)`` call)."""
    if not files:
        return 0
    good, errors = partition_readable_parquet(connection, files)
    record_pipeline_errors(connection, errors, run_id=run_id, stage=stage)
    raise_if_shards_required(errors, config)
    if not good:
        return 0
    hive = "true" if hive_partitioning else "false"
    from_clause = (
        f"read_parquet({parquet_list_sql(good)}, "
        f"hive_partitioning={hive}, union_by_name=true)"
    )
    connection.execute(insert_sql.format(from_clause=from_clause))
    return len(good)


def create_view_from_readable_parquet(
    connection: Any,
    view_name: str,
    files: Sequence[Path],
    *,
    hive_partitioning: bool = False,
    stage: str = "parquet_view",
) -> list[ShardReadError]:
    """Replace ``view_name`` with a union of readable files. Skip if none readable."""
    if not files:
        return []
    good, errors = partition_readable_parquet(connection, files)
    record_pipeline_errors(connection, errors, run_id=None, stage=stage)
    if not good:
        logger.warning(
            "not registering view %s: %d/%d parquet shards unreadable",
            view_name,
            len(errors),
            len(files),
        )
        return list(errors)
    hive = "true" if hive_partitioning else "false"
    connection.execute(
        f"CREATE OR REPLACE VIEW {view_name} AS "
        f"SELECT * FROM read_parquet("
        f"{parquet_list_sql(good)}, hive_partitioning={hive}, union_by_name=true)"
    )
    return list(errors)
