"""Phase 89–91 — sequential shard ingest/parse, then one post-merge detect chain.

Phase 91 adds optional progress callbacks and cancel-between-shards checks
(finish or abort the current shard cleanly; do not start the next shard or
post-merge detect when cancel is requested).
"""

from __future__ import annotations

import copy
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from src.config import ingestion_settings, parse_settings, sharding_settings
from src.db.connection import get_connection
from src.ingestion.dedup import ContentHashSet
from src.ingestion.file_hash import merkle_sha256
from src.ingestion.persist import clear_ingest_staging, ingest_staging_dir, run_ingest
from src.ingestion.sharding.manifest import ShardManifestRecord, read_manifest
from src.ingestion.sharding.split import ShardError, split_log_file
from src.parsing.persist import ParseSummary, run_parse

logger = logging.getLogger(__name__)

# Stages after parse — run once on the merged warehouse (Phase 90).
POST_MERGE_STAGES: tuple[str, ...] = (
    "bucket",
    "detect-statistical",
    "detect-spectral",
    "cluster",
    "detect-ml",
    "detect-changepoint",
    "detect-seasonal",
    "correlate",
    "report",
)

# phase ∈ {split, ingest_parse, detect}; shard_index is 0-based when set.
ShardProgressCallback = Callable[
    [str, int | None, int | None, str | None],
    None,
]
CancelCheck = Callable[[], bool]


class ShardCancelled(ShardError):
    """Raised when cancel-between-shards stops before the next shard / detect."""


@dataclass
class ShardStageStatus:
    shard_index: int
    shard_path: str
    shard_sha256: str
    ingest_ok: bool = False
    parse_ok: bool = False
    ingest_skipped_empty: bool = False


@dataclass
class ShardedIngestParseResult:
    split_run_id: str
    shard_count: int
    parser_snapshot_id: str | None = None
    parser_trained_snapshot_id: str | None = None
    entities_seen: set[str] = field(default_factory=set)
    ingest_run_ids: list[str] = field(default_factory=list)
    parse_summaries: list[ParseSummary] = field(default_factory=list)
    shard_statuses: list[ShardStageStatus] = field(default_factory=list)
    corpus_digest: str | None = None
    run_dir: Path | None = None
    post_merge_exit_code: int | None = None
    post_merge_ran: bool = False
    cancelled: bool = False
    cancel_message: str | None = None


def _emit_progress(
    on_progress: ShardProgressCallback | None,
    phase: str,
    *,
    shard_index: int | None = None,
    shard_count: int | None = None,
    detail: str | None = None,
) -> None:
    if on_progress is None:
        return
    on_progress(phase, shard_index, shard_count, detail)


def _raise_if_cancelled(
    should_cancel: CancelCheck | None,
    *,
    detail: str,
) -> None:
    if should_cancel is not None and should_cancel():
        raise ShardCancelled(detail)


def _manifest_from_run_dir(run_dir: Path) -> list[ShardManifestRecord]:
    path = run_dir / "manifest.jsonl"
    if not path.is_file():
        raise ShardError(f"shard manifest not found: {path}")
    records = read_manifest(path)
    if not records:
        raise ShardError(f"shard manifest is empty: {path}")
    return sorted(records, key=lambda r: r.shard_index)


def _resolve_manifest_records(
    config: dict[str, Any],
    *,
    manifest_path: Path | str | None,
    input_path: Path | str | None,
    split_run_id: str | None,
) -> tuple[list[ShardManifestRecord], str, Path]:
    settings = sharding_settings(config)
    output_root = Path(settings["output_dir"])

    if manifest_path is not None:
        manifest = Path(manifest_path)
        records = read_manifest(manifest)
        if not records:
            raise ShardError(f"shard manifest is empty: {manifest_path}")
        records = sorted(records, key=lambda r: r.shard_index)
        run_id = records[0].run_id
        return records, run_id, manifest.parent

    if input_path is not None:
        split = split_log_file(
            input_path,
            output_dir=settings["output_dir"],
            target_shard_bytes=settings["target_shard_bytes"],
            target_shard_lines=settings["target_shard_lines"],
            max_shards=int(settings["max_shards"]),
            run_id=split_run_id,
        )
        return list(split.records), split.run_id, split.run_dir

    if split_run_id:
        run_dir = output_root / split_run_id
        records = _manifest_from_run_dir(run_dir)
        return records, split_run_id, run_dir

    raise ShardError(
        "run-sharded requires --manifest, --input, or --run-id of an existing split"
    )


def _write_shard_status(run_dir: Path, statuses: list[ShardStageStatus]) -> Path:
    path = run_dir / "shard_status.jsonl"
    with path.open("w", encoding="utf-8") as handle:
        for status in statuses:
            handle.write(
                json.dumps(
                    {
                        "shard_index": status.shard_index,
                        "shard_path": status.shard_path,
                        "shard_sha256": status.shard_sha256,
                        "ingest_ok": status.ingest_ok,
                        "parse_ok": status.parse_ok,
                        "ingest_skipped_empty": status.ingest_skipped_empty,
                    },
                    sort_keys=True,
                )
                + "\n"
            )
    return path


def assert_shards_ready_for_detect(result: ShardedIngestParseResult) -> None:
    """Gate: refuse bucket/detect/correlate until every shard finished ingest/parse."""
    if not result.shard_statuses:
        raise ShardError(
            "post-merge detect refused: no shard statuses "
            "(run ingest/parse first)"
        )
    if len(result.shard_statuses) != result.shard_count:
        raise ShardError(
            "post-merge detect refused: shard status count "
            f"{len(result.shard_statuses)} != shard_count {result.shard_count}"
        )
    incomplete: list[int] = []
    for status in result.shard_statuses:
        if status.ingest_skipped_empty:
            # Empty after dedup is OK if ingest itself succeeded.
            if not status.ingest_ok:
                incomplete.append(status.shard_index)
            continue
        if not (status.ingest_ok and status.parse_ok):
            incomplete.append(status.shard_index)
    if incomplete:
        raise ShardError(
            "post-merge detect refused: shards not ingest_ok/parse_ok: "
            + ", ".join(str(i) for i in incomplete)
        )


def corpus_digest_from_shards(records: list[ShardManifestRecord]) -> str:
    """Merkle of all shard file sha256 digests (one analysis identity)."""
    return merkle_sha256([record.shard_sha256 for record in records])


def run_sharded_through_parse(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
    manifest_path: Path | str | None = None,
    input_path: Path | str | None = None,
    split_run_id: str | None = None,
    on_progress: ShardProgressCallback | None = None,
    should_cancel: CancelCheck | None = None,
) -> ShardedIngestParseResult:
    """Ingest each shard (append) then parse with shared Drain3 snapshot policy.

    Drain3 / ML identity for sharded mode (Phase 89):
    - First shard may ``train_and_snapshot`` (or whole run uses a pre-frozen
      ``reuse_snapshot`` + ``snapshot_id``).
    - Remaining shards **must** ``reuse_snapshot`` with that trained id.
    - Accidental per-shard retrain after shard 0 hard-fails.

    Detectors / correlate are **not** run in this loop (Phase 90).
    Cancel checks run **before** starting each shard (Phase 91).
    """
    working = copy.deepcopy(config)
    _emit_progress(on_progress, "split", detail="resolving shard manifest")
    records, run_id, run_dir = _resolve_manifest_records(
        working,
        manifest_path=manifest_path,
        input_path=input_path,
        split_run_id=split_run_id,
    )
    digest = corpus_digest_from_shards(records)
    shard_count = len(records)
    _emit_progress(
        on_progress,
        "split",
        shard_index=None,
        shard_count=shard_count,
        detail=f"manifest ready ({shard_count} shards)",
    )

    parse_cfg = parse_settings(working)
    whole_run_reuse = (
        parse_cfg["mode"] == "reuse_snapshot" and parse_cfg["snapshot_id"] is not None
    )
    if parse_cfg["mode"] == "reuse_snapshot" and parse_cfg["snapshot_id"] is None:
        raise ShardError(
            "sharded parse.mode=reuse_snapshot requires parse.snapshot_id "
            "(pre-frozen snapshot for the whole run)"
        )

    clear_ingest_staging(working)
    settings = ingestion_settings(working)
    staging_dir = ingest_staging_dir(working)
    hash_set = ContentHashSet(
        memory_max=int(settings["dedup_memory_max_hashes"]),
        backend=str(settings["dedup_backend"]),
        spill_dir=staging_dir,
    )

    result = ShardedIngestParseResult(
        split_run_id=run_id,
        shard_count=shard_count,
        corpus_digest=digest,
        run_dir=run_dir,
    )
    trained_snapshot_id: str | None = (
        str(parse_cfg["snapshot_id"]) if whole_run_reuse else None
    )

    try:
        for index, record in enumerate(records):
            _raise_if_cancelled(
                should_cancel,
                detail=(
                    f"Cancelled between shards after "
                    f"{len(result.shard_statuses)}/{shard_count} "
                    "(current shard may have finished; detect not started)"
                ),
            )
            shard_path = Path(record.shard_path)
            if not shard_path.is_file():
                raise ShardError(f"shard file missing: {shard_path}")

            is_first = index == 0
            is_last = index == len(records) - 1
            status = ShardStageStatus(
                shard_index=record.shard_index,
                shard_path=record.shard_path,
                shard_sha256=record.shard_sha256,
            )
            extra = {
                "sharded": True,
                "shard_index": record.shard_index,
                "shard_path": record.shard_path,
                "shard_sha256": record.shard_sha256,
                "split_run_id": run_id,
                "shard_of": len(records),
                "corpus_digest": digest,
            }
            _emit_progress(
                on_progress,
                "ingest_parse",
                shard_index=record.shard_index,
                shard_count=shard_count,
                detail=f"ingest shard {index + 1}/{shard_count}",
            )
            print(
                f"sharded ingest {index + 1}/{len(records)} "
                f"shard_index={record.shard_index}",
                flush=True,
            )
            ingest_summary = run_ingest(
                working,
                config_path=config_path,
                source_paths=[shard_path],
                append=not is_first,
                hash_set=hash_set,
                close_hash_set=False,
                extra_params=extra,
            )
            status.ingest_ok = True

            staging_parts = [
                staging_dir / name
                for name in (ingest_summary.staging_parts_written or [])
                if (staging_dir / name).is_file()
            ]
            if not staging_parts:
                if is_first and not whole_run_reuse:
                    raise ShardError(
                        f"first shard produced no staging rows: {shard_path}"
                    )
                status.ingest_skipped_empty = True
                status.parse_ok = True  # nothing to parse
                result.shard_statuses.append(status)
                logger.warning(
                    "shard %s produced no staging parts (all deduped or empty)",
                    record.shard_index,
                )
                _write_shard_status(run_dir, result.shard_statuses)
                continue

            if is_first:
                if whole_run_reuse:
                    working.setdefault("parse", {})
                    working["parse"] = {
                        **parse_settings(working),
                        "mode": "reuse_snapshot",
                        "snapshot_id": trained_snapshot_id,
                        "start_empty": False,
                    }
                else:
                    working.setdefault("parse", {})
                    working["parse"] = {
                        **parse_settings(working),
                        "mode": "train_and_snapshot",
                        "start_empty": True,
                        "snapshot_id": None,
                    }
            else:
                if not trained_snapshot_id:
                    raise ShardError(
                        "sharded mode: remaining shards require a trained "
                        "parser snapshot_id (first shard must train_and_snapshot)"
                    )
                working.setdefault("parse", {})
                working["parse"] = {
                    **parse_settings(working),
                    "mode": "reuse_snapshot",
                    "snapshot_id": trained_snapshot_id,
                    "start_empty": False,
                }
                if working["parse"]["mode"] != "reuse_snapshot":
                    raise ShardError(
                        "sharded mode forbids train_and_snapshot after shard 0"
                    )

            _emit_progress(
                on_progress,
                "ingest_parse",
                shard_index=record.shard_index,
                shard_count=shard_count,
                detail=f"parse shard {index + 1}/{shard_count}",
            )
            print(
                f"sharded parse {index + 1}/{len(records)} "
                f"mode={working['parse']['mode']}",
                flush=True,
            )
            parse_summary = run_parse(
                working,
                config_path=config_path,
                clear_outputs=is_first,
                staging_files=staging_parts,
                extra_params=extra,
            )
            status.parse_ok = True
            result.parse_summaries.append(parse_summary)
            result.parser_snapshot_id = parse_summary.parser_snapshot_id
            if parse_summary.parser_trained_snapshot_id:
                trained_snapshot_id = parse_summary.parser_trained_snapshot_id
                result.parser_trained_snapshot_id = trained_snapshot_id
            elif whole_run_reuse and trained_snapshot_id:
                result.parser_trained_snapshot_id = trained_snapshot_id

            if not is_last and working["parse"]["mode"] == "train_and_snapshot":
                if not trained_snapshot_id:
                    raise ShardError(
                        "sharded mode: first shard train_and_snapshot produced "
                        "no parser_trained_snapshot_id"
                    )

            result.shard_statuses.append(status)
            _write_shard_status(run_dir, result.shard_statuses)
    except ShardCancelled as exc:
        result.cancelled = True
        result.cancel_message = str(exc)
        _write_shard_status(run_dir, result.shard_statuses)
        print(f"run-sharded cancelled: {exc}", flush=True)
        return result
    finally:
        hash_set.close()

    connection = get_connection(working)
    try:
        rows = connection.execute(
            "SELECT entity_id FROM entities WHERE entity_id IS NOT NULL"
        ).fetchall()
        result.entities_seen = {str(r[0]) for r in rows}
    finally:
        connection.close()

    post_merge_meta = {
        "split_run_id": run_id,
        "shard_count": result.shard_count,
        "corpus_digest": digest,
        "parser_trained_snapshot_id": result.parser_trained_snapshot_id,
        "entities": len(result.entities_seen),
    }
    (run_dir / "post_merge.json").write_text(
        json.dumps(post_merge_meta, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        f"run-sharded through parse: shards={result.shard_count} "
        f"entities={len(result.entities_seen)} "
        f"corpus_digest={digest} "
        f"snapshot={result.parser_trained_snapshot_id or result.parser_snapshot_id}",
        flush=True,
    )
    return result


def run_sharded_post_merge_detect(
    config: dict[str, Any],
    result: ShardedIngestParseResult,
    *,
    config_path: str | None = None,
    require_complete: bool = False,
    on_progress: ShardProgressCallback | None = None,
    on_stage: Callable[[str, str, str | None], None] | None = None,
    should_cancel: CancelCheck | None = None,
) -> int:
    """After all shards are ready, run bucket→detectors→correlate→report **once**.

    Forbidden: calling this (or correlate) inside the per-shard loop.
    Soft-skips (cold start / empty cluster / nothing to correlate) follow
    ``run_stages`` on the **merged** series.
    """
    _raise_if_cancelled(
        should_cancel,
        detail=(
            "Cancelled after ingest/parse; post-merge detect was not started "
            "(no half-written detect scores)"
        ),
    )
    assert_shards_ready_for_detect(result)

    # Late import avoids circular import (pipeline → orchestrate → pipeline).
    from src.pipeline import run_stages

    _emit_progress(
        on_progress,
        "detect",
        shard_index=None,
        shard_count=result.shard_count,
        detail="post-merge detect starting",
    )
    print(
        f"post-merge detect: corpus_digest={result.corpus_digest} "
        f"shards={result.shard_count} stages={', '.join(POST_MERGE_STAGES)}",
        flush=True,
    )
    exit_code = run_stages(
        config,
        config_path=config_path,
        stages=list(POST_MERGE_STAGES),
        require_complete=require_complete,
        on_stage=on_stage,
    )
    result.post_merge_exit_code = exit_code
    result.post_merge_ran = True

    if result.run_dir is not None:
        meta_path = result.run_dir / "post_merge.json"
        meta: dict[str, Any] = {}
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta.update(
            {
                "post_merge_ran": True,
                "post_merge_exit_code": exit_code,
                "post_merge_stages": list(POST_MERGE_STAGES),
                "corpus_digest": result.corpus_digest,
            }
        )
        meta_path.write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return exit_code


def run_sharded_pipeline(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
    through: str = "report",
    manifest_path: Path | str | None = None,
    input_path: Path | str | None = None,
    split_run_id: str | None = None,
    require_complete: bool = False,
    on_progress: ShardProgressCallback | None = None,
    on_stage: Callable[[str, str, str | None], None] | None = None,
    should_cancel: CancelCheck | None = None,
) -> ShardedIngestParseResult:
    """Full sharded orchestration: ingest/parse loop, optional post-merge detect."""
    if through not in {"parse", "report"}:
        raise ShardError(
            f"unsupported --through {through!r}; allowed: parse, report"
        )

    result = run_sharded_through_parse(
        config,
        config_path=config_path,
        manifest_path=manifest_path,
        input_path=input_path,
        split_run_id=split_run_id,
        on_progress=on_progress,
        should_cancel=should_cancel,
    )
    if result.cancelled or through == "parse":
        return result

    # Phase 90 — one detect chain only after the gate.
    try:
        run_sharded_post_merge_detect(
            config,
            result,
            config_path=config_path,
            require_complete=require_complete,
            on_progress=on_progress,
            on_stage=on_stage,
            should_cancel=should_cancel,
        )
    except ShardCancelled as exc:
        result.cancelled = True
        result.cancel_message = str(exc)
        print(f"run-sharded cancelled before detect: {exc}", flush=True)
    return result
