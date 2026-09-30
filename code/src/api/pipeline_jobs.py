"""In-process pipeline job runner (Phases 56 + 91).

Starts ``run_stages`` or ``run_sharded_pipeline`` on a background thread so
FastAPI can return a ``job_id`` immediately and operators can poll status.
Single-flight: only one job may be queued/running at a time; a second start
returns busy (HTTP 409 at the route).

Jobs live in memory for the API process lifetime — they are not persisted across
uvicorn restarts. Mid-stage cancel is unsupported; sharded jobs support
**cancel between shards** (Phase 91).
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from src.config import load_config, orchestration_settings, sharding_settings
from src.db.writer_lock import WarehouseBusyError, WriterLock, writer_lock_path
from src.ingestion.file_hash import hash_file_bytes
from src.ingestion.sharding.orchestrate import POST_MERGE_STAGES, run_sharded_pipeline
from src.ingestion.sharding.split import ShardError
from src.pipeline import resolve_stage_list, run_stages

UTC = timezone.utc
_LOG = logging.getLogger(__name__)

JOB_STATUSES_ACTIVE = frozenset({"queued", "running", "cancelling"})
STAGE_DONE = frozenset({"success", "skipped"})
SHARDED_PRE_STAGES: tuple[str, ...] = ("split", "ingest_parse")
SHARDED_JOB_STAGES: tuple[str, ...] = SHARDED_PRE_STAGES + POST_MERGE_STAGES


class JobBusyError(Exception):
    """Raised when a second job cannot start (single-flight / warehouse lock)."""

    def __init__(self, message: str, *, job_id: str | None = None) -> None:
        super().__init__(message)
        self.job_id = job_id


class JobPathError(Exception):
    """Raised when a sharded input path is missing or outside allowed raw roots."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


@dataclass
class JobStageState:
    stage: str
    status: str = "pending"
    detail: str | None = None
    finished_at: str | None = None


@dataclass
class JobRecord:
    job_id: str
    status: str
    mode: str
    require_complete: bool
    stages: list[JobStageState]
    current_stage: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    config_path: str = ""
    total_stages: int = 0
    analysis_id: str | None = None
    ml_ensemble_enabled: bool | None = None
    phase: str | None = None
    shard_index: int | None = None
    shard_count: int | None = None
    input_path: str | None = None
    cancel_requested: bool = False
    cancel_supported: bool = False

    @property
    def completed_stages(self) -> int:
        return sum(1 for entry in self.stages if entry.status in STAGE_DONE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "mode": self.mode,
            "require_complete": self.require_complete,
            "current_stage": self.current_stage,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "completed_stages": self.completed_stages,
            "total_stages": self.total_stages,
            "stages": [
                {
                    "stage": entry.stage,
                    "status": entry.status,
                    "detail": entry.detail,
                    "finished_at": entry.finished_at,
                }
                for entry in self.stages
            ],
            "analysis_id": self.analysis_id,
            "ml_ensemble_enabled": self.ml_ensemble_enabled,
            "phase": self.phase,
            "shard_index": self.shard_index,
            "shard_count": self.shard_count,
            "input_path": self.input_path,
            "cancel_supported": self.cancel_supported,
            "cancel_requested": self.cancel_requested,
        }


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def warehouse_writer_busy(config: dict[str, Any]) -> bool:
    """True when another process holds the warehouse writer lock."""
    db_path = config.get("paths", {}).get("db_path")
    if not db_path:
        return False
    lock = WriterLock(writer_lock_path(db_path))
    try:
        lock.acquire()
    except WarehouseBusyError:
        return True
    lock.release()
    return False


def resolve_sharded_input_path(
    config: dict[str, Any],
    input_path: str | Path,
) -> Path:
    """Resolve ``input_path`` and require it under ``paths.raw_log_dir``."""
    raw_root = Path(str(config["paths"]["raw_log_dir"])).resolve()
    candidate = Path(str(input_path)).expanduser()
    if not candidate.is_absolute():
        candidate = (raw_root / candidate).resolve()
    else:
        candidate = candidate.resolve()
    try:
        candidate.relative_to(raw_root)
    except ValueError as exc:
        raise JobPathError(
            "input_path must resolve under paths.raw_log_dir "
            f"({raw_root})"
        ) from exc
    if not candidate.is_file():
        raise JobPathError(f"input_path is not a file: {candidate}")
    return candidate


class JobStore:
    """Process-wide job registry with a single active runner."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, JobRecord] = {}
        self._order: list[str] = []
        self._active_job_id: str | None = None
        self._threads: dict[str, threading.Thread] = {}

    def reset(self) -> None:
        """Drop all jobs (tests only). Does not kill running stage work."""
        with self._lock:
            self._jobs.clear()
            self._order.clear()
            self._active_job_id = None
            self._threads.clear()

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return deepcopy(job) if job is not None else None

    def latest(self) -> JobRecord | None:
        with self._lock:
            if self._active_job_id and self._active_job_id in self._jobs:
                active = self._jobs[self._active_job_id]
                if active.status in JOB_STATUSES_ACTIVE:
                    return deepcopy(active)
            if not self._order:
                return None
            return deepcopy(self._jobs[self._order[-1]])

    def request_cancel(self, job_id: str) -> JobRecord:
        """Request stop after the current shard (sharded jobs only)."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            if not job.cancel_supported:
                raise JobPathError(
                    "Cancel is only supported for sharded jobs "
                    "(stops before the next shard; current shard may finish)."
                )
            if job.status not in JOB_STATUSES_ACTIVE:
                return deepcopy(job)
            job.cancel_requested = True
            if job.status == "running":
                job.status = "cancelling"
            return deepcopy(job)

    def try_start(
        self,
        *,
        config_path: str | Path,
        mode: str = "run_all",
        require_complete: bool = False,
        stages: Sequence[str] | None = None,
        analysis_id: str | None = None,
        corpus_digest: str | None = None,
        file_count: int | None = None,
        ml_ensemble_enabled: bool | None = None,
        input_path: str | None = None,
    ) -> JobRecord:
        path = Path(config_path)
        config = load_config(path)
        settings = orchestration_settings(config)
        require = bool(require_complete) or bool(settings["run_all_require_complete"])
        mode_norm = (mode or "run_all").strip().lower()
        is_sharded = mode_norm == "run_sharded"

        if is_sharded:
            shard_cfg = sharding_settings(config)
            if not shard_cfg["enabled"]:
                raise JobPathError(
                    "Sharded jobs require sharding.enabled: true in pipeline YAML"
                )
            if not input_path or not str(input_path).strip():
                raise JobPathError(
                    "run_sharded requires input_path under paths.raw_log_dir "
                    "(or a staged upload path)"
                )
            resolved = resolve_sharded_input_path(config, input_path)
            input_path = str(resolved)
            if stages is not None:
                raise JobPathError(
                    "stages is not supported for run_sharded "
                    "(fixed split → ingest/parse → post-merge detect)"
                )
            selected = list(SHARDED_JOB_STAGES)
            cancel_supported = True
        else:
            selected = resolve_stage_list(stages)
            cancel_supported = False

        with self._lock:
            if self._active_job_id is not None:
                active = self._jobs.get(self._active_job_id)
                if active is not None and active.status in JOB_STATUSES_ACTIVE:
                    raise JobBusyError(
                        "A pipeline job is already running. Wait for it to finish "
                        "before starting another.",
                        job_id=active.job_id,
                    )
            if warehouse_writer_busy(config):
                raise JobBusyError(
                    "Warehouse writer lock is held by another process. "
                    "Wait for the CLI or other writer to finish."
                )

            job_id = str(uuid.uuid4())
            job = JobRecord(
                job_id=job_id,
                status="queued",
                mode=mode_norm,
                require_complete=require,
                stages=[JobStageState(stage=name) for name in selected],
                started_at=_utc_now_iso(),
                config_path=str(path),
                total_stages=len(selected),
                analysis_id=analysis_id,
                ml_ensemble_enabled=ml_ensemble_enabled,
                input_path=input_path if is_sharded else None,
                cancel_supported=cancel_supported,
                phase="queued" if is_sharded else None,
            )
            self._jobs[job_id] = job
            self._order.append(job_id)
            self._active_job_id = job_id
            snapshot = deepcopy(job)

        if analysis_id:
            try:
                self._bind_analysis(
                    config,
                    analysis_id=analysis_id,
                    job_id=job_id,
                    corpus_digest=corpus_digest or "",
                    file_count=int(file_count or 0),
                )
            except Exception:
                with self._lock:
                    if self._active_job_id == job_id:
                        self._active_job_id = None
                    stored = self._jobs.get(job_id)
                    if stored is not None:
                        stored.status = "failed"
                        stored.error = "Failed to bind analysis before start"
                        stored.finished_at = _utc_now_iso()
                raise

        if is_sharded:
            thread = threading.Thread(
                target=self._execute_sharded,
                args=(job_id, input_path),
                name=f"pipeline-shard-{job_id[:8]}",
                daemon=True,
            )
        else:
            thread = threading.Thread(
                target=self._execute,
                args=(job_id, selected),
                name=f"pipeline-job-{job_id[:8]}",
                daemon=True,
            )
        with self._lock:
            self._threads[job_id] = thread
        thread.start()
        return snapshot

    def _bind_analysis(
        self,
        config: dict[str, Any],
        *,
        analysis_id: str,
        job_id: str,
        corpus_digest: str,
        file_count: int,
    ) -> None:
        from src.api.analyses import bind_analysis_to_job
        from src.db.connection import get_connection

        connection = get_connection(config)
        try:
            bound = bind_analysis_to_job(
                connection,
                analysis_id,
                job_id=job_id,
                corpus_digest=corpus_digest,
                file_count=file_count,
            )
            if bound is None:
                raise RuntimeError(f"Analysis not found: {analysis_id}")
        finally:
            connection.close()

    def _set_pre_stage(
        self,
        job_id: str,
        stage: str,
        status: str,
        *,
        detail: str | None = None,
    ) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for entry in job.stages:
                if entry.stage == stage:
                    entry.status = status
                    entry.detail = detail
                    if status == "running":
                        job.current_stage = stage
                        entry.finished_at = None
                    else:
                        entry.finished_at = _utc_now_iso()
                    break

    def _execute(self, job_id: str, selected: list[str]) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.status = "running"
            config_path = job.config_path
            require_complete = job.require_complete
            ml_ensemble_enabled = job.ml_ensemble_enabled

        try:
            config = load_config(config_path)
        except Exception as exc:  # noqa: BLE001
            self._fail_job(job_id, f"Failed to load config: {exc}")
            return

        if ml_ensemble_enabled is not None:
            ml_block = dict(config.get("ml") or {})
            ensemble = dict(ml_block.get("ensemble") or {})
            ensemble["enabled"] = bool(ml_ensemble_enabled)
            ml_block["ensemble"] = ensemble
            config["ml"] = ml_block

        stage_index = {name: i for i, name in enumerate(selected)}

        def on_stage(stage: str, status: str, detail: str | None) -> None:
            with self._lock:
                job = self._jobs[job_id]
                idx = stage_index[stage]
                entry = job.stages[idx]
                entry.status = status
                entry.detail = detail
                if status == "running":
                    job.current_stage = stage
                    entry.finished_at = None
                else:
                    entry.finished_at = _utc_now_iso()
                    if status == "failed":
                        job.error = f"Stage '{stage}' failed: {detail or 'unknown error'}"

        exit_code = run_stages(
            config,
            config_path=config_path,
            stages=selected,
            require_complete=require_complete,
            on_stage=on_stage,
            emit_summary=True,
        )

        self._finish_job(job_id, exit_code=exit_code, require_complete=require_complete)

    def _execute_sharded(self, job_id: str, input_path: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.status = "running"
            job.phase = "split"
            config_path = job.config_path
            require_complete = job.require_complete
            ml_ensemble_enabled = job.ml_ensemble_enabled

        try:
            config = load_config(config_path)
        except Exception as exc:  # noqa: BLE001
            self._fail_job(job_id, f"Failed to load config: {exc}")
            return

        if ml_ensemble_enabled is not None:
            ml_block = dict(config.get("ml") or {})
            ensemble = dict(ml_block.get("ensemble") or {})
            ensemble["enabled"] = bool(ml_ensemble_enabled)
            ml_block["ensemble"] = ensemble
            config["ml"] = ml_block

        detect_index = {name: i for i, name in enumerate(SHARDED_JOB_STAGES)}

        def should_cancel() -> bool:
            with self._lock:
                job = self._jobs[job_id]
                return bool(job.cancel_requested)

        def on_progress(
            phase: str,
            shard_index: int | None,
            shard_count: int | None,
            detail: str | None,
        ) -> None:
            with self._lock:
                job = self._jobs[job_id]
                if job.cancel_requested and job.status == "running":
                    job.status = "cancelling"
                job.phase = phase
                if shard_index is not None:
                    job.shard_index = shard_index
                if shard_count is not None:
                    job.shard_count = shard_count
                if phase == "split":
                    job.current_stage = "split"
                    for entry in job.stages:
                        if entry.stage == "split" and entry.status == "pending":
                            entry.status = "running"
                            entry.detail = detail
                elif phase == "ingest_parse":
                    for entry in job.stages:
                        if entry.stage == "split" and entry.status == "running":
                            entry.status = "success"
                            entry.finished_at = _utc_now_iso()
                        if entry.stage == "ingest_parse":
                            entry.status = "running"
                            entry.detail = detail
                            entry.finished_at = None
                    job.current_stage = "ingest_parse"
                elif phase == "detect":
                    for entry in job.stages:
                        if entry.stage in SHARDED_PRE_STAGES and entry.status in {
                            "pending",
                            "running",
                        }:
                            entry.status = "success"
                            entry.finished_at = entry.finished_at or _utc_now_iso()
                    job.current_stage = "detect"

        def on_stage(stage: str, status: str, detail: str | None) -> None:
            with self._lock:
                job = self._jobs[job_id]
                job.phase = "detect"
                idx = detect_index[stage]
                entry = job.stages[idx]
                entry.status = status
                entry.detail = detail
                if status == "running":
                    job.current_stage = stage
                    entry.finished_at = None
                else:
                    entry.finished_at = _utc_now_iso()
                    if status == "failed":
                        job.error = f"Stage '{stage}' failed: {detail or 'unknown error'}"

        self._set_pre_stage(job_id, "split", "running", detail="starting")
        try:
            result = run_sharded_pipeline(
                config,
                config_path=config_path,
                through="report",
                input_path=input_path,
                require_complete=require_complete,
                on_progress=on_progress,
                on_stage=on_stage,
                should_cancel=should_cancel,
            )
        except ShardError as exc:
            self._fail_job(job_id, str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            self._fail_job(job_id, f"Sharded pipeline failed: {exc}")
            return

        if result.cancelled:
            with self._lock:
                job = self._jobs[job_id]
                job.status = "cancelled"
                job.error = result.cancel_message or (
                    "Cancelled between shards; detect was not started"
                )
                job.finished_at = _utc_now_iso()
                job.current_stage = None
                job.phase = "cancelled"
                job.shard_count = result.shard_count or job.shard_count
                for entry in job.stages:
                    if entry.status in {"pending", "running"}:
                        if entry.stage == "ingest_parse" and result.shard_statuses:
                            entry.status = "skipped"
                            entry.detail = "cancelled between shards"
                        elif entry.status == "running":
                            entry.status = "skipped"
                            entry.detail = "cancelled"
                        entry.finished_at = entry.finished_at or _utc_now_iso()
                analysis_id = job.analysis_id
                started_at = job.started_at
                config_path_final = job.config_path
                if self._active_job_id == job_id:
                    self._active_job_id = None
            if analysis_id:
                self._finalize_analysis(
                    config_path_final,
                    analysis_id=analysis_id,
                    job_succeeded=False,
                    started_at_iso=started_at,
                )
            with self._lock:
                self._threads.pop(job_id, None)
            return

        exit_code = (
            0
            if result.post_merge_exit_code is None
            else int(result.post_merge_exit_code)
        )
        with self._lock:
            job = self._jobs[job_id]
            job.shard_count = result.shard_count
            job.phase = "detect" if result.post_merge_ran else job.phase
        self._finish_job(job_id, exit_code=exit_code, require_complete=require_complete)

    def _finish_job(
        self,
        job_id: str,
        *,
        exit_code: int,
        require_complete: bool,
    ) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.finished_at = _utc_now_iso()
            job.current_stage = None
            if exit_code == 0:
                job.status = "succeeded"
                job.error = None
                if job.mode == "run_sharded" and job.phase != "cancelled":
                    job.phase = "done"
            else:
                job.status = "failed"
                if job.error is None:
                    skipped = [
                        entry.stage
                        for entry in job.stages
                        if entry.status == "skipped"
                    ]
                    if require_complete and skipped:
                        job.error = (
                            "require-complete: skipped stages treated as failure: "
                            + ", ".join(skipped)
                        )
                    else:
                        failed = [
                            entry.stage
                            for entry in job.stages
                            if entry.status == "failed"
                        ]
                        job.error = (
                            "Pipeline job failed"
                            + (f" at: {', '.join(failed)}" if failed else "")
                        )
            analysis_id = job.analysis_id
            job_succeeded = job.status == "succeeded"
            started_at = job.started_at
            config_path_final = job.config_path
            if self._active_job_id == job_id:
                self._active_job_id = None

        if analysis_id:
            self._finalize_analysis(
                config_path_final,
                analysis_id=analysis_id,
                job_succeeded=job_succeeded,
                started_at_iso=started_at,
            )

        with self._lock:
            self._threads.pop(job_id, None)

    def _fail_job(self, job_id: str, message: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.status = "failed"
            job.error = message
            job.finished_at = _utc_now_iso()
            job.current_stage = None
            if job.mode == "run_sharded":
                job.phase = "failed"
            analysis_id = job.analysis_id
            started_at = job.started_at
            config_path_final = job.config_path
            if self._active_job_id == job_id:
                self._active_job_id = None
        if analysis_id:
            self._finalize_analysis(
                config_path_final,
                analysis_id=analysis_id,
                job_succeeded=False,
                started_at_iso=started_at,
            )
        with self._lock:
            self._threads.pop(job_id, None)

    def _finalize_analysis(
        self,
        config_path: str,
        *,
        analysis_id: str,
        job_succeeded: bool,
        started_at_iso: str | None,
    ) -> None:
        from src.api.analyses import finalize_analysis_for_job
        from src.db.connection import get_connection

        started_at: datetime | None = None
        if started_at_iso:
            try:
                started_at = datetime.fromisoformat(started_at_iso)
            except ValueError:
                started_at = None

        last_error: Exception | None = None
        # Retry: API may briefly hold a read-only DuckDB handle (same-process
        # conflict with a writer). Stages have released the writer lock by now.
        for attempt in range(8):
            try:
                config = load_config(config_path)
                connection = get_connection(config)
                try:
                    finalize_analysis_for_job(
                        connection,
                        analysis_id,
                        job_succeeded=job_succeeded,
                        job_started_at=started_at,
                        config=config,
                    )
                finally:
                    connection.close()
                return
            except Exception as exc:  # noqa: BLE001 — retry then log
                last_error = exc
                time.sleep(0.05 * (attempt + 1))
        _LOG.warning(
            "Failed to finalize analysis %s after retries: %s",
            analysis_id,
            last_error,
        )

    def wait(self, job_id: str, timeout: float | None = None) -> bool:
        """Block until the job thread finishes (tests)."""
        with self._lock:
            thread = self._threads.get(job_id)
        if thread is None:
            return True
        thread.join(timeout=timeout)
        return not thread.is_alive()


_STORE = JobStore()


def get_job_store() -> JobStore:
    return _STORE


def reset_job_store() -> None:
    _STORE.reset()


def corpus_digest_for_path(path: Path) -> tuple[str, int]:
    """Single-file digest for analysis binding (sharded server-path starts)."""
    digest = hash_file_bytes(path)
    return digest.sha256, 1
