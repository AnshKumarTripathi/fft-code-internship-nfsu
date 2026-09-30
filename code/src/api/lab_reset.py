"""Operator lab wipe — remove regenerable pipeline outputs (trusted local host)."""

from __future__ import annotations

import gc
import shutil
import time
from pathlib import Path
from typing import Any

from src.api.pipeline_jobs import (
    JOB_STATUSES_ACTIVE,
    get_job_store,
    reset_job_store,
    warehouse_writer_busy,
)
from src.api.pipeline_uploads import upload_dir_from_config
from src.config import ConfigError, ensure_data_directories, normalize_settings
from src.db.connection import get_connection
from src.normalize.writers import (
    clear_normalize_dead_letter,
    clear_normalize_output,
)


class LabResetError(Exception):
    """Raised when lab reset cannot proceed safely."""

    def __init__(self, message: str, *, status_code: int = 409) -> None:
        super().__init__(message)
        self.status_code = status_code


def _rm_tree_contents(path: Path) -> list[str]:
    """Delete children of ``path``; keep the directory. Return relative names removed."""
    removed: list[str] = []
    if not path.is_dir():
        return removed
    for child in list(path.iterdir()):
        if child.name == ".gitkeep":
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=False)
        else:
            child.unlink(missing_ok=True)
        removed.append(child.name)
    return removed


def _rm_file(path: Path) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    path.unlink(missing_ok=True)
    return True


def _delete_warehouse(db_path: Path) -> list[str]:
    """Remove DuckDB file + WAL + writer lock. Retry briefly for Windows handles."""
    removed: list[str] = []
    candidates = [
        db_path,
        Path(str(db_path) + ".wal"),
        Path(str(db_path) + ".writer.lock"),
    ]
    last_error: OSError | None = None
    for _ in range(8):
        gc.collect()
        last_error = None
        pending = [p for p in candidates if p.exists() or p.is_symlink()]
        if not pending:
            break
        for path in pending:
            try:
                if _rm_file(path):
                    removed.append(path.name)
            except OSError as exc:
                last_error = exc
        if last_error is None:
            break
        time.sleep(0.05)
    if last_error is not None:
        still = [str(p) for p in candidates if p.exists()]
        raise LabResetError(
            "Could not delete warehouse files (file may still be open). "
            f"Close other DuckDB clients and retry. Remaining: {still}",
            status_code=503,
        ) from last_error
    return removed


def _clear_raw_non_upload(raw_dir: Path, upload_dir: Path) -> list[str]:
    """Remove top-level items under raw except the upload directory itself."""
    removed: list[str] = []
    if not raw_dir.is_dir():
        return removed
    upload_resolved = upload_dir.resolve()
    for child in list(raw_dir.iterdir()):
        if child.name == ".gitkeep":
            continue
        try:
            if child.resolve() == upload_resolved:
                continue
        except OSError:
            if child.name == upload_dir.name:
                continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=False)
        else:
            child.unlink(missing_ok=True)
        removed.append(child.name)
    return removed


def reset_lab_data(
    config: dict[str, Any],
    *,
    clear_uploads: bool = True,
    clear_raw_non_upload: bool = False,
) -> dict[str, Any]:
    """Wipe regenerable lab outputs. Blocks if a pipeline job is active or writer busy."""
    store = get_job_store()
    latest = store.latest()
    if latest is not None and latest.status in JOB_STATUSES_ACTIVE:
        raise LabResetError(
            "A pipeline job is still running. Wait for it to finish, then clear again.",
            status_code=409,
        )
    if warehouse_writer_busy(config):
        raise LabResetError(
            "Warehouse writer lock is held. Wait for the batch stage to finish.",
            status_code=409,
        )

    paths = config["paths"]
    db_path = Path(paths["db_path"])
    cleared: dict[str, list[str]] = {}

    cleared["warehouse"] = _delete_warehouse(db_path)

    dir_keys = (
        ("analyses_dir", "analyses"),
        ("report_dir", "reports"),
        ("scores_dir", "scores"),
        ("timeseries_dir", "timeseries"),
        ("parsed_dir", "parsed"),
        ("baseline_dir", "baselines"),
    )
    for key, label in dir_keys:
        raw = paths.get(key)
        if not raw:
            cleared[label] = []
            continue
        cleared[label] = _rm_tree_contents(Path(str(raw)))

    upload_dir = upload_dir_from_config(config)
    if clear_uploads:
        cleared["uploads"] = _rm_tree_contents(upload_dir)
    else:
        cleared["uploads"] = []

    # Phase 80 — regenerable normalize outputs (always wipe; independent of uploads).
    try:
        nsettings = normalize_settings(config)
        clear_normalize_output(nsettings)
        clear_normalize_dead_letter(nsettings)
        cleared["normalized"] = ["*"]
        cleared["normalize_dead_letter"] = ["*"]
    except ConfigError:
        cleared["normalized"] = []
        cleared["normalize_dead_letter"] = []

    raw_dir = Path(paths["raw_log_dir"])
    if clear_raw_non_upload:
        cleared["raw_other"] = _clear_raw_non_upload(raw_dir, upload_dir)
    else:
        cleared["raw_other"] = []

    ensure_data_directories(config)
    # Recreate an empty warehouse so Triage/Entities/Runs show empty lists
    # instead of "missing / busy" after a wipe.
    connection = get_connection(config)
    connection.close()
    reset_job_store()

    return {
        "ok": True,
        "cleared": cleared,
        "clear_uploads": clear_uploads,
        "clear_raw_non_upload": clear_raw_non_upload,
        "message": (
            "Lab outputs cleared. Stage logs and start a new run from Pipeline."
        ),
    }
