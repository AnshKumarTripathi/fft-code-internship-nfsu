"""Sealed run manifest: git, config hashes, package versions (R4).

Attached to every ``pipeline_runs`` row via ``params_json.manifest``.
Missing git or config files yield nulls — never fail a stage for that.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST_PACKAGES: tuple[tuple[str, str], ...] = (
    ("numpy", "numpy"),
    ("scipy", "scipy"),
    ("sklearn", "scikit-learn"),
    ("drain3", "drain3"),
)

_GIT_TIMEOUT_SECONDS = 2.0


def build_run_manifest(config_path: str | Path | None = None) -> dict[str, Any]:
    """Return a JSON-serialisable manifest dict."""
    yaml_path = _existing_file(config_path)
    ini_path = _drain3_ini_path(config_path)
    return {
        "git_commit": git_commit(),
        "pipeline_yaml_sha256": _sha256_or_none(yaml_path),
        "drain3_ini_sha256": _sha256_or_none(ini_path),
        "package_versions": package_versions(),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "parser_snapshot_id": None,
        "model_snapshot_id": None,
        "onnx_model_hash": None,
        "cluster_run_id": None,
    }


def git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    digest = result.stdout.strip()
    return digest or None


def package_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for label, dist_name in MANIFEST_PACKAGES:
        try:
            versions[label] = importlib.metadata.version(dist_name)
        except importlib.metadata.PackageNotFoundError:
            versions[label] = None
    return versions


def _existing_file(path: str | Path | None) -> Path | None:
    if path is None:
        return None
    candidate = Path(path)
    if candidate.is_file():
        return candidate
    return None


def _drain3_ini_path(config_path: str | Path | None) -> Path | None:
    if config_path is not None:
        sibling = Path(config_path).resolve().parent / "drain3.ini"
        if sibling.is_file():
            return sibling
    cwd_candidate = Path("config") / "drain3.ini"
    if cwd_candidate.is_file():
        return cwd_candidate
    return None


def _sha256_or_none(path: Path | None) -> str | None:
    if path is None:
        return None
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()
