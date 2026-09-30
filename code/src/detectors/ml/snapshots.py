"""ML model + vocab snapshots under ``baseline_dir/snapshots/ml/`` (R5 / Phase 53)."""

from __future__ import annotations

import hashlib
import pickle
from pathlib import Path
from typing import Union

from src.detectors.ml.autoencoder import AutoencoderBundle
from src.detectors.ml.isolation_forest import IsolationBundle

ML_SNAPSHOT_FILENAME = "isolation_forest.pkl"
AE_SNAPSHOT_FILENAME = "autoencoder.pkl"

MlBundle = Union[IsolationBundle, AutoencoderBundle]


class MlSnapshotError(Exception):
    """Raised when an ML snapshot cannot be loaded."""


def ml_snapshot_path(
    baseline_dir: str | Path,
    snapshot_id: str,
    *,
    filename: str = ML_SNAPSHOT_FILENAME,
) -> Path:
    return Path(baseline_dir) / "snapshots" / "ml" / snapshot_id / filename


def save_ml_snapshot(baseline_dir: str | Path, bundle: IsolationBundle) -> str:
    """Pickle an IsolationForest bundle; return content-addressed snapshot id."""
    payload = pickle.dumps(bundle, protocol=4)
    snapshot_id = hashlib.sha256(payload).hexdigest()
    path = ml_snapshot_path(baseline_dir, snapshot_id, filename=ML_SNAPSHOT_FILENAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return snapshot_id


def save_autoencoder_snapshot(
    baseline_dir: str | Path, bundle: AutoencoderBundle
) -> str:
    """Pickle an autoencoder bundle; return content-addressed snapshot id."""
    payload = pickle.dumps(bundle, protocol=4)
    snapshot_id = hashlib.sha256(payload).hexdigest()
    path = ml_snapshot_path(baseline_dir, snapshot_id, filename=AE_SNAPSHOT_FILENAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return snapshot_id


def load_ml_snapshot(baseline_dir: str | Path, snapshot_id: str) -> IsolationBundle:
    if not snapshot_id:
        raise MlSnapshotError(
            "ml.snapshot_id is required when ml.mode is reuse_snapshot"
        )
    path = ml_snapshot_path(baseline_dir, snapshot_id, filename=ML_SNAPSHOT_FILENAME)
    if not path.is_file():
        raise MlSnapshotError(f"ML snapshot not found: {path}")
    bundle = pickle.loads(path.read_bytes())
    if not isinstance(bundle, IsolationBundle):
        raise MlSnapshotError(f"ML snapshot is not an IsolationBundle: {path}")
    return bundle


def load_autoencoder_snapshot(
    baseline_dir: str | Path, snapshot_id: str
) -> AutoencoderBundle:
    if not snapshot_id:
        raise MlSnapshotError(
            "ml.snapshot_id is required when ml.mode is reuse_snapshot"
        )
    path = ml_snapshot_path(baseline_dir, snapshot_id, filename=AE_SNAPSHOT_FILENAME)
    if not path.is_file():
        raise MlSnapshotError(f"Autoencoder snapshot not found: {path}")
    bundle = pickle.loads(path.read_bytes())
    if not isinstance(bundle, AutoencoderBundle):
        raise MlSnapshotError(f"ML snapshot is not an AutoencoderBundle: {path}")
    return bundle


def load_any_ml_snapshot(
    baseline_dir: str | Path, snapshot_id: str
) -> MlBundle:
    """Load IF or AE snapshot; prefer matching filename when both exist."""
    if not snapshot_id:
        raise MlSnapshotError(
            "ml.snapshot_id is required when ml.mode is reuse_snapshot"
        )
    ae_path = ml_snapshot_path(
        baseline_dir, snapshot_id, filename=AE_SNAPSHOT_FILENAME
    )
    if_path = ml_snapshot_path(
        baseline_dir, snapshot_id, filename=ML_SNAPSHOT_FILENAME
    )
    if ae_path.is_file():
        return load_autoencoder_snapshot(baseline_dir, snapshot_id)
    if if_path.is_file():
        return load_ml_snapshot(baseline_dir, snapshot_id)
    raise MlSnapshotError(
        f"ML snapshot not found under {Path(baseline_dir) / 'snapshots' / 'ml' / snapshot_id}"
    )
