"""Static per-detector investigate/contain strings (R7). Not auto-action."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DEFAULT_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "statistical": {
        "title": "Investigate a rate burst",
        "hint": (
            "High event count versus this entity's typical windows. "
            "Confirm a known change before treating the flag as an attack."
        ),
        "actions": [
            "Review templates and log sources in the flagged window",
            "Check change tickets (patch, backup, mass password reset, log-level bump)",
            "Compare adjacent hours for a collector spike versus a host burst",
        ],
    },
    "spectral": {
        "title": "Investigate a rhythm change",
        "hint": (
            "Energy flags volume; shape flags mix or schedule. Dual OR can fire "
            "on either leg. Dominant period is argmax of the window PSD "
            "(DC skipped), not the attack period."
        ),
        "actions": [
            "Read which leg crossed (energy_z versus shape_js_z)",
            "Confirm HR, travel, or VPN timezone before treating a shape-only flag as C2",
            "Hand beacons faster than two buckets to the statistical rate detector",
        ],
    },
    "ml": {
        "title": "Investigate unusual template sequences",
        "hint": (
            "IsolationForest ranks how unusual this window's template/bigram "
            "vector is versus the batch. Coarse median-deviation attribution "
            "is not SHAP and not a named ATT&CK technique. Snapshot identity matters."
        ),
        "actions": [
            "Confirm parser and ML snapshot ids match the intended freeze",
            "Review top contributing templates / features on the why-flagged card",
            "Do not treat ML-only disagreement after an accidental re-train as a new incident",
        ],
    },
    "autoencoder": {
        "title": "Investigate a reconstruction residual",
        "hint": (
            "Autoencoder flags high reconstruction error on the same template/"
            "bigram features as IsolationForest. Unlike IF (path-length / "
            "isolation score), AE measures how poorly the window reconstructs "
            "from a compressed representation. Attribution ranks residual "
            "features, not SHAP. Treat as sequence-unusual versus this batch."
        ),
        "actions": [
            "Confirm ml.model_type is autoencoder and the AE snapshot id is the intended freeze",
            "Compare residual top features with an IsolationForest run on the same vocab",
            "Do not treat AE-only disagreement after a re-train as a new incident",
        ],
    },
    "ensemble": {
        "title": "Investigate an ML ensemble agreement",
        "hint": (
            "IsolationForest and autoencoder both scored this window; the "
            "fused flag uses the configured vote rule (default majority: "
            "both must flag). Member votes and scores are in metadata. "
            "This is still sequence-unusual versus the batch, not a named "
            "ATT&CK technique."
        ),
        "actions": [
            "Read which members voted (IF vs AE) on the why-flagged card",
            "Compare member scores when votes disagree across nearby windows",
            "Do not treat ensemble-only disagreement after a re-train as a new incident",
        ],
    },
    "onnx": {
        "title": "Investigate an ONNX sidecar score",
        "hint": (
            "Scoring uses a frozen .onnx model plus its sibling .vocab.json "
            "sidecar (export hash / vocab must match). The warehouse does not "
            "re-fit; honesty depends on the sidecar matching the export used "
            "to train. Attribution follows the exported model path "
            "(IF-style or AE residual), not live IsolationForest."
        ),
        "actions": [
            "Confirm onnx_model_path and the .vocab.json sidecar exist and match the export",
            "Check run manifest onnx_model_hash against the file you intended to score",
            "Do not treat ONNX-only disagreement after swapping the sidecar as a new incident",
        ],
    },
    "cluster_outlier": {
        "title": "Investigate a peer-group outlier",
        "hint": (
            "DBSCAN -1 means unlike the fitted groups, including rare but "
            "legitimate roles. Cold-start entities without a spectral baseline "
            "are not emitted."
        ),
        "actions": [
            "Compare the compact fingerprint to named peers",
            "Confirm the lookback window policy used for the anomaly span",
            "Review whether N was large enough to cluster (small labs skip this detector)",
        ],
    },
    "changepoint": {
        "title": "Investigate a volume level shift",
        "hint": (
            "Two-sided CUSUM on bucket counts. Flags a sustained mean jump or "
            "drop versus the entity's early-history median. Not a p-value; "
            "decision_h is a heuristic in MAD-sigma units. Distinct from a "
            "short statistical rate burst: look for a lasting step change."
        ),
        "actions": [
            "Confirm whether the shift is a collector outage, log-level change, or host silence",
            "Compare direction (up vs down) and span with the statistical rate detector",
            "Check adjacent entities / sources for a shared ingest cutover",
            "Do not treat a lone changepoint flag as proof of an implant",
        ],
    },
    "seasonal": {
        "title": "Investigate a seasonal residual",
        "hint": (
            "Counts differ from this entity's median profile for the same "
            "time-of-day phase (period_buckets, default 144 ≈ 24 h at 600 s). "
            "A schedule change, shift swap, or timezone hop can clear residual_z "
            "without a beacon; a beacon locked to the occupational rhythm can hide."
        ),
        "actions": [
            "Compare residual direction (high vs low) with spectral shape and rate",
            "Confirm HR / travel / VPN timezone before treating as C2",
            "Check whether the phase aligns with a known schedule change ticket",
            "Do not treat a lone seasonal flag as proof of an implant",
        ],
    },
}

# ML model_type values that have dedicated playbooks; others fall back to "ml".
ML_MODEL_PLAYBOOK_KEYS = frozenset({"autoencoder", "onnx", "ensemble"})

REQUIRED_PLAYBOOK_KEYS = ("title", "hint", "actions")


class PlaybookError(Exception):
    """Invalid playbooks file."""


def normalize_playbook(raw: Any, detector: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PlaybookError(f"playbook for {detector!r} must be a mapping")
    title = raw.get("title")
    hint = raw.get("hint")
    actions = raw.get("actions")
    if not isinstance(title, str) or not title.strip():
        raise PlaybookError(f"playbook {detector}.title must be a non-empty string")
    if not isinstance(hint, str) or not hint.strip():
        raise PlaybookError(f"playbook {detector}.hint must be a non-empty string")
    if not isinstance(actions, list) or not all(
        isinstance(item, str) and item.strip() for item in actions
    ):
        raise PlaybookError(
            f"playbook {detector}.actions must be a list of non-empty strings"
        )
    return {
        "title": title.strip(),
        "hint": hint.strip(),
        "actions": [item.strip() for item in actions],
    }


def _copy_playbook(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": str(payload.get("title") or ""),
        "hint": str(payload.get("hint") or ""),
        "actions": [str(item) for item in payload.get("actions") or []],
    }


def load_playbooks(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load YAML playbooks, filling missing detectors from the built-in defaults."""
    merged = {
        detector: dict(payload)
        for detector, payload in DEFAULT_PLAYBOOKS.items()
    }
    if path is None:
        return merged
    file_path = Path(path)
    if not file_path.is_file():
        return merged
    loaded = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    if loaded is None:
        return merged
    if not isinstance(loaded, dict):
        raise PlaybookError("playbooks file must be a mapping of detector → playbook")
    for detector, payload in loaded.items():
        merged[str(detector)] = normalize_playbook(payload, str(detector))
    return merged


def playbook_lookup_keys(
    detector: str,
    *,
    model_type: str | None = None,
) -> list[str]:
    """Ordered catalog keys to try for a detector (and optional ML model_type)."""
    keys: list[str] = []
    if detector == "ml" and model_type:
        normalized = str(model_type).strip().lower()
        if normalized in ML_MODEL_PLAYBOOK_KEYS:
            keys.append(normalized)
    keys.append(detector)
    # Deduplicate while preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def playbook_for(
    detector: str,
    *,
    stored: dict[str, Any] | None = None,
    playbooks: dict[str, dict[str, Any]] | None = None,
    model_type: str | None = None,
) -> dict[str, Any] | None:
    """Resolve a playbook. Missing keys return None (graceful UI fallback)."""
    if isinstance(stored, dict) and stored.get("title") and stored.get("hint"):
        actions = stored.get("actions")
        if isinstance(actions, list):
            return {
                "title": str(stored["title"]),
                "hint": str(stored["hint"]),
                "actions": [str(item) for item in actions],
            }
    catalog = playbooks if playbooks is not None else DEFAULT_PLAYBOOKS
    for key in playbook_lookup_keys(detector, model_type=model_type):
        payload = catalog.get(key)
        if isinstance(payload, dict) and payload.get("title") and payload.get("hint"):
            return _copy_playbook(payload)
    return None
