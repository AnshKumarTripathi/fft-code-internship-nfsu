"""Fuse IsolationForest + autoencoder window scores (opt-in ML ensemble)."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any, Iterable, Sequence

from src.detectors.ml.isolation_forest import MlWindowScore

ALLOWED_FUSIONS = frozenset({"majority", "any", "unanimous"})


def _window_key(row: MlWindowScore) -> tuple[str, datetime]:
    return (row.entity_id, row.window_start)


def _index_rows(rows: Sequence[MlWindowScore]) -> dict[tuple[str, datetime], MlWindowScore]:
    return {_window_key(row): row for row in rows}


def _vote_flagged(
    flags: Sequence[bool],
    *,
    fusion: str,
) -> bool:
    if not flags:
        return False
    n_true = sum(1 for flag in flags if flag)
    n = len(flags)
    if fusion == "any":
        return n_true >= 1
    if fusion == "unanimous":
        return n_true == n
    # majority: strict majority (> n/2). For two models this means both.
    return n_true > (n / 2.0)


def _pick_attribution(
    members: dict[str, MlWindowScore],
    *,
    flagged: bool,
) -> dict[str, Any] | None:
    """Prefer attribution from a flagged member with the highest score."""
    candidates = list(members.items())
    if flagged:
        voted = [(name, row) for name, row in candidates if row.flagged]
        if voted:
            candidates = voted
    candidates.sort(key=lambda item: -float(item[1].model_score))
    for _, row in candidates:
        if row.attribution:
            return dict(row.attribution)
    return None


def fuse_ml_window_scores(
    member_rows: dict[str, Sequence[MlWindowScore]],
    *,
    fusion: str = "majority",
) -> list[MlWindowScore]:
    """Merge per-model scores into one row per window.

    ``member_rows`` maps model name → scored windows (same window set expected).
    Flagging uses ``fusion`` on member ``flagged`` bits. ``model_score`` /
    ``mad_z`` take the max across members for ranking continuity with correlate.
    """
    normalized = str(fusion).strip().lower()
    if normalized not in ALLOWED_FUSIONS:
        raise ValueError(
            f"fusion must be one of {sorted(ALLOWED_FUSIONS)}, got {fusion!r}"
        )
    if len(member_rows) < 2:
        raise ValueError("ensemble fusion requires at least two member score lists")

    indexes = {
        name: _index_rows(rows) for name, rows in member_rows.items() if rows
    }
    if len(indexes) < 2:
        return []

    keys: set[tuple[str, datetime]] = set()
    for index in indexes.values():
        keys |= set(index.keys())

    fused: list[MlWindowScore] = []
    model_names = sorted(indexes.keys())
    for key in sorted(keys, key=lambda item: (item[0], item[1])):
        members: dict[str, MlWindowScore] = {}
        for name in model_names:
            row = indexes[name].get(key)
            if row is not None:
                members[name] = row
        if len(members) < 2:
            # Incomplete member coverage — skip rather than invent a vote.
            continue

        flags = [row.flagged for row in members.values()]
        flagged = _vote_flagged(flags, fusion=normalized)
        scores = [float(row.model_score) for row in members.values()]
        model_score = max(scores)
        mad_values = [
            float(row.mad_z) for row in members.values() if row.mad_z is not None
        ]
        mad_z = max(mad_values) if mad_values else None

        base = next(iter(members.values()))
        attribution = _pick_attribution(members, flagged=flagged) or {}
        attribution["ensemble"] = {
            "fusion": normalized,
            "votes": {name: bool(row.flagged) for name, row in members.items()},
            "scores": {
                name: float(row.model_score) for name, row in members.items()
            },
            "mad_z": {
                name: (float(row.mad_z) if row.mad_z is not None else None)
                for name, row in members.items()
            },
            "snapshot_ids": {
                name: row.model_snapshot_id for name, row in members.items()
            },
        }

        # Prefer IF snapshot id when present for the scalar column; both live in
        # attribution.ensemble.snapshot_ids.
        snapshot_id = members.get("isolation_forest", base).model_snapshot_id
        if snapshot_id is None:
            snapshot_id = base.model_snapshot_id

        fused.append(
            replace(
                base,
                model_score=model_score,
                flagged=flagged,
                mad_z=mad_z,
                model_snapshot_id=snapshot_id,
                attribution=attribution,
            )
        )
    return fused


def ensemble_summary_votes(
    rows: Iterable[MlWindowScore],
) -> dict[str, int]:
    """Count per-model true votes across fused rows (for run summaries)."""
    counts: dict[str, int] = {}
    for row in rows:
        ensemble = (row.attribution or {}).get("ensemble") or {}
        votes = ensemble.get("votes") or {}
        if not isinstance(votes, dict):
            continue
        for name, flagged in votes.items():
            if flagged:
                counts[str(name)] = counts.get(str(name), 0) + 1
    return counts
