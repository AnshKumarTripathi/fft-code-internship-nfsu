"""Load entity/window labels from CSV or Parquet."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

ALLOWED_LABELS = frozenset({"benign", "attacker"})
REQUIRED_COLUMNS = ("entity_id", "label")


class EvaluationError(Exception):
    """Raised when evaluate cannot proceed (missing labels, unreadable file)."""


@dataclass(frozen=True)
class LabelRow:
    entity_id: str
    label: str
    window_start: datetime | None
    window_end: datetime | None
    attack_type: str | None


def load_labels(path: str | Path) -> list[LabelRow]:
    """Parse a labels file into ``LabelRow`` values.

    Both timestamps null → entity-level label. Exactly one timestamp is an error.
    """
    labels_path = Path(path)
    if not labels_path.is_file():
        raise EvaluationError(f"labels file not found: {labels_path}")

    frame = _read_labels_frame(labels_path)
    missing = [col for col in REQUIRED_COLUMNS if col not in frame.columns]
    if missing:
        raise EvaluationError(
            f"labels file missing required columns: {', '.join(missing)}"
        )

    rows: list[LabelRow] = []
    for index, record in frame.iterrows():
        entity_id = _required_text(record.get("entity_id"), "entity_id", index)
        label = _required_text(record.get("label"), "label", index).lower()
        if label not in ALLOWED_LABELS:
            raise EvaluationError(
                f"labels row {index}: label must be 'benign' or 'attacker', got {label!r}"
            )
        window_start = _parse_optional_utc(record.get("window_start"), "window_start", index)
        window_end = _parse_optional_utc(record.get("window_end"), "window_end", index)
        if (window_start is None) != (window_end is None):
            raise EvaluationError(
                f"labels row {index}: window_start and window_end must both be set "
                "or both be empty (entity-level label)"
            )
        attack_type = _optional_text(record.get("attack_type") if "attack_type" in frame.columns else None)
        rows.append(
            LabelRow(
                entity_id=entity_id,
                label=label,
                window_start=window_start,
                window_end=window_end,
                attack_type=attack_type,
            )
        )
    return rows


def _read_labels_frame(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    try:
        if suffix in {".parquet", ".pq"}:
            return pd.read_parquet(path)
        if suffix == ".csv":
            return pd.read_csv(path)
    except EvaluationError:
        raise
    except Exception as exc:
        raise EvaluationError(f"labels file unreadable: {path}: {exc}") from exc
    raise EvaluationError(
        f"labels file must be CSV or Parquet, got {suffix or path.name}"
    )


def _required_text(value: Any, column: str, index: Any) -> str:
    text = _optional_text(value)
    if text is None:
        raise EvaluationError(f"labels row {index}: {column} is required")
    return text


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    if pd.isna(value):
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "nat", "none", "null"}:
        return None
    return text


def _parse_optional_utc(value: Any, column: str, index: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    if pd.isna(value):
        return None
    if isinstance(value, datetime):
        return _ensure_utc(value)
    text = str(value).strip()
    if not text or text.lower() in {"nan", "nat", "none", "null"}:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise EvaluationError(
            f"labels row {index}: {column} is not ISO-8601: {value!r}"
        ) from exc
    return _ensure_utc(parsed)


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)
