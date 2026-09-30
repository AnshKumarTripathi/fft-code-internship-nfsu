"""Hive partition path helpers (Windows-safe entity directories).

Hive folders are ``entity_id=<sanitized>``. Original ``entity_id`` is written
into Parquet columns so DuckDB syncs do not depend on decoding the folder name.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import quote


def sanitize_hive_value(value: str) -> str:
    """Percent-encode partition values so Windows rejects (*, ?, :, etc.) never appear."""
    # Keep common safe path chars unescaped; encode everything else (incl. *).
    return quote(str(value), safe=".-_")


def hive_entity_dir(parent: Path, entity_id: str) -> Path:
    """Return ``parent/entity_id=<sanitized>`` for parquet partition layout."""
    return parent / f"entity_id={sanitize_hive_value(entity_id)}"
