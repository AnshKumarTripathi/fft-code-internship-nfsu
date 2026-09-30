"""Tests for Windows-safe hive partition path helpers."""

from __future__ import annotations

from pathlib import Path

from src.hive_paths import hive_entity_dir, sanitize_hive_value
from src.timeseries.writers import write_entity_buckets
from src.timeseries.bucketing import BucketCountRow
from datetime import datetime, timezone


def test_sanitize_asterisks_for_windows() -> None:
    assert "*" not in sanitize_hive_value("*****")
    assert sanitize_hive_value("*****") == "%2A%2A%2A%2A%2A"
    assert sanitize_hive_value("alice") == "alice"
    assert sanitize_hive_value("user:name") == "user%3Aname"


def test_hive_entity_dir_encodes_stars(tmp_path: Path) -> None:
    path = hive_entity_dir(tmp_path, "*****")
    assert path.name == "entity_id=%2A%2A%2A%2A%2A"
    path.mkdir(parents=True, exist_ok=True)
    assert path.is_dir()


def test_write_entity_buckets_with_star_username(tmp_path: Path) -> None:
    ts = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
    rows = [
        BucketCountRow(
            entity_id="*****",
            bucket_start=ts,
            bucket_seconds=600,
            event_count=3.0,
        )
    ]
    out = write_entity_buckets(tmp_path, "*****", rows)
    assert out is not None
    assert out.is_file()
    assert "%2A" in str(out.parent)
