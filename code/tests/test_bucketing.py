"""Unit tests for bucket_events (Phase 4 pure logic)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.timeseries.bucketing import bucket_events

UTC = timezone.utc
IST = timezone(timedelta(hours=5, minutes=30))
ENTITY = "alice"
REF = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def test_empty_timestamps() -> None:
    assert bucket_events([], bucket_seconds=600, entity_id=ENTITY) == []


def test_single_bin_three_events() -> None:
    timestamps = [REF, REF + timedelta(seconds=30), REF + timedelta(seconds=59)]
    rows = bucket_events(timestamps, bucket_seconds=600, entity_id=ENTITY)
    assert len(rows) == 1
    assert rows[0].entity_id == ENTITY
    assert rows[0].bucket_seconds == 600
    assert rows[0].event_count == 3.0
    assert rows[0].bucket_start == REF


def test_boundary_half_open() -> None:
    """Half-open [start, start+bucket): t=600 lands in bin starting at 600."""
    base = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    t0 = base
    t600 = base + timedelta(seconds=600)
    t1199 = base + timedelta(seconds=1199)
    rows = bucket_events([t0, t600, t1199], bucket_seconds=600, entity_id=ENTITY)
    assert len(rows) == 2
    assert rows[0].bucket_start == base
    assert rows[0].event_count == 1.0  # t=0
    assert rows[1].bucket_start == t600
    assert rows[1].event_count == 2.0  # t=600 and t=1199


def test_zero_fill_gap() -> None:
    base = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    t0 = base
    t3600 = base + timedelta(seconds=3600)
    rows = bucket_events([t0, t3600], bucket_seconds=600, entity_id=ENTITY)
    assert len(rows) == 6  # bins starting 0,600,...,3000 (t=3600 in last bin)
    assert rows[0].event_count == 1.0
    assert rows[-1].event_count == 1.0
    for row in rows[1:-1]:
        assert row.event_count == 0.0


def test_timezone_normalization() -> None:
    utc_ts = datetime(2024, 6, 15, 6, 30, 0, tzinfo=UTC)
    ist_ts = datetime(2024, 6, 15, 12, 0, 0, tzinfo=IST)
    utc_rows = bucket_events([utc_ts], bucket_seconds=600, entity_id=ENTITY)
    ist_rows = bucket_events([ist_ts], bucket_seconds=600, entity_id=ENTITY)
    assert len(utc_rows) == 1
    assert len(ist_rows) == 1
    assert utc_rows[0].bucket_start == ist_rows[0].bucket_start
    assert utc_rows[0].event_count == ist_rows[0].event_count


def test_bucket_seconds_from_config() -> None:
    timestamps = [
        REF,
        REF + timedelta(seconds=30),
        REF + timedelta(seconds=90),
    ]
    wide = bucket_events(timestamps, bucket_seconds=600, entity_id=ENTITY)
    narrow = bucket_events(timestamps, bucket_seconds=60, entity_id=ENTITY)
    assert len(wide) == 1
    assert len(narrow) == 2
    assert wide[0].event_count == 3.0
    assert sum(r.event_count for r in narrow) == 3.0


@pytest.mark.parametrize("bucket_seconds", [0, -1])
def test_invalid_bucket_seconds(bucket_seconds: int) -> None:
    with pytest.raises(ValueError, match="bucket_seconds must be positive"):
        bucket_events([REF], bucket_seconds=bucket_seconds, entity_id=ENTITY)
