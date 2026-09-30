"""Phase 92 — opt-in analysis window for heavy detectors on merged history.

When ``sharding.analysis_window.enabled`` is true, detectors score only the
bounded slice of ``entity_bucket_counts`` / ``parsed_events``. Warehouse rows
outside the window are **not** deleted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from src.config import sharding_settings

UTC = timezone.utc


@dataclass(frozen=True)
class AnalysisWindow:
    """Inclusive UTC bounds applied at detect collect time."""

    mode: str  # "last_days" | "absolute"
    start_utc: datetime
    end_utc: datetime
    last_days: int | None = None
    anchor_utc: datetime | None = None

    def to_params(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "mode": self.mode,
            "last_days": self.last_days,
            "start_utc": _iso(self.start_utc),
            "end_utc": _iso(self.end_utc),
            "anchor_utc": _iso(self.anchor_utc) if self.anchor_utc else None,
        }


def analysis_window_disabled_params() -> dict[str, Any]:
    return {"enabled": False}


def attach_analysis_window_params(
    params: dict[str, Any],
    window: AnalysisWindow | None,
) -> None:
    params["analysis_window"] = (
        window.to_params() if window is not None else analysis_window_disabled_params()
    )


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_utc_timestamp(raw: Any, *, field_name: str) -> datetime:
    """Parse an ISO-8601 timestamp; naive values are treated as UTC."""
    if isinstance(raw, datetime):
        return _ensure_utc(raw)
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{field_name} must be a non-empty ISO-8601 timestamp")
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be ISO-8601 UTC (got {raw!r})"
        ) from exc
    return _ensure_utc(parsed)


def resolve_analysis_window(
    config: dict[str, Any],
    connection: Any,
    *,
    source: str = "buckets",
) -> AnalysisWindow | None:
    """Resolve the active analysis window, or ``None`` when disabled.

    ``source`` selects the anchor for ``last_days`` mode:
    - ``buckets`` → ``max(bucket_start)`` on ``entity_bucket_counts``
    - ``events`` → ``max(event_timestamp)`` on ``parsed_events``
    """
    settings = sharding_settings(config)["analysis_window"]
    if not settings["enabled"]:
        return None

    start_raw = settings.get("start_utc")
    end_raw = settings.get("end_utc")
    if start_raw is not None or end_raw is not None:
        if start_raw is None or end_raw is None:
            raise ValueError(
                "sharding.analysis_window.start_utc and end_utc "
                "must both be set for absolute mode"
            )
        start = parse_utc_timestamp(
            start_raw, field_name="sharding.analysis_window.start_utc"
        )
        end = parse_utc_timestamp(
            end_raw, field_name="sharding.analysis_window.end_utc"
        )
        if start > end:
            raise ValueError(
                "sharding.analysis_window.start_utc must be <= end_utc"
            )
        return AnalysisWindow(
            mode="absolute",
            start_utc=start,
            end_utc=end,
            last_days=None,
            anchor_utc=None,
        )

    last_days = int(settings["last_days"])
    if source == "events":
        row = connection.execute(
            "SELECT max(event_timestamp) FROM parsed_events"
        ).fetchone()
    else:
        row = connection.execute(
            "SELECT max(bucket_start) FROM entity_bucket_counts"
        ).fetchone()
    anchor = row[0] if row else None
    if anchor is None or not isinstance(anchor, datetime):
        return None
    anchor_utc = _ensure_utc(anchor)
    start = anchor_utc - timedelta(days=last_days)
    return AnalysisWindow(
        mode="last_days",
        start_utc=start,
        end_utc=anchor_utc,
        last_days=last_days,
        anchor_utc=anchor_utc,
    )


def bucket_series_sql(window: AnalysisWindow | None) -> tuple[str, list[Any]]:
    """Return SELECT for entity bucket series, optionally window-filtered."""
    base = """
        SELECT entity_id, bucket_start, bucket_seconds, event_count
        FROM entity_bucket_counts
    """
    if window is None:
        return (
            base + " ORDER BY entity_id, bucket_start",
            [],
        )
    return (
        base
        + """
        WHERE bucket_start >= ? AND bucket_start <= ?
        ORDER BY entity_id, bucket_start
        """,
        [window.start_utc, window.end_utc],
    )


def event_series_sql(window: AnalysisWindow | None) -> tuple[str, list[Any]]:
    """Return SELECT for parsed events, optionally window-filtered."""
    base = """
        SELECT entity_id, event_timestamp, template_id
        FROM parsed_events
    """
    if window is None:
        return (
            base + " ORDER BY entity_id, event_timestamp",
            [],
        )
    return (
        base
        + """
        WHERE event_timestamp >= ? AND event_timestamp <= ?
        ORDER BY entity_id, event_timestamp
        """,
        [window.start_utc, window.end_utc],
    )


def execute_query(
    connection: Any,
    sql: str,
    params: list[Any],
) -> Any:
    if params:
        return connection.execute(sql, params)
    return connection.execute(sql)
