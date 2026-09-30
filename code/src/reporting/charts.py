"""Self-contained SVG sparkline charts for deterministic HTML reports."""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

CHART_MAX_POINTS = 120
CHART_WIDTH = 720
CHART_HEIGHT = 180
CHART_PAD_LEFT = 44
CHART_PAD_RIGHT = 12
CHART_PAD_TOP = 12
CHART_PAD_BOTTOM = 28

OVERLAY_COLORS = {
    "statistical": "rgba(161, 74, 0, 0.22)",
    "spectral": "rgba(11, 110, 79, 0.22)",
}


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def downsample_xy(
    xs: Sequence[float],
    ys: Sequence[float],
    max_points: int = CHART_MAX_POINTS,
) -> tuple[list[float], list[float]]:
    n = min(len(xs), len(ys))
    if n == 0:
        return [], []
    if n <= max_points or max_points < 2:
        return list(xs[:n]), list(ys[:n])
    stride = max(1, n // max_points)
    return list(xs[::stride][:max_points]), list(ys[::stride][:max_points])


def _as_epoch(value: datetime | float | int | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.timestamp()
    return float(value)


def render_activity_svg(
    bucket_starts: Sequence[datetime | None],
    event_counts: Sequence[float],
    overlays: Sequence[tuple[str, datetime | None, datetime | None]] = (),
    *,
    title: str = "event_count per bucket",
) -> str:
    xs_raw: list[float] = []
    ys_raw: list[float] = []
    for start, count in zip(bucket_starts, event_counts, strict=False):
        epoch = _as_epoch(start)
        if epoch is None:
            continue
        xs_raw.append(epoch)
        ys_raw.append(float(count))
    xs, ys = downsample_xy(xs_raw, ys_raw)
    if len(xs) < 2:
        return ""
    return _polyline_svg(
        xs,
        ys,
        overlays=[
            (source, _as_epoch(start), _as_epoch(end))
            for source, start, end in overlays
        ],
        title=title,
        y_label="count",
        stroke="#0b6e4f",
        fill="rgba(11, 110, 79, 0.12)",
    )


def render_psd_svg(
    freq_grid: Sequence[float],
    psd_norm: Sequence[float],
    *,
    title: str = "normalized PSD",
) -> str:
    xs, ys = downsample_xy(list(freq_grid), list(psd_norm))
    if len(xs) < 2:
        return ""
    return _polyline_svg(
        xs,
        ys,
        overlays=[],
        title=title,
        y_label="psd",
        stroke="#1a1a1a",
        fill="rgba(26, 26, 26, 0.08)",
    )


def _polyline_svg(
    xs: list[float],
    ys: list[float],
    overlays: Sequence[tuple[str, float | None, float | None]],
    *,
    title: str,
    y_label: str,
    stroke: str,
    fill: str,
) -> str:
    x_min = min(xs)
    x_max = max(xs)
    y_min = 0.0
    y_max = max(ys) if ys else 1.0
    if y_max <= y_min:
        y_max = y_min + 1.0
    if x_max <= x_min:
        x_max = x_min + 1.0

    inner_w = CHART_WIDTH - CHART_PAD_LEFT - CHART_PAD_RIGHT
    inner_h = CHART_HEIGHT - CHART_PAD_TOP - CHART_PAD_BOTTOM

    def x_px(value: float) -> float:
        return CHART_PAD_LEFT + (value - x_min) / (x_max - x_min) * inner_w

    def y_px(value: float) -> float:
        return CHART_PAD_TOP + (1.0 - (value - y_min) / (y_max - y_min)) * inner_h

    points = " ".join(f"{x_px(x):.1f},{y_px(y):.1f}" for x, y in zip(xs, ys))
    area = f"{CHART_PAD_LEFT:.1f},{y_px(y_min):.1f} {points} {x_px(xs[-1]):.1f},{y_px(y_min):.1f}"

    overlay_rects: list[str] = []
    for source, start, end in overlays:
        if start is None or end is None:
            continue
        left = x_px(min(max(start, x_min), x_max))
        right = x_px(min(max(end, x_min), x_max))
        if right < left:
            left, right = right, left
        width = max(2.0, right - left)
        color = OVERLAY_COLORS.get(source, "rgba(26, 26, 26, 0.12)")
        overlay_rects.append(
            f'<rect x="{left:.1f}" y="{CHART_PAD_TOP}" width="{width:.1f}" '
            f'height="{inner_h}" fill="{color}" />'
        )

    y_top_label = f"{y_max:.2g}"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {CHART_WIDTH} {CHART_HEIGHT}" '
        f'width="100%" role="img" aria-label="{_xml_escape(title)}">'
        f'<title>{_xml_escape(title)}</title>'
        f'<rect x="0" y="0" width="{CHART_WIDTH}" height="{CHART_HEIGHT}" fill="#ffffff" />'
        + "".join(overlay_rects)
        + f'<polygon points="{area}" fill="{fill}" />'
        f'<polyline points="{points}" fill="none" stroke="{stroke}" '
        f'stroke-width="1.5" />'
        f'<text x="8" y="{CHART_PAD_TOP + 10}" fill="#5c5a55" font-size="10">'
        f"{_xml_escape(y_top_label)}</text>"
        f'<text x="8" y="{CHART_HEIGHT - 8}" fill="#5c5a55" font-size="10">'
        f"{_xml_escape(y_label)}</text>"
        "</svg>"
    )
