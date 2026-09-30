"""Safe listing and resolution of incident report files (Phase 17 / 37 / 98)."""

from __future__ import annotations

import re
from pathlib import Path

from src.api.schemas import ReportFileItem

# Jinja: incident_{id}.md|.html ; Phase 98 Insight: incident_{id}_ai_insight.md
REPORT_FILENAME_RE = re.compile(
    r"^incident_[A-Za-z0-9_-]+(?:_ai_insight)?\.(md|html)$"
)
DEFAULT_REPORT_LIMIT = 100
MAX_REPORT_LIMIT = 500
_AI_INSIGHT_SUFFIX = "_ai_insight"

_MEDIA_TYPES = {
    ".md": "text/markdown",
    ".html": "text/html",
}


def is_safe_report_filename(filename: str) -> bool:
    if not filename:
        return False
    if ".." in filename or "/" in filename or "\\" in filename:
        return False
    if Path(filename).is_absolute():
        return False
    return REPORT_FILENAME_RE.fullmatch(filename) is not None


def is_ai_insight_filename(filename: str) -> bool:
    stem = Path(filename).stem
    return stem.startswith("incident_") and stem.endswith(_AI_INSIGHT_SUFFIX)


def incident_id_from_report_filename(filename: str) -> str:
    stem = Path(filename).stem
    if stem.endswith(_AI_INSIGHT_SUFFIX):
        stem = stem[: -len(_AI_INSIGHT_SUFFIX)]
    prefix = "incident_"
    if stem.startswith(prefix):
        return stem[len(prefix) :]
    return stem


def media_type_for_report(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    return _MEDIA_TYPES.get(suffix, "text/plain")


def resolve_report_file(report_dir: Path, filename: str) -> Path | None:
    """Return the file if it exists and the name is a guarded incident report."""
    if not is_safe_report_filename(filename):
        return None
    root = report_dir.resolve()
    candidate = (root / filename).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


def list_report_files(
    report_dir: Path,
    *,
    limit: int = DEFAULT_REPORT_LIMIT,
    offset: int = 0,
) -> tuple[list[ReportFileItem], int]:
    if not report_dir.is_dir():
        return [], 0
    names = sorted(
        name
        for name in report_dir.iterdir()
        if name.is_file() and is_safe_report_filename(name.name)
    )
    total = len(names)
    offset = max(0, int(offset))
    limit = max(1, min(int(limit), MAX_REPORT_LIMIT))
    sliced = names[offset : offset + limit]
    items = [
        ReportFileItem(
            filename=path.name,
            incident_id=incident_id_from_report_filename(path.name),
            media_type=media_type_for_report(path.name),
        )
        for path in sliced
    ]
    return items, total
