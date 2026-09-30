"""Optional extractor protocol so a later version can add families as files."""

from __future__ import annotations

from typing import Protocol

from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


class LogExtractor(Protocol):
    """Source-family extractor (SSH in v2; Windows/firewall later)."""

    def extract(
        self,
        line: str,
        *,
        default_year: int,
        year_state: SyslogYearState | None = None,
        year_policy: str = "carry",
    ) -> ExtractionResult: ...
