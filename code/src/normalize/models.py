"""Normalize stage summary and shared result types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class NormalizeSummary:
    files_in: int = 0
    files_out: int = 0
    files_passthrough: int = 0
    files_converted: int = 0
    dead_lettered: int = 0
    converter_unavailable: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    skipped_disabled: bool = False
    skipped_empty: bool = False
    input_dir: str | None = None
    output_dir: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ConvertedFile:
    """One file written under the normalize output tree."""

    output_path: Path
    bytes_out: int
    converter: str


@dataclass
class ConverterResult:
    files: list[ConvertedFile] = field(default_factory=list)


class NormalizeError(Exception):
    """Raised when normalize cannot proceed (config or on_unsupported=fail)."""


class ConverterError(Exception):
    """Raised when a single archive/member fails (zip slip, bomb, corrupt)."""

    def __init__(self, message: str, *, reason: str = "converter_error") -> None:
        super().__init__(message)
        self.reason = reason
