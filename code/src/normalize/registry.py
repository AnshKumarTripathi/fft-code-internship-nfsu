"""Converter id → callable registry for normalize."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.normalize.converters.bunzip2 import convert_bunzip2
from src.normalize.converters.evtx_text import convert_evtx_text
from src.normalize.converters.gunzip import convert_gunzip
from src.normalize.converters.journal_export import convert_journal_export
from src.normalize.converters.tar_archive import convert_tar
from src.normalize.converters.unzip import convert_unzip
from src.normalize.models import ConverterResult

ConverterFn = Callable[..., ConverterResult]

KNOWN_CONVERTERS: dict[str, ConverterFn] = {
    "gunzip": convert_gunzip,
    "bunzip2": convert_bunzip2,
    "unzip": convert_unzip,
    "tar": convert_tar,
    "evtx_text": convert_evtx_text,
    "journal_export": convert_journal_export,
}


def get_converter(converter_id: str) -> ConverterFn:
    try:
        return KNOWN_CONVERTERS[converter_id]
    except KeyError as exc:
        raise KeyError(f"unknown normalize converter: {converter_id!r}") from exc


def run_converter(
    converter_id: str,
    source: Path,
    output_dir: Path,
    *,
    relative_base: str,
    settings: dict[str, Any],
    bytes_written_so_far: int,
) -> ConverterResult:
    fn = get_converter(converter_id)
    return fn(
        source,
        output_dir,
        relative_base=relative_base,
        max_member_bytes=int(settings["max_member_bytes"]),
        max_total_output_bytes=int(settings["max_total_output_bytes"]),
        bytes_written_so_far=bytes_written_so_far,
        max_members_per_archive=int(settings["max_members_per_archive"]),
        settings=settings,
    )
