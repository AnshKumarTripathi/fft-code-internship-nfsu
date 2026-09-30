"""bunzip2 converter — stream decompress single-member .bz2 (not .tar.bz2)."""

from __future__ import annotations

import bz2
from pathlib import Path

from src.normalize.converters._common import (
    resolve_under,
    strip_compression_suffix,
    write_streamed,
)
from src.normalize.models import ConvertedFile, ConverterError, ConverterResult


def convert_bunzip2(
    source: Path,
    output_dir: Path,
    *,
    relative_base: str,
    max_member_bytes: int,
    max_total_output_bytes: int,
    bytes_written_so_far: int,
    max_members_per_archive: int,
    settings: dict | None = None,
) -> ConverterResult:
    _ = max_members_per_archive, settings
    out_name = strip_compression_suffix(source.name)
    if not out_name:
        out_name = f"{source.stem}.out"
    rel_parent = str(Path(relative_base).parent).replace("\\", "/")
    if rel_parent in (".", ""):
        relative = out_name
    else:
        relative = f"{rel_parent}/{out_name}"
    destination = resolve_under(output_dir, relative)

    try:
        with bz2.open(source, "rb") as handle:

            def chunks():
                while True:
                    block = handle.read(1024 * 1024)
                    if not block:
                        break
                    yield block

            written = write_streamed(
                destination,
                chunks(),
                max_member_bytes=max_member_bytes,
                bytes_written_so_far=bytes_written_so_far,
                max_total_output_bytes=max_total_output_bytes,
            )
    except ConverterError:
        if destination.exists():
            destination.unlink(missing_ok=True)
        raise
    except OSError as exc:
        if destination.exists():
            destination.unlink(missing_ok=True)
        raise ConverterError(f"bunzip2 failed: {exc}", reason="corrupt") from exc

    return ConverterResult(
        files=[
            ConvertedFile(
                output_path=destination,
                bytes_out=written,
                converter="bunzip2",
            )
        ]
    )
