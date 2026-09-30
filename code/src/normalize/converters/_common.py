"""Safe path helpers and streaming write caps for archive converters."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from src.normalize.models import ConverterError


def sanitize_member_name(name: str) -> str:
    """Return a relative POSIX-style member path or raise ConverterError (zip slip)."""
    raw = str(name).replace("\\", "/").strip()
    if not raw or raw.endswith("/"):
        raise ConverterError(f"empty or directory-only member: {name!r}", reason="zip_slip")
    if raw.startswith("/") or (len(raw) >= 2 and raw[1] == ":"):
        raise ConverterError(f"absolute member path rejected: {name!r}", reason="zip_slip")
    parts = [p for p in raw.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        raise ConverterError(f"path traversal rejected: {name!r}", reason="zip_slip")
    return "/".join(parts)


def resolve_under(output_root: Path, relative: str) -> Path:
    """Resolve ``relative`` under ``output_root``; reject escapes."""
    target = (output_root / relative).resolve()
    root = output_root.resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ConverterError(
            f"output path escapes normalize root: {relative!r}",
            reason="zip_slip",
        ) from exc
    return target


def strip_compression_suffix(name: str) -> str:
    lower = name.lower()
    for suffix in (".tar.gz", ".tar.bz2", ".tgz", ".gz", ".bz2", ".zip", ".tar"):
        if lower.endswith(suffix):
            return name[: len(name) - len(suffix)]
    return name


def check_byte_budget(
    *,
    adding: int,
    member_bytes: int,
    max_member_bytes: int,
    bytes_written_so_far: int,
    max_total_output_bytes: int,
) -> None:
    if member_bytes > max_member_bytes:
        raise ConverterError(
            f"member exceeds max_member_bytes ({max_member_bytes})",
            reason="size_cap",
        )
    if bytes_written_so_far + adding > max_total_output_bytes:
        raise ConverterError(
            f"archive would exceed max_total_output_bytes ({max_total_output_bytes})",
            reason="size_cap",
        )


def write_streamed(
    destination: Path,
    chunks: Iterable[bytes],
    *,
    max_member_bytes: int,
    bytes_written_so_far: int,
    max_total_output_bytes: int,
) -> int:
    """Write iterable of bytes chunks; return bytes written. Enforces caps."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with destination.open("wb") as handle:
        for chunk in chunks:
            if not chunk:
                continue
            next_total = written + len(chunk)
            check_byte_budget(
                adding=next_total,
                member_bytes=next_total,
                max_member_bytes=max_member_bytes,
                bytes_written_so_far=bytes_written_so_far,
                max_total_output_bytes=max_total_output_bytes,
            )
            handle.write(chunk)
            written = next_total
    return written
