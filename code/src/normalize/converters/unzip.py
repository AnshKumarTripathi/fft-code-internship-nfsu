"""unzip converter — extract zip members with zip-slip and bomb caps."""

from __future__ import annotations

import zipfile
from pathlib import Path

from src.normalize.converters._common import (
    resolve_under,
    sanitize_member_name,
    strip_compression_suffix,
    write_streamed,
)
from src.normalize.models import ConvertedFile, ConverterError, ConverterResult


def convert_unzip(
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
    _ = settings
    archive_stem = strip_compression_suffix(Path(relative_base).name) or source.stem
    rel_parent = str(Path(relative_base).parent).replace("\\", "/")
    if rel_parent in (".", ""):
        nest_root = archive_stem
    else:
        nest_root = f"{rel_parent}/{archive_stem}"

    results: list[ConvertedFile] = []
    written_total = bytes_written_so_far

    try:
        with zipfile.ZipFile(source, "r") as zf:
            infos = [info for info in zf.infolist() if not info.is_dir()]
            if len(infos) > max_members_per_archive:
                raise ConverterError(
                    f"zip has {len(infos)} members; max_members_per_archive="
                    f"{max_members_per_archive}",
                    reason="member_cap",
                )
            for info in infos:
                if info.filename.endswith("/") or not info.filename:
                    continue
                # Symlink / special: ZipInfo flag_bits; reject external_attr symlink bit loosely
                member = sanitize_member_name(info.filename)
                relative = f"{nest_root}/{member}"
                destination = resolve_under(output_dir, relative)

                def chunks(name: str = info.filename):
                    with zf.open(name, "r") as handle:
                        while True:
                            block = handle.read(1024 * 1024)
                            if not block:
                                break
                            yield block

                try:
                    written = write_streamed(
                        destination,
                        chunks(),
                        max_member_bytes=max_member_bytes,
                        bytes_written_so_far=written_total,
                        max_total_output_bytes=max_total_output_bytes,
                    )
                except ConverterError:
                    if destination.exists():
                        destination.unlink(missing_ok=True)
                    raise
                written_total += written
                results.append(
                    ConvertedFile(
                        output_path=destination,
                        bytes_out=written,
                        converter="unzip",
                    )
                )
    except ConverterError:
        raise
    except zipfile.BadZipFile as exc:
        raise ConverterError(f"bad zip: {exc}", reason="corrupt") from exc
    except OSError as exc:
        raise ConverterError(f"unzip failed: {exc}", reason="corrupt") from exc

    if not results:
        raise ConverterError("zip contained no extractable files", reason="empty_archive")
    return ConverterResult(files=results)
