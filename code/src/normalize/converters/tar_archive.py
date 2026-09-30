"""tar converter — .tar / .tar.gz / .tgz / .tar.bz2 with path safety caps."""

from __future__ import annotations

import tarfile
from pathlib import Path

from src.normalize.converters._common import (
    resolve_under,
    sanitize_member_name,
    strip_compression_suffix,
    write_streamed,
)
from src.normalize.models import ConvertedFile, ConverterError, ConverterResult


def convert_tar(
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
        with tarfile.open(source, mode="r:*") as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            if len(members) > max_members_per_archive:
                raise ConverterError(
                    f"tar has {len(members)} members; max_members_per_archive="
                    f"{max_members_per_archive}",
                    reason="member_cap",
                )
            for member in members:
                if member.issym() or member.islnk():
                    raise ConverterError(
                        f"symlink/hardlink member rejected: {member.name!r}",
                        reason="symlink",
                    )
                safe = sanitize_member_name(member.name)
                relative = f"{nest_root}/{safe}"
                destination = resolve_under(output_dir, relative)
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue

                def chunks(handle=extracted):
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
                finally:
                    extracted.close()
                written_total += written
                results.append(
                    ConvertedFile(
                        output_path=destination,
                        bytes_out=written,
                        converter="tar",
                    )
                )
    except ConverterError:
        raise
    except tarfile.TarError as exc:
        raise ConverterError(f"bad tar: {exc}", reason="corrupt") from exc
    except OSError as exc:
        raise ConverterError(f"tar extract failed: {exc}", reason="corrupt") from exc

    if not results:
        raise ConverterError("tar contained no extractable files", reason="empty_archive")
    return ConverterResult(files=results)
