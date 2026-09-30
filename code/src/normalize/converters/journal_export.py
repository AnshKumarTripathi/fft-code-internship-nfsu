"""journal_export converter — systemd journal → journalctl short-iso text.

Locked dialect (Phase 81): ``short_iso`` lines that include a parseable ISO
timestamp and preferably ``_SYSTEMD_UNIT=`` so Phase 21 ``linux_journald``
detection/extraction succeeds, e.g.::

    2024-01-15T10:00:01+00:00 hostname systemd[1]: Started ssh.service _SYSTEMD_UNIT=ssh.service

Primary path: subprocess ``journalctl --file=<path> -o short-iso --no-pager``.
Missing ``journalctl`` → ``converter_unavailable`` (common on Windows labs).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.normalize.converters._common import (
    check_byte_budget,
    resolve_under,
)
from src.normalize.models import ConvertedFile, ConverterError, ConverterResult


def journalctl_available() -> bool:
    return shutil.which("journalctl") is not None


def _run_journalctl(source: Path, *, max_lines: int) -> str:
    if not journalctl_available():
        raise ConverterError(
            "journalctl not found on PATH; install systemd/journalctl "
            "or convert the journal on a Linux host",
            reason="converter_unavailable",
        )
    try:
        completed = subprocess.run(
            [
                "journalctl",
                f"--file={source}",
                "-o",
                "short-iso",
                "--no-pager",
                "-n",
                str(max_lines),
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except OSError as exc:
        raise ConverterError(
            f"journalctl failed to start: {exc}",
            reason="converter_unavailable",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ConverterError("journalctl timed out", reason="corrupt") from exc

    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip()
        raise ConverterError(
            f"journalctl exited {completed.returncode}: {err[:500]}",
            reason="corrupt",
        )
    return completed.stdout or ""


def _ensure_journald_markers(text: str) -> str:
    """If journalctl short-iso lacks _SYSTEMD_UNIT, keep as-is (filename may help).

    When lines already contain unit markers, leave unchanged. No invented fields.
    """
    return text


def convert_journal_export(
    source: Path,
    output_dir: Path,
    *,
    relative_base: str,
    max_member_bytes: int,
    max_total_output_bytes: int,
    bytes_written_so_far: int,
    max_members_per_archive: int,
    settings: dict[str, Any] | None = None,
) -> ConverterResult:
    _ = max_members_per_archive
    settings = settings or {}
    journal_cfg = settings.get("journal") or {}
    if not isinstance(journal_cfg, dict):
        journal_cfg = {}
    max_lines = int(journal_cfg.get("max_lines", 500_000))

    rel_parent = str(Path(relative_base).parent).replace("\\", "/")
    out_name = f"{source.name}.txt"
    if rel_parent in (".", ""):
        relative = out_name
    else:
        relative = f"{rel_parent}/{out_name}"
    destination = resolve_under(output_dir, relative)

    raw_text = _run_journalctl(source, max_lines=max_lines)
    text = _ensure_journald_markers(raw_text).strip()
    if not text:
        raise ConverterError("journalctl produced no lines", reason="empty_archive")

    # Cap line count defensively
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        text = "\n".join(lines)
    payload = (text + "\n").encode("utf-8")

    check_byte_budget(
        adding=len(payload),
        member_bytes=len(payload),
        max_member_bytes=max_member_bytes,
        bytes_written_so_far=bytes_written_so_far,
        max_total_output_bytes=max_total_output_bytes,
    )
    if payload == source.read_bytes():
        raise ConverterError(
            "journal_export refused rename-only output (bytes identical to input)",
            reason="rename_only",
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return ConverterResult(
        files=[
            ConvertedFile(
                output_path=destination,
                bytes_out=len(payload),
                converter="journal_export",
            )
        ]
    )
