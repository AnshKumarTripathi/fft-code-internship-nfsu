"""Byte-level SHA-256 for ingest chain of custody (R4).

File hashes use the bytes on disk, not a UTF-8 replacement decode.
Policy A line hashes (``hash_raw_line``) stay in ``loaders`` and remain
utf-8-replace; this module is for evidence of the original bytes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class SourceFileDigest:
    source_path: str
    sha256: str
    size_bytes: int
    mtime_utc: datetime


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file_bytes(path: Path) -> SourceFileDigest:
    """Stream SHA-256 of ``path`` as raw bytes (never decoded)."""
    hasher = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
            size_bytes += len(chunk)
    mtime_utc = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return SourceFileDigest(
        source_path=str(path),
        sha256=hasher.hexdigest(),
        size_bytes=size_bytes,
        mtime_utc=mtime_utc,
    )


def merkle_sha256(digests: Sequence[str]) -> str:
    """SHA-256 of sorted hex digests joined by newline.

    Empty input is SHA-256 of the empty byte string. Order of ``digests``
    does not matter; the join is sorted so a shuffled part list is stable.
    """
    payload = "\n".join(sorted(digests)).encode("ascii")
    return hashlib.sha256(payload).hexdigest()
