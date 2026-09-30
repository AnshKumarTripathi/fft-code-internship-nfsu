"""Bounded content-hash set for ingest Policy A dedup.

Keeps unique ``sha256(raw_line)`` digests within a single ingest run. The
in-memory set is capped; overflow spills to a temporary SQLite file so RAM
stays bounded.
"""

from __future__ import annotations

import logging
import sqlite3
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

BACKEND_MEMORY = "memory"
BACKEND_SQLITE = "sqlite"


class ContentHashSet:
    """True from ``add`` means first time seen (keep the line)."""

    def __init__(
        self,
        *,
        memory_max: int,
        backend: str = BACKEND_MEMORY,
        spill_dir: Path | None = None,
    ) -> None:
        if memory_max < 1:
            raise ValueError("memory_max must be >= 1")
        self._memory: set[str] = set()
        self._memory_max = memory_max
        self._spill_dir = spill_dir
        self._conn: sqlite3.Connection | None = None
        self._spill_path: Path | None = None
        self._spilled = False
        if backend == BACKEND_SQLITE:
            self._open_spill()

    @property
    def spilled(self) -> bool:
        return self._spilled

    @property
    def backend_used(self) -> str:
        return BACKEND_SQLITE if self._conn is not None else BACKEND_MEMORY

    @property
    def memory_size(self) -> int:
        return len(self._memory)

    def add(self, digest: str) -> bool:
        """Return True if ``digest`` is newly seen and should be kept."""
        if self._conn is not None:
            return self._sqlite_add(digest)
        if digest in self._memory:
            return False
        if len(self._memory) >= self._memory_max:
            self._spill_existing()
            return self._sqlite_add(digest)
        self._memory.add(digest)
        return True

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        if self._spill_path is not None:
            try:
                self._spill_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("could not delete dedup spill file %s", self._spill_path)
            self._spill_path = None
        self._memory.clear()

    def _open_spill(self) -> None:
        directory = self._spill_dir if self._spill_dir is not None else Path(tempfile.gettempdir())
        directory.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            prefix="ingest_dedup_",
            suffix=".sqlite",
            dir=str(directory),
            delete=False,
        )
        handle.close()
        self._spill_path = Path(handle.name)
        self._conn = sqlite3.connect(str(self._spill_path))
        self._conn.execute("CREATE TABLE hashes(h TEXT PRIMARY KEY)")
        self._spilled = True

    def _spill_existing(self) -> None:
        logger.warning(
            "dedup hash set exceeded cap %s; spilling to sqlite",
            self._memory_max,
        )
        self._open_spill()
        assert self._conn is not None
        self._conn.executemany(
            "INSERT OR IGNORE INTO hashes(h) VALUES (?)",
            ((digest,) for digest in self._memory),
        )
        self._conn.commit()
        self._memory.clear()

    def _sqlite_add(self, digest: str) -> bool:
        assert self._conn is not None
        cursor = self._conn.execute(
            "INSERT OR IGNORE INTO hashes(h) VALUES (?)",
            (digest,),
        )
        self._conn.commit()
        return cursor.rowcount == 1
