"""Exclusive writer lock for the DuckDB warehouse (R6).

DuckDB itself refuses a second writer, but the error is an I/O lock message.
This advisory lock fails immediately with a clear ``WarehouseBusyError`` so two
``run-all`` processes cannot start a second writer by accident.

Same-process nested ``get_connection`` calls share the lock (refcount) so a
stage can open the warehouse without deadlocking itself.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

_HELD: dict[str, WriterLock] = {}


class WarehouseBusyError(Exception):
    """Raised when another process already holds the warehouse writer lock."""


def writer_lock_path(db_path: str | Path) -> Path:
    return Path(str(db_path) + ".writer.lock")


class WriterLock:
    """Non-blocking exclusive lock on a sidecar file next to the warehouse."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._handle: TextIO | None = None
        self._depth = 0
        self._key = ""
        self._owner: WriterLock | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        key = str(self.path.resolve())
        self._key = key
        held = _HELD.get(key)
        if held is not None:
            held._depth += 1
            self._owner = held
            return
        handle = open(self.path, "a+", encoding="utf-8")
        if handle.tell() == 0:
            handle.write("\n")
            handle.flush()
        try:
            _lock_exclusive_nb(handle)
        except OSError as exc:
            holder = _read_holder(handle)
            handle.close()
            raise WarehouseBusyError(_busy_message(self.path, holder)) from exc
        self._handle = handle
        self._depth = 1
        self._owner = self
        _HELD[key] = self
        _write_holder(handle)

    def release(self) -> None:
        owner = self._owner
        self._owner = None
        if owner is None:
            return
        owner._depth -= 1
        if owner._depth > 0:
            return
        _HELD.pop(owner._key, None)
        owner._unlock_os()

    def _unlock_os(self) -> None:
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            _unlock(handle)
        finally:
            handle.close()

    def __enter__(self) -> WriterLock:
        self.acquire()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.release()


def _lock_exclusive_nb(handle: TextIO) -> None:
    handle.seek(0)
    if sys.platform == "win32":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(handle: TextIO) -> None:
    handle.seek(0)
    if sys.platform == "win32":
        import msvcrt

        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            return
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _write_holder(handle: TextIO) -> None:
    payload = {
        "pid": os.getpid(),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    handle.seek(0)
    handle.truncate()
    handle.write(json.dumps(payload))
    handle.write("\n")
    handle.flush()


def _read_holder(handle: TextIO) -> dict[str, Any] | None:
    try:
        handle.seek(0)
        text = handle.read().strip()
    except OSError:
        return None
    if not text:
        return None
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _busy_message(path: Path, holder: dict[str, Any] | None) -> str:
    base = (
        f"Warehouse is locked by another writer ({path}). "
        "Wait for the running pipeline stage to finish; only one process may write."
    )
    if not holder:
        return base
    pid = holder.get("pid")
    started = holder.get("started_at")
    extra = []
    if pid is not None:
        extra.append(f"pid={pid}")
    if started:
        extra.append(f"since={started}")
    if extra:
        return f"{base} Holder: {', '.join(extra)}."
    return base
