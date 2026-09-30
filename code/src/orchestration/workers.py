"""Entity-level worker dispatch for detector stages (SDD §10).

Workers compute in-memory results. The parent process is the only DuckDB writer.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable, Sequence
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from typing import Any, TypeVar

from src.config import orchestration_settings

logger = logging.getLogger(__name__)

BACKEND_NONE = "none"
BACKEND_THREADS = "threads"
BACKEND_PROCESSES = "processes"
BACKEND_DASK = "dask"

T = TypeVar("T")
R = TypeVar("R")


def resolve_backend(config: dict[str, Any]) -> str:
    """Return a usable backend, falling back if Dask is requested but missing."""
    settings = orchestration_settings(config)
    backend = str(settings["parallel_backend"])
    if backend != BACKEND_DASK:
        return backend
    try:
        import dask  # noqa: F401
    except ImportError:
        fallback = BACKEND_THREADS if sys.platform.startswith("win") else BACKEND_PROCESSES
        logger.warning("dask is not importable; falling back to %s", fallback)
        return fallback
    return BACKEND_DASK


def resolve_worker_count(config: dict[str, Any], n_items: int) -> int:
    """Clamp ``n_workers`` to ``min(configured, cpu_count, n_entities)``, never below 1."""
    settings = orchestration_settings(config)
    configured = int(settings["n_workers"])
    cpu_count = os.cpu_count() or 1
    item_count = max(int(n_items), 1)
    return max(1, min(configured, cpu_count, item_count))


def map_entities(
    func: Callable[[T], R],
    items: Sequence[T],
    *,
    backend: str,
    n_workers: int,
) -> list[R | Exception]:
    """Apply ``func`` to each item; worker exceptions are returned, not raised.

    Results stay in input order. Callers should pass items sorted by ``entity_id``.
    """
    if not items:
        return []
    workers = max(1, int(n_workers))
    if backend == BACKEND_NONE or workers <= 1:
        return [_invoke(func, item) for item in items]
    if backend == BACKEND_THREADS:
        return _map_executor(ThreadPoolExecutor, func, items, workers)
    if backend == BACKEND_PROCESSES:
        return _map_executor(ProcessPoolExecutor, func, items, workers)
    if backend == BACKEND_DASK:
        return _map_dask(func, items, workers)
    raise ValueError(f"unknown parallel backend: {backend!r}")


def _invoke(func: Callable[[T], R], item: T) -> R | Exception:
    try:
        return func(item)
    except Exception as exc:  # noqa: BLE001 — captured for the parent to count
        return exc


def _map_executor(
    executor_cls: type[ThreadPoolExecutor] | type[ProcessPoolExecutor],
    func: Callable[[T], R],
    items: Sequence[T],
    n_workers: int,
) -> list[R | Exception]:
    with executor_cls(max_workers=n_workers) as pool:
        futures = [pool.submit(_invoke, func, item) for item in items]
        return [future.result() for future in futures]


def _map_dask(
    func: Callable[[T], R],
    items: Sequence[T],
    n_workers: int,
) -> list[R | Exception]:
    import dask

    delayed_items = [dask.delayed(_invoke)(func, item) for item in items]
    computed = dask.compute(*delayed_items, num_workers=n_workers, scheduler="threads")
    return list(computed)
