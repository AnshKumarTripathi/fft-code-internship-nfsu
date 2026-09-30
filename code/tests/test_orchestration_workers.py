"""Unit tests for entity worker dispatch (no DuckDB)."""

from __future__ import annotations

from src.orchestration.workers import (
    map_entities,
    resolve_backend,
    resolve_worker_count,
)


def _square(value: int) -> int:
    return value * value


def _boom(value: int) -> int:
    if value == 3:
        raise RuntimeError(f"bad entity {value}")
    return value


def test_map_entities_threads_calls_every_item() -> None:
    items = [1, 2, 3, 4]
    results = map_entities(_square, items, backend="threads", n_workers=2)
    assert results == [1, 4, 9, 16]


def test_map_entities_none_is_serial() -> None:
    results = map_entities(_square, [2, 5], backend="none", n_workers=8)
    assert results == [4, 25]


def test_worker_count_clamped_to_entity_count() -> None:
    config = {"orchestration": {"parallel_backend": "threads", "n_workers": 8}}
    assert resolve_worker_count(config, n_items=1) == 1
    assert resolve_worker_count(config, n_items=2) <= 2


def test_n_workers_two_four_entities_uses_parallel_backend() -> None:
    config = {"orchestration": {"parallel_backend": "threads", "n_workers": 2}}
    backend = resolve_backend(config)
    assert backend != "none"
    n_workers = resolve_worker_count(config, n_items=4)
    assert n_workers == 2
    results = map_entities(_square, [10, 20, 30, 40], backend=backend, n_workers=n_workers)
    assert results == [100, 400, 900, 1600]


def test_one_worker_exception_is_returned() -> None:
    results = map_entities(_boom, [1, 3, 5], backend="threads", n_workers=2)
    assert results[0] == 1
    assert isinstance(results[1], RuntimeError)
    assert "bad entity 3" in str(results[1])
    assert results[2] == 5
