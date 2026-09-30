"""Unit tests for robust_z_scores."""

from __future__ import annotations

from src.detectors.robust_z import robust_z_scores


def test_single_value_returns_zero() -> None:
    assert robust_z_scores([42.0]) == [0.0]


def test_empty_returns_empty() -> None:
    assert robust_z_scores([]) == []


def test_mad_zero_flat_series() -> None:
    assert robust_z_scores([5.0, 5.0, 5.0, 5.0]) == [0.0, 0.0, 0.0, 0.0]


def test_spike_has_highest_z() -> None:
    values = [2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 50.0]
    z_scores = robust_z_scores(values)
    spike_index = values.index(50.0)
    assert z_scores[spike_index] == max(z_scores)
    assert z_scores[spike_index] > 0.0


def test_normal_spread_ordering() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    z_scores = robust_z_scores(values)
    assert z_scores[2] == 0.0  # median element
    assert z_scores[-1] > z_scores[0]
