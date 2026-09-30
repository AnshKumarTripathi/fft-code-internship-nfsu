"""Phase 51 spectral flagging policy: modes, thresholds, last-window discount."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.config import ConfigError, load_config, spectral_flagging_settings
from src.detectors.spectral.baseline import compute_baseline
from src.detectors.spectral.windowed import apply_spectral_flag, windowed_deviation
from src.explainability.payload import spectral_crossing_legs
from tests.fixtures.synthetic_entities import generate_periodic_counts

BUCKET_SECONDS = 600
DAILY_PERIOD_BUCKETS = 144  # 24h at 600s
Z_THRESHOLD = 4.0
REPO_CONFIG = Path(__file__).resolve().parents[1] / "config" / "pipeline.yaml"


def _baseline_kwargs() -> dict:
    return {
        "entity_id": "sine",
        "bucket_seconds": BUCKET_SECONDS,
        "baseline_max_nperseg": 1440,
    }


def test_apply_spectral_flag_modes() -> None:
    assert apply_spectral_flag(
        5.0, 1.0, energy_z_threshold=4.0, shape_js_z_threshold=4.0, flag_mode="or"
    )
    assert not apply_spectral_flag(
        5.0, 1.0, energy_z_threshold=4.0, shape_js_z_threshold=4.0, flag_mode="and"
    )
    assert apply_spectral_flag(
        5.0, 5.0, energy_z_threshold=4.0, shape_js_z_threshold=4.0, flag_mode="and"
    )
    assert apply_spectral_flag(
        5.0,
        1.0,
        energy_z_threshold=4.0,
        shape_js_z_threshold=4.0,
        flag_mode="energy_only",
    )
    assert not apply_spectral_flag(
        1.0,
        5.0,
        energy_z_threshold=4.0,
        shape_js_z_threshold=4.0,
        flag_mode="energy_only",
    )
    assert apply_spectral_flag(
        1.0,
        5.0,
        energy_z_threshold=4.0,
        shape_js_z_threshold=4.0,
        flag_mode="shape_only",
    )
    assert not apply_spectral_flag(
        5.0,
        1.0,
        energy_z_threshold=4.0,
        shape_js_z_threshold=4.0,
        flag_mode="shape_only",
    )


def test_separate_thresholds() -> None:
    assert apply_spectral_flag(
        3.5,
        1.0,
        energy_z_threshold=3.0,
        shape_js_z_threshold=4.0,
        flag_mode="energy_only",
    )
    assert not apply_spectral_flag(
        3.5,
        1.0,
        energy_z_threshold=4.0,
        shape_js_z_threshold=4.0,
        flag_mode="energy_only",
    )


def test_crossing_legs_use_per_leg_thresholds() -> None:
    assert spectral_crossing_legs(3.5, 5.0, 4.0, 4.0) == ["shape_js_z"]
    assert spectral_crossing_legs(3.5, 5.0, 3.0, 4.0) == ["energy_z", "shape_js_z"]


def test_repo_yaml_flagging_defaults() -> None:
    config = load_config(REPO_CONFIG)
    settings = spectral_flagging_settings(config)
    assert settings["flag_mode"] == "or"
    assert settings["discount_last_window"] is False
    assert settings["energy_z_threshold"] == 4.0
    assert settings["shape_js_z_threshold"] == 4.0
    assert settings["rule"] == "energy_or_shape"


def test_flag_mode_and_loads(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.yaml"
    path.write_text(
        REPO_CONFIG.read_text(encoding="utf-8").replace(
            "flag_mode: or", "flag_mode: and"
        ),
        encoding="utf-8",
    )
    # ensure keys exist even if replace missed (repo already has flag_mode)
    config = load_config(path)
    config["spectral"]["flag_mode"] = "and"
    settings = spectral_flagging_settings(config)
    assert settings["flag_mode"] == "and"
    assert settings["rule"] == "energy_and_shape"


def test_rejects_unknown_flag_mode(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.yaml"
    text = REPO_CONFIG.read_text(encoding="utf-8")
    text = text.replace("flag_mode: or", "flag_mode: xor")
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="flag_mode"):
        load_config(path)


def test_stationary_sine_interior_quiet_under_or() -> None:
    starts, counts = generate_periodic_counts(
        n_buckets=4000,
        period_buckets=DAILY_PERIOD_BUCKETS,
        bucket_seconds=BUCKET_SECONDS,
    )
    baseline = compute_baseline(counts, **_baseline_kwargs())
    assert baseline is not None
    rows = windowed_deviation(
        counts,
        starts,
        baseline,
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=DAILY_PERIOD_BUCKETS * 3,
        step_buckets=DAILY_PERIOD_BUCKETS,
        z_threshold=Z_THRESHOLD,
        flag_mode="or",
    )
    assert len(rows) > 2
    assert all(not row.flagged for row in rows[:-1])


def test_discount_last_window_clears_remainder_flag() -> None:
    starts, counts = generate_periodic_counts(
        n_buckets=4000,
        period_buckets=DAILY_PERIOD_BUCKETS,
        bucket_seconds=BUCKET_SECONDS,
    )
    baseline = compute_baseline(counts, **_baseline_kwargs())
    assert baseline is not None
    kwargs = dict(
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=DAILY_PERIOD_BUCKETS * 3,
        step_buckets=DAILY_PERIOD_BUCKETS,
        z_threshold=Z_THRESHOLD,
        flag_mode="or",
    )
    without = windowed_deviation(counts, starts, baseline, **kwargs)
    with_discount = windowed_deviation(
        counts, starts, baseline, discount_last_window=True, **kwargs
    )
    assert len(without) == len(with_discount) > 2
    assert with_discount[-1].flagged is False
    # Interior policy unchanged
    assert [row.flagged for row in without[:-1]] == [
        row.flagged for row in with_discount[:-1]
    ]


def test_and_mode_stricter_than_or_on_attack_injection() -> None:
    from tests.fixtures.synthetic_entities import inject_rhythm_attack

    starts, counts = generate_periodic_counts(
        n_buckets=4000,
        period_buckets=DAILY_PERIOD_BUCKETS,
        bucket_seconds=BUCKET_SECONDS,
    )
    counts = inject_rhythm_attack(
        counts,
        start=3000,
        length=288,
        new_period_buckets=24,
    )
    baseline = compute_baseline(counts, **_baseline_kwargs())
    assert baseline is not None
    shared = dict(
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=DAILY_PERIOD_BUCKETS * 3,
        step_buckets=DAILY_PERIOD_BUCKETS,
        z_threshold=Z_THRESHOLD,
    )
    or_rows = windowed_deviation(counts, starts, baseline, flag_mode="or", **shared)
    and_rows = windowed_deviation(counts, starts, baseline, flag_mode="and", **shared)
    assert sum(1 for row in or_rows if row.flagged) >= sum(
        1 for row in and_rows if row.flagged
    )
