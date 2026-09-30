"""Spectral cold-start measurement on a synthetic rhythm-attack series (SDD §12.3)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import timedelta

from src.detectors.spectral.baseline import compute_baseline
from src.detectors.spectral.windowed import windowed_deviation
from src.evaluation.metrics import intervals_overlap
from tests.fixtures.synthetic_entities import (
    generate_periodic_counts,
    inject_rhythm_attack,
)

HISTORY_HOURS: tuple[int, ...] = (24, 72, 168, 336)
DEFAULT_BUCKET_SECONDS = 600
DEFAULT_WINDOW_HOURS = 72.0
DEFAULT_STEP_FRACTION = 0.333
DEFAULT_Z_THRESHOLD = 4.0
DEFAULT_BASELINE_MAX_NPERSEG = 1440


@dataclass(frozen=True)
class ColdStartRow:
    history_hours: int
    flagged_attack_window: bool

    def as_dict(self) -> dict[str, int | bool]:
        return asdict(self)


def measure_spectral_cold_start(
    *,
    bucket_seconds: int = DEFAULT_BUCKET_SECONDS,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    window_hours: float = DEFAULT_WINDOW_HOURS,
    step_fraction: float = DEFAULT_STEP_FRACTION,
    baseline_max_nperseg: int = DEFAULT_BASELINE_MAX_NPERSEG,
) -> list[ColdStartRow]:
    """Score prefixes of 1d/3d/7d/14d; record whether the injected rhythm is flagged.

    Short prefixes may fail to flag — that is the measurement, not a test failure.
    """
    period_buckets = max(1, (24 * 3600) // bucket_seconds)
    window_buckets = max(1, round(window_hours * 3600 / bucket_seconds))
    step_buckets = max(1, round(window_buckets * step_fraction))
    rows: list[ColdStartRow] = []
    for history_hours in HISTORY_HOURS:
        n_buckets = max(1, round(history_hours * 3600 / bucket_seconds))
        starts, counts = generate_periodic_counts(
            n_buckets=n_buckets,
            period_buckets=period_buckets,
            bucket_seconds=bucket_seconds,
        )
        attack_start = n_buckets // 2
        attack_length = max(1, n_buckets - attack_start)
        attacked = inject_rhythm_attack(
            counts,
            start=attack_start,
            length=attack_length,
            new_period_buckets=max(4, period_buckets // 6),
        )
        flagged_attack = False
        if n_buckets >= window_buckets:
            baseline = compute_baseline(
                attacked,
                entity_id="synthetic_rhythm",
                bucket_seconds=bucket_seconds,
                baseline_max_nperseg=baseline_max_nperseg,
            )
            if baseline is not None:
                scores = windowed_deviation(
                    attacked,
                    starts,
                    baseline,
                    bucket_seconds=bucket_seconds,
                    window_buckets=window_buckets,
                    step_buckets=step_buckets,
                    z_threshold=z_threshold,
                )
                attack_window_start = starts[attack_start]
                attack_end_index = min(n_buckets - 1, attack_start + attack_length - 1)
                attack_window_end = starts[attack_end_index] + timedelta(
                    seconds=bucket_seconds
                )
                flagged_attack = any(
                    row.flagged
                    and intervals_overlap(
                        row.window_start,
                        row.window_end,
                        attack_window_start,
                        attack_window_end,
                    )
                    for row in scores
                )
        rows.append(
            ColdStartRow(
                history_hours=history_hours,
                flagged_attack_window=flagged_attack,
            )
        )
    return rows
