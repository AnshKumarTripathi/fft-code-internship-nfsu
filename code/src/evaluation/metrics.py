"""Window-overlap precision/recall for labeled detections (no DuckDB)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Literal, Sequence

from src.evaluation.labels import LabelRow

OverlapRule = Literal["any", "iou_0_1"]
IOU_THRESHOLD = 0.1


@dataclass(frozen=True)
class Detection:
    entity_id: str
    window_start: datetime
    window_end: datetime


@dataclass(frozen=True)
class DetectorMetrics:
    tp: int
    fp: int
    fn: int
    precision: float | None
    recall: float | None
    entity_recall: float | None

    def as_dict(self) -> dict[str, int | float | None]:
        return asdict(self)


def intervals_overlap(
    a_start: datetime,
    a_end: datetime,
    b_start: datetime,
    b_end: datetime,
) -> bool:
    """True if intervals share any time (inclusive endpoints)."""
    return _ensure_utc(a_start) <= _ensure_utc(b_end) and _ensure_utc(
        b_start
    ) <= _ensure_utc(a_end)


def interval_iou(
    a_start: datetime,
    a_end: datetime,
    b_start: datetime,
    b_end: datetime,
) -> float:
    """Intersection-over-union of two closed time intervals in [0, 1]."""
    a0 = _ensure_utc(a_start)
    a1 = _ensure_utc(a_end)
    b0 = _ensure_utc(b_start)
    b1 = _ensure_utc(b_end)
    if a1 < a0 or b1 < b0:
        return 0.0
    latest_start = max(a0, b0)
    earliest_end = min(a1, b1)
    if earliest_end < latest_start:
        return 0.0
    intersection = (earliest_end - latest_start).total_seconds()
    a_len = (a1 - a0).total_seconds()
    b_len = (b1 - b0).total_seconds()
    union = a_len + b_len - intersection
    if union <= 0:
        return 0.0
    return intersection / union


def windows_match(
    a_start: datetime,
    a_end: datetime,
    b_start: datetime,
    b_end: datetime,
    *,
    overlap_rule: OverlapRule = "any",
) -> bool:
    """True when two windows count as a hit under ``overlap_rule``."""
    if overlap_rule == "any":
        return intervals_overlap(a_start, a_end, b_start, b_end)
    if overlap_rule == "iou_0_1":
        return interval_iou(a_start, a_end, b_start, b_end) >= IOU_THRESHOLD
    raise ValueError(f"unknown overlap_rule: {overlap_rule!r}")


def score_detections(
    labels: Sequence[LabelRow],
    detections: Sequence[Detection],
    *,
    overlap_rule: OverlapRule = "any",
) -> DetectorMetrics:
    """Score flagged windows against labels.

    Unlabeled entities are ignored. Only ``benign`` rows are precision negatives.
    A detection that overlaps an attacker window is not also counted as FP.
    Entity-level labels (no window) still match any detection on that entity.
    """
    attacker_labels = [row for row in labels if row.label == "attacker"]
    benign_labels = [row for row in labels if row.label == "benign"]
    labeled_ids = {row.entity_id for row in labels}

    detections_by_entity: dict[str, list[Detection]] = {}
    for detection in detections:
        detections_by_entity.setdefault(detection.entity_id, []).append(detection)

    tp = 0
    fn = 0
    attacker_entities = {row.entity_id for row in attacker_labels}
    attacker_entities_with_tp: set[str] = set()

    for label in attacker_labels:
        entity_detections = detections_by_entity.get(label.entity_id, [])
        if _label_hits(label, entity_detections, overlap_rule=overlap_rule):
            tp += 1
            attacker_entities_with_tp.add(label.entity_id)
        else:
            fn += 1

    entity_level_benign = {
        row.entity_id
        for row in benign_labels
        if row.window_start is None and row.window_end is None
    }
    window_benign = [
        row
        for row in benign_labels
        if row.window_start is not None and row.window_end is not None
    ]

    fp = 0
    for detection in detections:
        if detection.entity_id not in labeled_ids:
            continue
        if _detection_matches_attacker(
            detection, attacker_labels, overlap_rule=overlap_rule
        ):
            continue
        if detection.entity_id in entity_level_benign:
            fp += 1
            continue
        if any(
            row.entity_id == detection.entity_id
            and row.window_start is not None
            and row.window_end is not None
            and windows_match(
                detection.window_start,
                detection.window_end,
                row.window_start,
                row.window_end,
                overlap_rule=overlap_rule,
            )
            for row in window_benign
        ):
            fp += 1

    precision = (tp / (tp + fp)) if (tp + fp) else None
    recall = (tp / (tp + fn)) if (tp + fn) else None
    entity_recall = (
        (len(attacker_entities_with_tp) / len(attacker_entities))
        if attacker_entities
        else None
    )
    return DetectorMetrics(
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        entity_recall=entity_recall,
    )


def _label_hits(
    label: LabelRow,
    detections: Sequence[Detection],
    *,
    overlap_rule: OverlapRule,
) -> bool:
    if not detections:
        return False
    if label.window_start is None and label.window_end is None:
        return True
    assert label.window_start is not None and label.window_end is not None
    return any(
        windows_match(
            label.window_start,
            label.window_end,
            detection.window_start,
            detection.window_end,
            overlap_rule=overlap_rule,
        )
        for detection in detections
    )


def _detection_matches_attacker(
    detection: Detection,
    attacker_labels: Sequence[LabelRow],
    *,
    overlap_rule: OverlapRule,
) -> bool:
    for label in attacker_labels:
        if label.entity_id != detection.entity_id:
            continue
        if label.window_start is None and label.window_end is None:
            return True
        assert label.window_start is not None and label.window_end is not None
        if windows_match(
            label.window_start,
            label.window_end,
            detection.window_start,
            detection.window_end,
            overlap_rule=overlap_rule,
        ):
            return True
    return False


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)
