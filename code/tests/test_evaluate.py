"""Tests for Phase 15 evaluation: labels, metrics, persist, cold-start, CLI."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from src.db.connection import get_connection
from src.detectors.statistical.rate_checks import MIN_WINDOWS, score_rate_windows
from src.evaluation.cold_start import HISTORY_HOURS, measure_spectral_cold_start
from src.evaluation.labels import EvaluationError, LabelRow, load_labels
from src.evaluation.metrics import Detection, intervals_overlap, score_detections
from src.evaluation.persist import run_evaluate
from src.pipeline import STAGE_ORDER, main

UTC = timezone.utc
FIXTURE_LABELS = (
    Path(__file__).resolve().parent / "fixtures" / "labels" / "synthetic_eval.csv"
)
BASE = datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC)


def _naive_utc(ts: datetime) -> datetime:
    """DuckDB TIMESTAMP is timezone-naive; aware UTC values become local on insert."""
    return ts.astimezone(UTC).replace(tzinfo=None)


def _config(tmp_path: Path, labels_path: str | None = None) -> dict:
    data = tmp_path / "data"
    return {
        "paths": {
            "raw_log_dir": str(data / "raw"),
            "parsed_dir": str(data / "parsed"),
            "timeseries_dir": str(data / "timeseries"),
            "baseline_dir": str(data / "baselines"),
            "scores_dir": str(data / "scores"),
            "report_dir": str(data / "reports"),
            "db_path": str(data / "warehouse.duckdb"),
        },
        "bucketing": {"bucket_seconds": 600},
        "statistical": {"window_buckets": 6, "z_threshold": 4.0},
        "spectral": {
            "window_hours": 72,
            "step_fraction": 0.333,
            "baseline_max_nperseg": 1440,
            "z_threshold": 4.0,
            "cluster_eps": 1.2,
            "cluster_min_samples": 2,
        },
        "ml": {
            "model_type": "isolation_forest",
            "onnx_model_path": None,
            "contamination": 0.02,
        },
        "correlation": {
            "session_gap_minutes": 30,
            "same_ip_link": True,
            "same_host_link": True,
        },
        "reporting": {
            "template_path": "src/reporting/templates/incident_report.md.j2",
            "use_llm_narrative": False,
            "llm_model": "qwen3-coder:30b",
        },
        "orchestration": {"parallel_backend": "none", "n_workers": 1},
        "evaluation": {
            "labels_path": labels_path,
            "output_dir": str(tmp_path / "eval_out"),
            "overlap_rule": "any",
            "write_entity_labels": True,
        },
    }


def _seed_entity(connection, entity_id: str) -> None:
    ts = _naive_utc(datetime(2024, 1, 1, tzinfo=UTC))
    connection.execute(
        """
        INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
        VALUES (?, 'user', ?, ?, NULL)
        ON CONFLICT (entity_id) DO NOTHING
        """,
        [entity_id, ts, ts],
    )


def test_evaluate_not_in_run_all_order() -> None:
    assert "evaluate" not in STAGE_ORDER


def test_load_labels_csv_fixture() -> None:
    rows = load_labels(FIXTURE_LABELS)
    assert len(rows) == 3
    alice_attack = next(
        row for row in rows if row.entity_id == "alice" and row.label == "attacker"
    )
    assert alice_attack.window_start == datetime(2024, 1, 1, 10, 0, tzinfo=UTC)
    assert alice_attack.window_end == datetime(2024, 1, 1, 11, 0, tzinfo=UTC)
    assert alice_attack.attack_type == "bruteforce"
    bob = next(row for row in rows if row.entity_id == "bob")
    assert bob.label == "benign"
    assert bob.window_start is None
    assert bob.window_end is None


def test_load_labels_parquet(tmp_path: Path) -> None:
    path = tmp_path / "labels.parquet"
    pd.DataFrame(
        [
            {
                "entity_id": "alice",
                "window_start": "2024-01-01T10:00:00Z",
                "window_end": "2024-01-01T11:00:00Z",
                "label": "attacker",
                "attack_type": "rhythm",
            }
        ]
    ).to_parquet(path, index=False)
    rows = load_labels(path)
    assert len(rows) == 1
    assert rows[0].entity_id == "alice"
    assert rows[0].label == "attacker"
    assert rows[0].attack_type == "rhythm"


def test_load_labels_rejects_bad_label(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text(
        "entity_id,label\nalice,suspicious\n",
        encoding="utf-8",
    )
    with pytest.raises(EvaluationError, match="benign"):
        load_labels(path)


def test_load_labels_rejects_one_sided_window(tmp_path: Path) -> None:
    path = tmp_path / "onesided.csv"
    path.write_text(
        "entity_id,window_start,window_end,label\n"
        "alice,2024-01-01T10:00:00Z,,attacker\n",
        encoding="utf-8",
    )
    with pytest.raises(EvaluationError, match="both be set"):
        load_labels(path)


def test_load_labels_missing_file(tmp_path: Path) -> None:
    with pytest.raises(EvaluationError, match="not found"):
        load_labels(tmp_path / "missing.csv")


def test_intervals_overlap_any() -> None:
    a0 = datetime(2024, 1, 1, 10, 0, tzinfo=UTC)
    a1 = datetime(2024, 1, 1, 11, 0, tzinfo=UTC)
    b0 = datetime(2024, 1, 1, 10, 30, tzinfo=UTC)
    b1 = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
    assert intervals_overlap(a0, a1, b0, b1)
    assert not intervals_overlap(
        a0, a1, datetime(2024, 1, 1, 12, 0, tzinfo=UTC), datetime(2024, 1, 1, 13, 0, tzinfo=UTC)
    )


def test_metrics_attacker_tp_and_miss_fn() -> None:
    labels = [
        LabelRow(
            entity_id="alice",
            label="attacker",
            window_start=BASE,
            window_end=BASE + timedelta(hours=1),
            attack_type="bruteforce",
        ),
        LabelRow(
            entity_id="eve",
            label="attacker",
            window_start=BASE,
            window_end=BASE + timedelta(hours=1),
            attack_type=None,
        ),
    ]
    detections = [
        Detection("alice", BASE + timedelta(minutes=10), BASE + timedelta(minutes=20)),
    ]
    metrics = score_detections(labels, detections)
    assert metrics.tp == 1
    assert metrics.fn == 1
    assert metrics.fp == 0
    assert metrics.recall == 0.5
    assert metrics.entity_recall == 0.5


def test_metrics_benign_flag_is_fp() -> None:
    labels = [
        LabelRow("bob", "benign", None, None, None),
    ]
    detections = [Detection("bob", BASE, BASE + timedelta(hours=1))]
    metrics = score_detections(labels, detections)
    assert metrics.fp == 1
    assert metrics.tp == 0
    assert metrics.precision == 0.0


def test_metrics_unlabeled_flags_ignored() -> None:
    labels = [
        LabelRow(
            "alice",
            "attacker",
            BASE,
            BASE + timedelta(hours=1),
            None,
        ),
    ]
    detections = [
        Detection("alice", BASE, BASE + timedelta(minutes=30)),
        Detection("noisy", BASE, BASE + timedelta(hours=1)),
    ]
    metrics = score_detections(labels, detections)
    assert metrics.tp == 1
    assert metrics.fp == 0
    assert metrics.precision == 1.0


def test_metrics_null_when_denominators_empty() -> None:
    metrics = score_detections([], [])
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.entity_recall is None


def test_metrics_attacker_overlap_not_also_fp() -> None:
    labels = [
        LabelRow("alice", "attacker", BASE, BASE + timedelta(hours=1), None),
        LabelRow(
            "alice",
            "benign",
            BASE - timedelta(hours=10),
            BASE - timedelta(hours=9),
            None,
        ),
    ]
    detections = [Detection("alice", BASE, BASE + timedelta(minutes=30))]
    metrics = score_detections(labels, detections)
    assert metrics.tp == 1
    assert metrics.fp == 0


def test_missing_labels_path_raises(tmp_path: Path) -> None:
    config = _config(tmp_path, labels_path=None)
    with pytest.raises(EvaluationError, match="labels_path"):
        run_evaluate(config)


def test_run_evaluate_seeded_warehouse(tmp_path: Path) -> None:
    config = _config(tmp_path, labels_path=str(FIXTURE_LABELS))
    connection = get_connection(config)
    try:
        for entity_id in ("alice", "bob", "charlie"):
            _seed_entity(connection, entity_id)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
                (entity_id, window_start, window_end, rate_z, flagged)
            VALUES
                ('alice', ?, ?, 6.0, TRUE),
                ('charlie', ?, ?, 5.0, TRUE)
            """,
            [
                _naive_utc(BASE),
                _naive_utc(BASE + timedelta(hours=1)),
                _naive_utc(BASE),
                _naive_utc(BASE + timedelta(hours=1)),
            ],
        )
    finally:
        connection.close()

    summary = run_evaluate(config)
    payload = json.loads(Path(summary.metrics_json_path).read_text(encoding="utf-8"))
    assert payload["overlap_rule"] == "any"
    assert "statistical" in payload["detectors"]
    stats = payload["detectors"]["statistical"]
    assert stats["tp"] == 1
    assert stats["fp"] == 0
    assert stats["fn"] == 0
    assert "precision" in stats
    assert "recall" in stats
    assert Path(summary.metrics_md_path).read_text(encoding="utf-8")

    connection = get_connection(config)
    try:
        labels = {
            row[0]: row[1]
            for row in connection.execute(
                "SELECT entity_id, label FROM entities WHERE label IS NOT NULL"
            ).fetchall()
        }
        assert labels["alice"] == "attacker"
        assert labels["bob"] == "benign"
        assert "charlie" not in labels
        run_row = connection.execute(
            """
            SELECT status FROM pipeline_runs
            WHERE stage = 'evaluate'
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()
        assert run_row[0] == "success"
    finally:
        connection.close()


def test_missing_spectral_table_omits_key(tmp_path: Path) -> None:
    config = _config(tmp_path, labels_path=str(FIXTURE_LABELS))
    connection = get_connection(config)
    try:
        _seed_entity(connection, "alice")
        connection.execute(
            """
            INSERT INTO statistical_window_scores
                (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 6.0, TRUE)
            """,
            [_naive_utc(BASE), _naive_utc(BASE + timedelta(hours=1))],
        )
    finally:
        connection.close()

    summary = run_evaluate(config)
    payload = json.loads(Path(summary.metrics_json_path).read_text(encoding="utf-8"))
    assert "spectral" not in payload["detectors"]
    assert "ml" not in payload["detectors"]
    assert "statistical" in payload["detectors"]


def test_unflagged_rows_still_emit_detector_key(tmp_path: Path) -> None:
    config = _config(tmp_path, labels_path=str(FIXTURE_LABELS))
    connection = get_connection(config)
    try:
        _seed_entity(connection, "alice")
        connection.execute(
            """
            INSERT INTO statistical_window_scores
                (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 0.5, FALSE)
            """,
            [_naive_utc(BASE), _naive_utc(BASE + timedelta(hours=1))],
        )
    finally:
        connection.close()

    summary = run_evaluate(config)
    payload = json.loads(Path(summary.metrics_json_path).read_text(encoding="utf-8"))
    stats = payload["detectors"]["statistical"]
    assert stats["tp"] == 0
    assert stats["fn"] == 1
    assert stats["precision"] is None
    assert stats["recall"] == 0.0


def test_live_statistical_burst_tp_quiet_benign_not_fp(tmp_path: Path) -> None:
    window_buckets = 6
    z_threshold = 4.0
    bucket_seconds = 600
    n = MIN_WINDOWS + window_buckets + 10
    starts = [BASE + timedelta(seconds=bucket_seconds * i) for i in range(n)]
    alice_counts = [1.0 + (i % 5) for i in range(n)]
    spike = n // 2
    alice_counts[spike] = 500.0
    alice_rows = score_rate_windows(
        starts,
        alice_counts,
        bucket_seconds,
        entity_id="alice",
        window_buckets=window_buckets,
        z_threshold=z_threshold,
    )
    flagged_alice = [row for row in alice_rows if row.flagged]
    assert flagged_alice

    bob_rows = score_rate_windows(
        starts,
        [2.0] * n,
        bucket_seconds,
        entity_id="bob",
        window_buckets=window_buckets,
        z_threshold=z_threshold,
    )
    assert all(not row.flagged for row in bob_rows)

    labels_path = tmp_path / "live_labels.csv"
    attack_start = min(row.window_start for row in flagged_alice)
    attack_end = max(row.window_end for row in flagged_alice)
    labels_path.write_text(
        "entity_id,window_start,window_end,label,attack_type\n"
        f"alice,{attack_start.isoformat()},{attack_end.isoformat()},attacker,bruteforce\n"
        "bob,,,benign,\n",
        encoding="utf-8",
    )

    config = _config(tmp_path, labels_path=str(labels_path))
    connection = get_connection(config)
    try:
        _seed_entity(connection, "alice")
        _seed_entity(connection, "bob")
        _seed_entity(connection, "charlie")
        for row in alice_rows + bob_rows:
            connection.execute(
                """
                INSERT INTO statistical_window_scores
                    (entity_id, window_start, window_end, rate_z, flagged)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    row.entity_id,
                    _naive_utc(row.window_start),
                    _naive_utc(row.window_end),
                    row.rate_z,
                    row.flagged,
                ],
            )
        connection.execute(
            """
            INSERT INTO statistical_window_scores
                (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('charlie', ?, ?, 9.0, TRUE)
            """,
            [_naive_utc(BASE), _naive_utc(BASE + timedelta(hours=1))],
        )
    finally:
        connection.close()

    summary = run_evaluate(config)
    payload = json.loads(Path(summary.metrics_json_path).read_text(encoding="utf-8"))
    stats = payload["detectors"]["statistical"]
    assert stats["tp"] >= 1
    assert stats["fp"] == 0
    assert stats["fn"] == 0


def test_missing_labels_cli_exit_nonzero(tmp_path: Path) -> None:
    yaml_path = tmp_path / "pipeline.yaml"
    yaml_path.write_text(
        "\n".join(
            [
                "paths:",
                "  raw_log_dir: data/raw/",
                "  parsed_dir: data/parsed/",
                "  timeseries_dir: data/timeseries/",
                "  baseline_dir: data/baselines/",
                "  scores_dir: data/scores/",
                "  report_dir: data/reports/",
                f"  db_path: {(tmp_path / 'warehouse.duckdb').as_posix()}",
                "bucketing:",
                "  bucket_seconds: 600",
                "statistical:",
                "  window_buckets: 6",
                "  z_threshold: 4.0",
                "spectral:",
                "  window_hours: 72",
                "  step_fraction: 0.333",
                "  baseline_max_nperseg: 1440",
                "  z_threshold: 4.0",
                "  cluster_eps: 1.2",
                "  cluster_min_samples: 2",
                "ml:",
                "  model_type: isolation_forest",
                "  onnx_model_path: null",
                "  contamination: 0.02",
                "correlation:",
                "  session_gap_minutes: 30",
                "  same_ip_link: true",
                "  same_host_link: true",
                "reporting:",
                "  template_path: src/reporting/templates/incident_report.md.j2",
                "  use_llm_narrative: false",
                "  llm_model: qwen3-coder:30b",
                "orchestration:",
                "  parallel_backend: none",
                "  n_workers: 1",
                "evaluation:",
                "  labels_path: null",
                f"  output_dir: {(tmp_path / 'eval_out').as_posix()}",
                "  overlap_rule: any",
                "  write_entity_labels: true",
                "",
            ]
        ),
        encoding="utf-8",
    )
    assert main(["evaluate", "--config", str(yaml_path)]) == 1


def test_cold_start_returns_four_prefixes() -> None:
    rows = measure_spectral_cold_start()
    assert [row.history_hours for row in rows] == list(HISTORY_HOURS)
    by_hours = {row.history_hours: row.flagged_attack_window for row in rows}
    # 1d of 10-minute buckets is shorter than the default 72h spectral window.
    assert by_hours[24] is False


def test_cold_start_appended_to_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from src.evaluation.cold_start import ColdStartRow

    monkeypatch.setattr(
        "src.evaluation.cold_start.measure_spectral_cold_start",
        lambda **_kwargs: [
            ColdStartRow(history_hours=24, flagged_attack_window=False),
            ColdStartRow(history_hours=336, flagged_attack_window=True),
        ],
    )
    config = _config(tmp_path, labels_path=str(FIXTURE_LABELS))
    connection = get_connection(config)
    try:
        _seed_entity(connection, "alice")
        connection.execute(
            """
            INSERT INTO statistical_window_scores
                (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 6.0, TRUE)
            """,
            [_naive_utc(BASE), _naive_utc(BASE + timedelta(hours=1))],
        )
    finally:
        connection.close()

    summary = run_evaluate(config, cold_start_synthetic=True)
    payload = json.loads(Path(summary.metrics_json_path).read_text(encoding="utf-8"))
    assert payload["cold_start"][0]["history_hours"] == 24
    markdown = Path(summary.metrics_md_path).read_text(encoding="utf-8")
    assert "history_hours" in markdown
    assert summary.cold_start_rows == 2
