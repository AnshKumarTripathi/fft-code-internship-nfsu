"""Tests for config loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.config import (
    ConfigError,
    changepoint_settings,
    dashboard_settings,
    ensure_data_directories,
    evaluation_settings,
    explainability_settings,
    ingestion_settings,
    load_config,
    ml_settings,
    parse_settings,
    spectral_max_buckets_per_entity,
    spectral_settings,
    ui_honesty_settings,
)

REPO_CONFIG = Path(__file__).resolve().parents[1] / "config" / "pipeline.yaml"


def test_load_repo_pipeline_yaml() -> None:
    config = load_config(REPO_CONFIG)
    assert "paths" in config
    assert config["paths"]["db_path"] == "data/warehouse.duckdb"
    assert config["bucketing"]["bucket_seconds"] == 600
    assert config["statistical"]["z_threshold"] == 4.0
    assert config["spectral"]["window_hours"] == 72
    assert config["spectral"]["z_threshold"] == 4.0
    assert config["ingestion"]["syslog_year_policy"] == "carry"
    assert config["ingestion"]["dedup_backend"] == "memory"
    settings = ingestion_settings(config)
    assert settings["dedup_memory_max_hashes"] == 2000000
    assert settings["enabled_sources"] == []
    assert settings["evidence_line_hash"] is False
    assert settings["max_line_bytes"] == 1048576
    assert config["orchestration"]["parallel_backend"] == "threads"
    assert config["orchestration"]["n_workers"] == 8
    settings = ml_settings(config)
    assert settings["flagging"] == "mad_threshold"
    assert settings["mad_k"] == 4.0
    assert settings["min_windows_to_fit"] == 20
    assert settings["score_threshold"] is None
    assert settings["mode"] == "refit_and_snapshot"
    assert settings["snapshot_id"] is None
    assert settings["ensemble"]["enabled"] is False
    assert settings["ensemble"]["fusion"] == "majority"
    parse = parse_settings(config)
    assert parse["mode"] == "train_and_snapshot"
    assert parse["start_empty"] is False
    assert parse["snapshot_id"] is None
    assert config["spectral"]["cluster_min_entities"] == 20
    assert config["spectral"]["window"] == "hann"
    assert config["spectral"]["min_welch_length"] == 4
    fft = spectral_settings(config)
    assert fft["window"] == "hann"
    assert fft["min_welch_length"] == 4
    assert spectral_max_buckets_per_entity(config) == 100000
    settings = evaluation_settings(config)
    assert settings["labels_path"] is None
    assert settings["output_dir"] == "data/reports/eval/"
    assert settings["overlap_rule"] == "any"
    assert settings["write_entity_labels"] is True
    settings = dashboard_settings(config)
    assert settings["default_incident_limit"] == 50
    assert settings["max_incident_limit"] == 500
    assert settings["incident_chart_pad_hours"] == 6
    assert settings["serve_vendor_locally"] is True
    assert settings["serve_legacy_html"] is False
    assert settings["operator_label"] == "local"
    assert "http://127.0.0.1:3000" in settings["cors_origins"]
    assert "http://localhost:3000" in settings["cors_origins"]
    expl = explainability_settings(config)
    assert expl["playbooks_path"] == "config/playbooks.yaml"
    assert expl["log_source_limit"] == 8
    assert expl["ml_top_templates"] == 5
    assert expl["spectral_top_js_bins"] == 3
    assert expl["gap_zero_fraction"] == 0.5
    assert expl["warn_band"] == 0.5
    honesty = ui_honesty_settings(config)
    assert honesty["warn_band"] == 0.5
    assert honesty["statistical_z_threshold"] == 4.0
    assert honesty["spectral_z_threshold"] == 4.0
    assert honesty["ml_mad_k"] == 4.0
    assert honesty["operator_label"] == "local"
    cp = changepoint_settings(config)
    assert cp["min_history_buckets"] == 48
    assert cp["baseline_buckets"] == 48
    assert cp["drift_k"] == 0.5
    assert cp["decision_h"] == 5.0
    assert config["changepoint"]["decision_h"] == 5.0


def test_load_config_rejects_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.yaml"
    with pytest.raises(ConfigError, match="not found"):
        load_config(missing)


def test_load_config_rejects_incomplete_paths(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("paths:\n  db_path: data/warehouse.duckdb\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(bad)


def test_ensure_data_directories(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    config = {
        "paths": {
            "raw_log_dir": str(data_root / "raw"),
            "parsed_dir": str(data_root / "parsed"),
            "timeseries_dir": str(data_root / "timeseries"),
            "baseline_dir": str(data_root / "baselines"),
            "scores_dir": str(data_root / "scores"),
            "report_dir": str(data_root / "reports"),
            "db_path": str(data_root / "warehouse.duckdb"),
        }
    }
    ensure_data_directories(config)
    assert (data_root / "raw").is_dir()
    assert (data_root / "parsed").is_dir()
    assert data_root.is_dir()


def _minimal_yaml(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "pipeline.yaml"
    path.write_text(
        "\n".join(
            [
                "paths:",
                "  raw_log_dir: data/raw/",
                "  parsed_dir: data/parsed/",
                "  timeseries_dir: data/timeseries/",
                "  baseline_dir: data/baselines/",
                "  scores_dir: data/scores/",
                "  report_dir: data/reports/",
                "  db_path: data/warehouse.duckdb",
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
                "  parallel_backend: dask",
                "  n_workers: 8",
                extra,
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_ingestion_block_loads(tmp_path: Path) -> None:
    path = _minimal_yaml(
        tmp_path,
        "ingestion:\n  dedup_backend: sqlite\n  dedup_memory_max_hashes: 100\n"
        "  syslog_year_policy: file_mtime",
    )
    config = load_config(path)
    settings = ingestion_settings(config)
    assert settings["dedup_backend"] == "sqlite"
    assert settings["syslog_year_policy"] == "file_mtime"
    assert settings["dedup_memory_max_hashes"] == 100
    assert settings["evidence_line_hash"] is False


def test_enabled_sources_allowlist_loads(tmp_path: Path) -> None:
    path = _minimal_yaml(tmp_path, "ingestion:\n  enabled_sources: [ssh]\n")
    settings = ingestion_settings(load_config(path))
    assert settings["enabled_sources"] == ["ssh"]


def test_enabled_sources_unknown_name_raises(tmp_path: Path) -> None:
    path = _minimal_yaml(
        tmp_path,
        "ingestion:\n  enabled_sources: [not_a_family]\n",
    )
    with pytest.raises(ConfigError, match="unknown names"):
        load_config(path)


def test_bad_syslog_year_policy_raises(tmp_path: Path) -> None:
    path = _minimal_yaml(
        tmp_path,
        "ingestion:\n  syslog_year_policy: invent_years",
    )
    with pytest.raises(ConfigError, match="syslog_year_policy"):
        load_config(path)


def test_evidence_line_hash_must_be_boolean(tmp_path: Path) -> None:
    path = _minimal_yaml(
        tmp_path,
        "ingestion:\n  evidence_line_hash: 1\n",
    )
    with pytest.raises(ConfigError, match="evidence_line_hash"):
        load_config(path)


def test_changepoint_rejects_nonpositive_h(tmp_path: Path) -> None:
    path = _minimal_yaml(tmp_path, "changepoint:\n  decision_h: 0\n")
    with pytest.raises(ConfigError, match="decision_h"):
        load_config(path)


def test_ml_defaults_when_flagging_omitted(tmp_path: Path) -> None:
    config = load_config(_minimal_yaml(tmp_path))
    settings = ml_settings(config)
    assert settings["flagging"] == "mad_threshold"
    assert settings["min_windows_to_fit"] == 20
    assert settings["mode"] == "refit_and_snapshot"
    assert settings["ensemble"]["enabled"] is False
    assert settings["ensemble"]["fusion"] == "majority"
    assert settings["ensemble"]["models"] == [
        "isolation_forest",
        "autoencoder",
    ]
    parse = parse_settings(config)
    assert parse["mode"] == "train_and_snapshot"
    assert parse["start_empty"] is False


def test_ml_ensemble_reuse_snapshot_rejected(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.yaml"
    path.write_text(
        _minimal_yaml(tmp_path).read_text(encoding="utf-8").replace(
            "  contamination: 0.02\n",
            "  contamination: 0.02\n"
            "  mode: refit_and_snapshot\n"
            "  ensemble:\n"
            "    enabled: true\n"
            "    models: [isolation_forest, autoencoder]\n"
            "    fusion: majority\n",
        ),
        encoding="utf-8",
    )
    # First confirm ensemble enabled loads
    settings = ml_settings(load_config(path))
    assert settings["ensemble"]["enabled"] is True

    bad = tmp_path / "pipeline_bad.yaml"
    bad.write_text(
        path.read_text(encoding="utf-8").replace(
            "mode: refit_and_snapshot",
            "mode: reuse_snapshot\n  snapshot_id: deadbeef",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="ensemble.enabled is incompatible"):
        load_config(bad)


def test_parse_reuse_snapshot_requires_id(tmp_path: Path) -> None:
    path = _minimal_yaml(
        tmp_path,
        "parse:\n  mode: reuse_snapshot\n  snapshot_id: null\n",
    )
    with pytest.raises(ConfigError, match="parse.snapshot_id"):
        load_config(path)


def test_ml_reuse_snapshot_requires_id(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.yaml"
    path.write_text(
        _minimal_yaml(tmp_path).read_text(encoding="utf-8").replace(
            "  contamination: 0.02\n",
            "  contamination: 0.02\n  mode: reuse_snapshot\n",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="ml.snapshot_id"):
        load_config(path)


def test_ml_score_threshold_without_value_raises(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.yaml"
    path.write_text(
        _minimal_yaml(tmp_path).read_text(encoding="utf-8").replace(
            "  contamination: 0.02\n",
            "  contamination: 0.02\n  flagging: score_threshold\n  score_threshold: null\n",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="score_threshold"):
        load_config(path)


def test_evaluation_defaults_when_block_omitted(tmp_path: Path) -> None:
    config = load_config(_minimal_yaml(tmp_path))
    settings = evaluation_settings(config)
    assert settings["labels_path"] is None
    assert settings["overlap_rule"] == "any"
    assert settings["write_entity_labels"] is True
    assert settings["output_dir"] == "data/reports/eval/"


def test_evaluation_iou_rule_loads(tmp_path: Path) -> None:
    path = _minimal_yaml(
        tmp_path,
        "evaluation:\n  overlap_rule: iou_0_1\n",
    )
    config = load_config(path)
    assert evaluation_settings(config)["overlap_rule"] == "iou_0_1"


def test_dashboard_defaults_when_block_omitted(tmp_path: Path) -> None:
    config = load_config(_minimal_yaml(tmp_path))
    settings = dashboard_settings(config)
    assert settings["default_incident_limit"] == 50
    assert settings["default_timeline_limit"] == 200
    assert settings["serve_legacy_html"] is False
    assert settings["cors_origins"] == [
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ]


def test_dashboard_rejects_wildcard_cors(tmp_path: Path) -> None:
    path = _minimal_yaml(tmp_path, "dashboard:\n  cors_origins: ['*']\n")
    with pytest.raises(ConfigError, match="must not include"):
        load_config(path)


def test_dashboard_rejects_non_local_cors(tmp_path: Path) -> None:
    path = _minimal_yaml(
        tmp_path,
        "dashboard:\n  cors_origins: ['http://evil.example']\n",
    )
    with pytest.raises(ConfigError, match="localhost"):
        load_config(path)


def test_spectral_fft_defaults_when_keys_omitted(tmp_path: Path) -> None:
    config = load_config(_minimal_yaml(tmp_path))
    settings = spectral_settings(config)
    assert settings["window"] == "hann"
    assert settings["min_welch_length"] == 4
    assert spectral_max_buckets_per_entity(config) == 100000


def test_spectral_window_unknown_raises(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.yaml"
    text = _minimal_yaml(tmp_path).read_text(encoding="utf-8")
    path.write_text(
        text.replace("  window_hours: 72\n", "  window: kaiser\n  window_hours: 72\n"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="spectral.window"):
        load_config(path)


def test_spectral_min_welch_length_must_be_at_least_two(tmp_path: Path) -> None:
    path = tmp_path / "pipeline.yaml"
    text = _minimal_yaml(tmp_path).read_text(encoding="utf-8")
    path.write_text(
        text.replace(
            "  window_hours: 72\n",
            "  min_welch_length: 1\n  window_hours: 72\n",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="min_welch_length"):
        load_config(path)


def test_warn_band_must_be_non_negative(tmp_path: Path) -> None:
    path = _minimal_yaml(
        tmp_path,
        "explainability:\n  warn_band: -0.1\n",
    )
    with pytest.raises(ConfigError, match="warn_band"):
        load_config(path)


def test_operator_label_must_be_non_empty(tmp_path: Path) -> None:
    path = _minimal_yaml(tmp_path, "dashboard:\n  operator_label: '   '\n")
    with pytest.raises(ConfigError, match="operator_label"):
        load_config(path)

