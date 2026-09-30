"""Load and validate pipeline.yaml configuration.

Relative paths in config are resolved against the process working directory.
Run commands from the `code/` project root so `data/` and `config/` resolve correctly.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from src.detectors.spectral.series import (
    ALLOWED_FFT_WINDOWS,
    DEFAULT_FFT_WINDOW,
    MIN_WELCH_LENGTH,
)
from src.ingestion.extractors.registry import REGISTERED_LOG_SOURCES
from src.ingestion.syslog_time import YEAR_POLICIES

REQUIRED_TOP_LEVEL_KEYS = (
    "paths",
    "bucketing",
    "statistical",
    "spectral",
    "ml",
    "correlation",
    "reporting",
    "orchestration",
)

REQUIRED_PATH_KEYS = (
    "raw_log_dir",
    "parsed_dir",
    "timeseries_dir",
    "baseline_dir",
    "scores_dir",
    "report_dir",
    "db_path",
)

# Optional path (Phase 66). Defaults applied in load_config / ensure_data_directories.
DEFAULT_ANALYSES_DIR = "data/analyses/"

DEDUP_BACKENDS = frozenset({"memory", "sqlite"})

DEFAULT_INGESTION: dict[str, Any] = {
    "dedup_backend": "memory",
    "dedup_memory_max_hashes": 2_000_000,
    "syslog_year_policy": "carry",
    "enabled_sources": [],
    "evidence_line_hash": False,
    "max_line_bytes": 1_048_576,
}

PARALLEL_BACKENDS = frozenset({"none", "threads", "processes", "dask"})

ML_FLAGGING_POLICIES = frozenset(
    {"predict", "score_threshold", "mad_threshold", "none"}
)

ALLOWED_ML_MODEL_TYPES = frozenset({"isolation_forest", "autoencoder", "onnx"})
ALLOWED_ML_ENSEMBLE_MODELS = frozenset({"isolation_forest", "autoencoder"})
ALLOWED_ML_ENSEMBLE_FUSIONS = frozenset({"majority", "any", "unanimous"})

DEFAULT_ML_ENSEMBLE: dict[str, Any] = {
    "enabled": False,
    "models": ["isolation_forest", "autoencoder"],
    "fusion": "majority",
}

DEFAULT_ML: dict[str, Any] = {
    "model_type": "isolation_forest",
    "onnx_model_path": None,
    "contamination": 0.02,
    "flagging": "mad_threshold",
    "score_threshold": None,
    "mad_k": 4.0,
    "min_windows_to_fit": 20,
    "mode": "refit_and_snapshot",
    "snapshot_id": None,
    "ae_hidden_dims": [32, 8, 32],
    "ae_max_iter": 200,
    "ensemble": dict(DEFAULT_ML_ENSEMBLE),
}

PARSE_MODES = frozenset({"train_and_snapshot", "reuse_snapshot"})
ML_SNAPSHOT_MODES = frozenset({"refit_and_snapshot", "reuse_snapshot"})

DEFAULT_PARSE: dict[str, Any] = {
    "mode": "train_and_snapshot",
    "start_empty": False,
    "snapshot_id": None,
}

DEFAULT_SPECTRAL_CLUSTER_MIN_ENTITIES = 20
DEFAULT_SPECTRAL_MAX_BUCKETS_PER_ENTITY = 100_000

KNOWN_SPECTRAL_FLAG_MODES = frozenset({"or", "and", "energy_only", "shape_only"})

DEFAULT_SPECTRAL_FLAGGING: dict[str, Any] = {
    "energy_z_threshold": None,
    "shape_js_z_threshold": None,
    "flag_mode": "or",
    "discount_last_window": False,
}

DEFAULT_CHANGEPOINT: dict[str, Any] = {
    "min_history_buckets": 48,
    "baseline_buckets": 48,
    "drift_k": 0.5,
    "decision_h": 5.0,
}

DEFAULT_SEASONAL: dict[str, Any] = {
    "enabled": True,
    "period_buckets": 144,
    "min_history_buckets": 288,
    "z_threshold": 4.0,
}

DEFAULT_SPECTRAL_FFT: dict[str, Any] = {
    "window": DEFAULT_FFT_WINDOW,
    "min_welch_length": MIN_WELCH_LENGTH,
}

KNOWN_OVERLAP_RULES = frozenset({"any", "iou_0_1"})
IMPLEMENTED_OVERLAP_RULES = frozenset({"any", "iou_0_1"})

DEFAULT_EVALUATION: dict[str, Any] = {
    "labels_path": None,
    "output_dir": "data/reports/eval/",
    "overlap_rule": "any",
    "write_entity_labels": True,
}

DEFAULT_CORS_ORIGINS = [
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]
ALLOWED_CORS_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

DEFAULT_DASHBOARD: dict[str, Any] = {
    "default_incident_limit": 50,
    "max_incident_limit": 500,
    "default_timeline_limit": 200,
    "incident_chart_pad_hours": 6,
    "serve_vendor_locally": True,
    "cors_origins": list(DEFAULT_CORS_ORIGINS),
    "serve_legacy_html": False,
    "operator_label": "local",
}

DEFAULT_EXPLAINABILITY: dict[str, Any] = {
    "playbooks_path": "config/playbooks.yaml",
    "log_source_limit": 8,
    "ml_top_templates": 5,
    "spectral_top_js_bins": 3,
    "gap_zero_fraction": 0.5,
    "warn_band": 0.5,
}

DEFAULT_PIPELINE_UI: dict[str, Any] = {
    "upload_dir": "data/raw/uploads/",
    "max_upload_bytes": 52_428_800,  # 50 MiB
    "max_files_per_request": 50,
    "allowed_suffixes": [".log", ".txt", ".json", ".jsonl", ".csv", ".cef"],
}

# Phase 80 — opt-in pre-ingest archive expand (disabled by default).
KNOWN_NORMALIZE_CONVERTERS = frozenset(
    {"gunzip", "bunzip2", "unzip", "tar", "evtx_text", "journal_export"}
)
KNOWN_NORMALIZE_ON_UNSUPPORTED = frozenset({"dead_letter", "skip", "fail"})
NORMALIZE_EXTRA_UPLOAD_SUFFIXES = (
    ".gz",
    ".bz2",
    ".zip",
    ".tar",
    ".tgz",
    ".ndjson",
    ".evtx",
    ".evt",
    ".journal",
)
KNOWN_EVTX_OUTPUT_FORMATS = frozenset({"text_oneline", "jsonl"})
KNOWN_JOURNAL_OUTPUT_FORMATS = frozenset({"short_iso"})

DEFAULT_NORMALIZE: dict[str, Any] = {
    "enabled": False,
    "input_dir": None,
    "output_dir": "data/raw/normalized",
    "clear_output_on_run": True,
    "converters": [
        "gunzip",
        "bunzip2",
        "unzip",
        "tar",
        "evtx_text",
        "journal_export",
    ],
    "on_unsupported": "dead_letter",
    "max_members_per_archive": 500,
    "max_member_bytes": 52_428_800,
    "max_total_output_bytes": 536_870_912,
    "allow_suffixes_passthrough": [
        ".log",
        ".txt",
        ".json",
        ".jsonl",
        ".csv",
        ".cef",
        ".ndjson",
    ],
    "evtx": {
        "output_format": "text_oneline",
        "max_events": 500_000,
    },
    "journal": {
        "output_format": "short_iso",
        "max_lines": 500_000,
    },
}

# Phase 88 — line-safe large-corpus splitter (opt-in; run-sharded is later).
DEFAULT_SHARDING_ANALYSIS_WINDOW: dict[str, Any] = {
    "enabled": False,
    "last_days": 30,
    "start_utc": None,
    "end_utc": None,
}

DEFAULT_SHARDING: dict[str, Any] = {
    "enabled": False,
    "target_shard_bytes": 1_073_741_824,  # 1 GiB soft target
    "target_shard_lines": None,
    "output_dir": "data/raw/shards/",
    "max_shards": 500,
    "prefer_server_path": True,
    "analysis_window": dict(DEFAULT_SHARDING_ANALYSIS_WINDOW),
}

# Phase 95 — assistive copilot feature flags (secrets stay in .env, not YAML).
DEFAULT_COPILOT_AI_INSIGHT: dict[str, Any] = {
    "enabled": False,
}

DEFAULT_COPILOT: dict[str, Any] = {
    "enabled": False,
    "max_attachment_chars": 4000,
    "max_timeline_events": 20,
    "ai_insight": dict(DEFAULT_COPILOT_AI_INSIGHT),
}


def default_parallel_backend() -> str:
    """Threads on Windows (DuckDB + processes is painful); processes elsewhere."""
    return "threads" if sys.platform.startswith("win") else "processes"


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


def load_config(path: str | Path) -> dict[str, Any]:
    """Load YAML config and validate required keys.

    Raises:
        ConfigError: if the file is missing or required structure is absent.
    """
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Config file not found: {config_path}")

    with config_path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        raise ConfigError(f"Config must be a mapping, got {type(data).__name__}")

    _validate_config(data)
    return data


def _validate_config(config: dict[str, Any]) -> None:
    missing_top = [key for key in REQUIRED_TOP_LEVEL_KEYS if key not in config]
    if missing_top:
        raise ConfigError(f"Config missing top-level keys: {', '.join(missing_top)}")

    paths = config["paths"]
    if not isinstance(paths, dict):
        raise ConfigError("Config 'paths' must be a mapping")

    missing_paths = [key for key in REQUIRED_PATH_KEYS if key not in paths]
    if missing_paths:
        raise ConfigError(f"Config paths missing keys: {', '.join(missing_paths)}")

    if not paths.get("db_path"):
        raise ConfigError("Config paths.db_path is required")

    analyses_dir = paths.get("analyses_dir")
    if not isinstance(analyses_dir, str) or not analyses_dir.strip():
        paths["analyses_dir"] = DEFAULT_ANALYSES_DIR
    else:
        paths["analyses_dir"] = analyses_dir.strip()

    if "ingestion" in config:
        ingestion = config["ingestion"]
        if not isinstance(ingestion, dict):
            raise ConfigError("Config 'ingestion' must be a mapping")
        _validate_ingestion_settings({**DEFAULT_INGESTION, **ingestion})

    orchestration = config["orchestration"]
    if not isinstance(orchestration, dict):
        raise ConfigError("Config 'orchestration' must be a mapping")
    _validate_orchestration_settings(
        {
            "parallel_backend": default_parallel_backend(),
            "n_workers": 8,
            "run_all_require_complete": False,
            **orchestration,
        }
    )

    ml = config["ml"]
    if not isinstance(ml, dict):
        raise ConfigError("Config 'ml' must be a mapping")
    _validate_ml_settings({**DEFAULT_ML, **ml})

    if "parse" in config:
        parse = config["parse"]
        if not isinstance(parse, dict):
            raise ConfigError("Config 'parse' must be a mapping")
        _validate_parse_settings({**DEFAULT_PARSE, **parse})

    spectral = config["spectral"]
    if not isinstance(spectral, dict):
        raise ConfigError("Config 'spectral' must be a mapping")
    _validate_spectral_fft_settings({**DEFAULT_SPECTRAL_FFT, **spectral})
    _validate_spectral_flagging_settings(spectral)
    _validate_spectral_cluster_min_entities(
        spectral.get("cluster_min_entities", DEFAULT_SPECTRAL_CLUSTER_MIN_ENTITIES)
    )
    _validate_spectral_max_buckets(
        spectral.get(
            "max_buckets_per_entity", DEFAULT_SPECTRAL_MAX_BUCKETS_PER_ENTITY
        )
    )

    if "changepoint" in config:
        changepoint = config["changepoint"]
        if not isinstance(changepoint, dict):
            raise ConfigError("Config 'changepoint' must be a mapping")
        _validate_changepoint_settings({**DEFAULT_CHANGEPOINT, **changepoint})

    if "seasonal" in config:
        seasonal = config["seasonal"]
        if not isinstance(seasonal, dict):
            raise ConfigError("Config 'seasonal' must be a mapping")
        _validate_seasonal_settings({**DEFAULT_SEASONAL, **seasonal})

    if "evaluation" in config:
        evaluation = config["evaluation"]
        if not isinstance(evaluation, dict):
            raise ConfigError("Config 'evaluation' must be a mapping")
        _validate_evaluation_settings({**DEFAULT_EVALUATION, **evaluation})

    if "dashboard" in config:
        dashboard = config["dashboard"]
        if not isinstance(dashboard, dict):
            raise ConfigError("Config 'dashboard' must be a mapping")
        _validate_dashboard_settings({**DEFAULT_DASHBOARD, **dashboard})

    if "explainability" in config:
        explainability = config["explainability"]
        if not isinstance(explainability, dict):
            raise ConfigError("Config 'explainability' must be a mapping")
        _validate_explainability_settings({**DEFAULT_EXPLAINABILITY, **explainability})

    if "pipeline_ui" in config:
        pipeline_ui = config["pipeline_ui"]
        if not isinstance(pipeline_ui, dict):
            raise ConfigError("Config 'pipeline_ui' must be a mapping")
        merged_ui = {**DEFAULT_PIPELINE_UI, **pipeline_ui}
        if "upload_dir" not in pipeline_ui:
            merged_ui["upload_dir"] = str(
                Path(str(config["paths"]["raw_log_dir"])) / "uploads"
            )
        _validate_pipeline_ui_settings(
            merged_ui,
            raw_log_dir=str(config["paths"]["raw_log_dir"]),
        )

    if "normalize" in config:
        normalize = config["normalize"]
        if not isinstance(normalize, dict):
            raise ConfigError("Config 'normalize' must be a mapping")
        _validate_normalize_settings({**DEFAULT_NORMALIZE, **normalize})

    if "sharding" in config:
        sharding = config["sharding"]
        if not isinstance(sharding, dict):
            raise ConfigError("Config 'sharding' must be a mapping")
        _validate_sharding_settings(
            {**DEFAULT_SHARDING, **sharding},
            raw_log_dir=str(config["paths"]["raw_log_dir"]),
        )

    if "copilot" in config:
        copilot = config["copilot"]
        if not isinstance(copilot, dict):
            raise ConfigError("Config 'copilot' must be a mapping")
        _validate_copilot_settings({**DEFAULT_COPILOT, **copilot})

    # correlation.* numeric/enum checks run inside correlate (persist), not here,
    # so run-all can list correlate as failed on bad values instead of aborting load.


def ingestion_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return ingestion tunables with defaults applied.

    ``ingestion`` is optional so inline test configs need not declare the block.
    """
    block = config.get("ingestion") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'ingestion' must be a mapping")
    settings = {**DEFAULT_INGESTION, **block}
    _validate_ingestion_settings(settings)
    return settings


def _validate_ingestion_settings(settings: dict[str, Any]) -> None:
    backend = settings.get("dedup_backend")
    if backend not in DEDUP_BACKENDS:
        raise ConfigError(
            f"ingestion.dedup_backend must be one of {sorted(DEDUP_BACKENDS)}, got {backend!r}"
        )
    policy = settings.get("syslog_year_policy")
    if policy not in YEAR_POLICIES:
        raise ConfigError(
            f"ingestion.syslog_year_policy must be one of {sorted(YEAR_POLICIES)}, got {policy!r}"
        )
    max_hashes = settings.get("dedup_memory_max_hashes")
    try:
        max_hashes_int = int(max_hashes)
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            "ingestion.dedup_memory_max_hashes must be a positive integer"
        ) from exc
    if max_hashes_int < 1:
        raise ConfigError("ingestion.dedup_memory_max_hashes must be a positive integer")
    settings["dedup_memory_max_hashes"] = max_hashes_int
    enabled = settings.get("enabled_sources", [])
    if enabled is None:
        enabled = []
    if not isinstance(enabled, list) or not all(isinstance(item, str) for item in enabled):
        raise ConfigError("ingestion.enabled_sources must be a list of strings")
    unknown = [name for name in enabled if name not in REGISTERED_LOG_SOURCES]
    if unknown:
        raise ConfigError(
            "ingestion.enabled_sources has unknown names: "
            + ", ".join(sorted(unknown))
            + f" (registered: {sorted(REGISTERED_LOG_SOURCES)})"
        )
    settings["enabled_sources"] = enabled
    evidence = settings.get("evidence_line_hash", False)
    if not isinstance(evidence, bool):
        raise ConfigError("ingestion.evidence_line_hash must be a boolean")
    settings["evidence_line_hash"] = evidence
    max_line_bytes = settings.get("max_line_bytes", 1_048_576)
    try:
        max_line_int = int(max_line_bytes)
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            "ingestion.max_line_bytes must be a positive integer"
        ) from exc
    if isinstance(max_line_bytes, bool) or max_line_int < 1:
        raise ConfigError("ingestion.max_line_bytes must be a positive integer")
    settings["max_line_bytes"] = max_line_int


def orchestration_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return orchestration tunables with platform defaults applied."""
    block = config.get("orchestration") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'orchestration' must be a mapping")
    settings = {
        "parallel_backend": default_parallel_backend(),
        "n_workers": 8,
        "run_all_require_complete": False,
        **block,
    }
    _validate_orchestration_settings(settings)
    return settings


def _validate_orchestration_settings(settings: dict[str, Any]) -> None:
    backend = settings.get("parallel_backend")
    if backend not in PARALLEL_BACKENDS:
        raise ConfigError(
            f"orchestration.parallel_backend must be one of {sorted(PARALLEL_BACKENDS)}, "
            f"got {backend!r}"
        )
    n_workers = settings.get("n_workers")
    try:
        n_workers_int = int(n_workers)
    except (TypeError, ValueError) as exc:
        raise ConfigError("orchestration.n_workers must be a positive integer") from exc
    if n_workers_int < 1:
        raise ConfigError("orchestration.n_workers must be a positive integer")
    settings["n_workers"] = n_workers_int
    require_complete = settings.get("run_all_require_complete", False)
    if not isinstance(require_complete, bool):
        raise ConfigError("orchestration.run_all_require_complete must be a boolean")
    settings["run_all_require_complete"] = require_complete


def ml_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return ML tunables with Phase 14 defaults applied."""
    block = config.get("ml") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'ml' must be a mapping")
    settings = {**DEFAULT_ML, **block}
    ensemble_block = block.get("ensemble", DEFAULT_ML_ENSEMBLE)
    if not isinstance(ensemble_block, dict):
        raise ConfigError("ml.ensemble must be a mapping")
    settings["ensemble"] = {**DEFAULT_ML_ENSEMBLE, **ensemble_block}
    _validate_ml_settings(settings)
    return settings


def _validate_ml_ensemble_settings(ensemble: dict[str, Any]) -> None:
    enabled = ensemble.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("ml.ensemble.enabled must be a boolean")
    ensemble["enabled"] = enabled

    models = ensemble.get("models", DEFAULT_ML_ENSEMBLE["models"])
    if not isinstance(models, (list, tuple)) or not models:
        raise ConfigError(
            "ml.ensemble.models must be a non-empty list of "
            f"{sorted(ALLOWED_ML_ENSEMBLE_MODELS)}"
        )
    parsed_models: list[str] = []
    seen: set[str] = set()
    for item in models:
        name = str(item).strip().lower()
        if name not in ALLOWED_ML_ENSEMBLE_MODELS:
            raise ConfigError(
                f"ml.ensemble.models entries must be one of "
                f"{sorted(ALLOWED_ML_ENSEMBLE_MODELS)}, got {item!r}"
            )
        if name in seen:
            continue
        seen.add(name)
        parsed_models.append(name)
    if len(parsed_models) < 2:
        raise ConfigError(
            "ml.ensemble.models must include at least two distinct models"
        )
    ensemble["models"] = parsed_models

    fusion = ensemble.get("fusion", "majority")
    if not isinstance(fusion, str) or fusion.strip().lower() not in (
        ALLOWED_ML_ENSEMBLE_FUSIONS
    ):
        raise ConfigError(
            f"ml.ensemble.fusion must be one of {sorted(ALLOWED_ML_ENSEMBLE_FUSIONS)}, "
            f"got {fusion!r}"
        )
    ensemble["fusion"] = fusion.strip().lower()


def _validate_ml_settings(settings: dict[str, Any]) -> None:
    model_type = settings.get("model_type", "isolation_forest")
    if model_type not in ALLOWED_ML_MODEL_TYPES:
        raise ConfigError(
            f"ml.model_type must be one of {sorted(ALLOWED_ML_MODEL_TYPES)}, "
            f"got {model_type!r}"
        )
    settings["model_type"] = str(model_type)

    ensemble = settings.get("ensemble", DEFAULT_ML_ENSEMBLE)
    if not isinstance(ensemble, dict):
        raise ConfigError("ml.ensemble must be a mapping")
    merged_ensemble = {**DEFAULT_ML_ENSEMBLE, **ensemble}
    _validate_ml_ensemble_settings(merged_ensemble)
    settings["ensemble"] = merged_ensemble
    if merged_ensemble["enabled"] and settings.get("mode") == "reuse_snapshot":
        raise ConfigError(
            "ml.ensemble.enabled is incompatible with ml.mode: reuse_snapshot "
            "(IF and AE use distinct snapshot ids; use refit_and_snapshot)"
        )

    onnx_path = settings.get("onnx_model_path")
    if onnx_path is not None and not isinstance(onnx_path, str):
        raise ConfigError("ml.onnx_model_path must be a string or null")
    if onnx_path == "":
        onnx_path = None
    settings["onnx_model_path"] = onnx_path

    hidden = settings.get("ae_hidden_dims", [32, 8, 32])
    if not isinstance(hidden, (list, tuple)) or not hidden:
        raise ConfigError("ml.ae_hidden_dims must be a non-empty list of positive ints")
    parsed_hidden: list[int] = []
    for item in hidden:
        try:
            dim = int(item)
        except (TypeError, ValueError) as exc:
            raise ConfigError(
                "ml.ae_hidden_dims must be a non-empty list of positive ints"
            ) from exc
        if isinstance(item, bool) or dim < 1:
            raise ConfigError(
                "ml.ae_hidden_dims must be a non-empty list of positive ints"
            )
        parsed_hidden.append(dim)
    settings["ae_hidden_dims"] = parsed_hidden

    max_iter = settings.get("ae_max_iter", 200)
    try:
        max_iter_int = int(max_iter)
    except (TypeError, ValueError) as exc:
        raise ConfigError("ml.ae_max_iter must be a positive integer") from exc
    if isinstance(max_iter, bool) or max_iter_int < 1:
        raise ConfigError("ml.ae_max_iter must be a positive integer")
    settings["ae_max_iter"] = max_iter_int

    flagging = settings.get("flagging")
    if flagging not in ML_FLAGGING_POLICIES:
        raise ConfigError(
            f"ml.flagging must be one of {sorted(ML_FLAGGING_POLICIES)}, "
            f"got {flagging!r}"
        )
    settings["flagging"] = str(flagging)

    contamination = settings.get("contamination")
    if not isinstance(contamination, (int, float)) or isinstance(contamination, bool):
        raise ConfigError(
            f"ml.contamination must be in (0, 0.5], got {contamination!r}"
        )
    contamination_f = float(contamination)
    if not (0.0 < contamination_f <= 0.5):
        raise ConfigError(
            f"ml.contamination must be in (0, 0.5], got {contamination!r}"
        )
    settings["contamination"] = contamination_f

    mad_k = settings.get("mad_k")
    if not isinstance(mad_k, (int, float)) or isinstance(mad_k, bool):
        raise ConfigError(f"ml.mad_k must be numeric, got {mad_k!r}")
    settings["mad_k"] = float(mad_k)

    min_windows = settings.get("min_windows_to_fit")
    try:
        min_windows_int = int(min_windows)
    except (TypeError, ValueError) as exc:
        raise ConfigError("ml.min_windows_to_fit must be a positive integer") from exc
    if isinstance(min_windows, bool) or min_windows_int < 1:
        raise ConfigError("ml.min_windows_to_fit must be a positive integer")
    settings["min_windows_to_fit"] = min_windows_int

    score_threshold = settings.get("score_threshold")
    if settings["flagging"] == "score_threshold":
        if score_threshold is None:
            raise ConfigError(
                "ml.score_threshold is required when ml.flagging is 'score_threshold'"
            )
        if not isinstance(score_threshold, (int, float)) or isinstance(
            score_threshold, bool
        ):
            raise ConfigError(
                f"ml.score_threshold must be numeric, got {score_threshold!r}"
            )
        settings["score_threshold"] = float(score_threshold)
    elif score_threshold is not None:
        if not isinstance(score_threshold, (int, float)) or isinstance(
            score_threshold, bool
        ):
            raise ConfigError(
                f"ml.score_threshold must be numeric or null, got {score_threshold!r}"
            )
        settings["score_threshold"] = float(score_threshold)

    mode = settings.get("mode", "refit_and_snapshot")
    if mode not in ML_SNAPSHOT_MODES:
        raise ConfigError(
            f"ml.mode must be one of {sorted(ML_SNAPSHOT_MODES)}, got {mode!r}"
        )
    settings["mode"] = str(mode)
    snapshot_id = settings.get("snapshot_id")
    if snapshot_id is not None and not isinstance(snapshot_id, str):
        raise ConfigError("ml.snapshot_id must be a string or null")
    if snapshot_id == "":
        snapshot_id = None
    settings["snapshot_id"] = snapshot_id
    if mode == "reuse_snapshot" and not snapshot_id:
        raise ConfigError("ml.snapshot_id is required when ml.mode is reuse_snapshot")

def parse_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return parse snapshot tunables. ``parse`` is optional on test configs."""
    block = config.get("parse") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'parse' must be a mapping")
    settings = {**DEFAULT_PARSE, **block}
    _validate_parse_settings(settings)
    return settings


def _validate_parse_settings(settings: dict[str, Any]) -> None:
    mode = settings.get("mode", "train_and_snapshot")
    if mode not in PARSE_MODES:
        raise ConfigError(
            f"parse.mode must be one of {sorted(PARSE_MODES)}, got {mode!r}"
        )
    settings["mode"] = str(mode)
    start_empty = settings.get("start_empty", False)
    if not isinstance(start_empty, bool):
        raise ConfigError("parse.start_empty must be a boolean")
    settings["start_empty"] = start_empty
    snapshot_id = settings.get("snapshot_id")
    if snapshot_id is not None and not isinstance(snapshot_id, str):
        raise ConfigError("parse.snapshot_id must be a string or null")
    if snapshot_id == "":
        snapshot_id = None
    settings["snapshot_id"] = snapshot_id
    if mode == "reuse_snapshot" and not snapshot_id:
        raise ConfigError(
            "parse.snapshot_id is required when parse.mode is reuse_snapshot"
        )
    if mode == "reuse_snapshot" and start_empty:
        raise ConfigError(
            "parse.start_empty cannot be true when parse.mode is reuse_snapshot"
        )


def changepoint_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return CUSUM tunables. ``changepoint`` is optional on inline test configs."""
    block = config.get("changepoint") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'changepoint' must be a mapping")
    settings = {**DEFAULT_CHANGEPOINT, **block}
    _validate_changepoint_settings(settings)
    return settings


def _validate_changepoint_settings(settings: dict[str, Any]) -> None:
    for key in ("min_history_buckets", "baseline_buckets"):
        value = settings.get(key)
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"changepoint.{key} must be a positive integer") from exc
        if isinstance(value, bool) or number < 1:
            raise ConfigError(f"changepoint.{key} must be a positive integer")
        settings[key] = number
    for key in ("drift_k", "decision_h"):
        value = settings.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ConfigError(f"changepoint.{key} must be numeric")
        number = float(value)
        if key == "drift_k" and number < 0.0:
            raise ConfigError("changepoint.drift_k must be non-negative")
        if key == "decision_h" and number <= 0.0:
            raise ConfigError("changepoint.decision_h must be > 0")
        settings[key] = number


def seasonal_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return seasonal residual tunables. ``seasonal`` is optional on inline configs."""
    block = config.get("seasonal") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'seasonal' must be a mapping")
    settings = {**DEFAULT_SEASONAL, **block}
    _validate_seasonal_settings(settings)
    return settings


def _validate_seasonal_settings(settings: dict[str, Any]) -> None:
    enabled = settings.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError("seasonal.enabled must be a boolean")
    settings["enabled"] = enabled
    for key in ("period_buckets", "min_history_buckets"):
        value = settings.get(key)
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"seasonal.{key} must be a positive integer") from exc
        if isinstance(value, bool) or number < 1:
            raise ConfigError(f"seasonal.{key} must be a positive integer")
        if key == "period_buckets" and number < 2:
            raise ConfigError("seasonal.period_buckets must be an integer >= 2")
        settings[key] = number
    z_threshold = settings.get("z_threshold")
    if not isinstance(z_threshold, (int, float)) or isinstance(z_threshold, bool):
        raise ConfigError("seasonal.z_threshold must be numeric")
    z_value = float(z_threshold)
    if z_value <= 0.0:
        raise ConfigError("seasonal.z_threshold must be > 0")
    settings["z_threshold"] = z_value


def evaluation_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return evaluation tunables with defaults applied.

    ``evaluation`` is optional so inline test configs need not declare the block.
    ``labels_path`` may be null until the evaluate stage runs.
    """
    block = config.get("evaluation") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'evaluation' must be a mapping")
    settings = {**DEFAULT_EVALUATION, **block}
    _validate_evaluation_settings(settings)
    return settings


def _validate_evaluation_settings(settings: dict[str, Any]) -> None:
    overlap_rule = settings.get("overlap_rule")
    if overlap_rule not in KNOWN_OVERLAP_RULES:
        raise ConfigError(
            f"evaluation.overlap_rule must be one of {sorted(KNOWN_OVERLAP_RULES)}, "
            f"got {overlap_rule!r}"
        )
    if overlap_rule not in IMPLEMENTED_OVERLAP_RULES:
        raise ConfigError(
            f"evaluation.overlap_rule {overlap_rule!r} is not implemented; use 'any'"
        )
    settings["overlap_rule"] = str(overlap_rule)

    write_entity_labels = settings.get("write_entity_labels", True)
    if not isinstance(write_entity_labels, bool):
        raise ConfigError("evaluation.write_entity_labels must be a boolean")
    settings["write_entity_labels"] = write_entity_labels

    output_dir = settings.get("output_dir")
    if not isinstance(output_dir, str) or not output_dir.strip():
        raise ConfigError("evaluation.output_dir must be a non-empty string")
    settings["output_dir"] = output_dir

    labels_path = settings.get("labels_path")
    if labels_path is not None and (
        not isinstance(labels_path, str) or not str(labels_path).strip()
    ):
        raise ConfigError("evaluation.labels_path must be a path string or null")
    if isinstance(labels_path, str):
        settings["labels_path"] = labels_path.strip() or None


def dashboard_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return dashboard tunables with defaults applied.

    ``dashboard`` is optional so inline test configs need not declare the block.
    """
    block = config.get("dashboard") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'dashboard' must be a mapping")
    settings = {**DEFAULT_DASHBOARD, **block}
    _validate_dashboard_settings(settings)
    return settings


def _validate_dashboard_settings(settings: dict[str, Any]) -> None:
    for key in (
        "default_incident_limit",
        "max_incident_limit",
        "default_timeline_limit",
        "incident_chart_pad_hours",
    ):
        value = settings.get(key)
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"dashboard.{key} must be a positive integer") from exc
        if isinstance(value, bool) or number < 1:
            raise ConfigError(f"dashboard.{key} must be a positive integer")
        settings[key] = number
    if settings["default_incident_limit"] > settings["max_incident_limit"]:
        raise ConfigError(
            "dashboard.default_incident_limit must be <= dashboard.max_incident_limit"
        )
    serve_vendor = settings.get("serve_vendor_locally", True)
    if not isinstance(serve_vendor, bool):
        raise ConfigError("dashboard.serve_vendor_locally must be a boolean")
    settings["serve_vendor_locally"] = serve_vendor
    serve_legacy = settings.get("serve_legacy_html", False)
    if not isinstance(serve_legacy, bool):
        raise ConfigError("dashboard.serve_legacy_html must be a boolean")
    settings["serve_legacy_html"] = serve_legacy
    settings["cors_origins"] = _validate_cors_origins(
        settings.get("cors_origins", DEFAULT_CORS_ORIGINS)
    )
    label = settings.get("operator_label", "local")
    if not isinstance(label, str) or not label.strip():
        raise ConfigError("dashboard.operator_label must be a non-empty string")
    settings["operator_label"] = label.strip()[:64]


def pipeline_ui_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return pipeline operator-UI tunables with defaults applied.

    ``pipeline_ui`` is optional so inline test configs need not declare the block.
    When ``upload_dir`` is omitted, it defaults to ``{paths.raw_log_dir}/uploads``.
    """
    block = config.get("pipeline_ui") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'pipeline_ui' must be a mapping")
    settings = {**DEFAULT_PIPELINE_UI, **block}
    if "upload_dir" not in block:
        settings["upload_dir"] = str(
            Path(str(config["paths"]["raw_log_dir"])) / "uploads"
        )
    _validate_pipeline_ui_settings(
        settings,
        raw_log_dir=str(config["paths"]["raw_log_dir"]),
    )
    return settings


def normalize_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return normalize tunables. ``normalize`` is optional on inline configs."""
    block = config.get("normalize") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'normalize' must be a mapping")
    settings = {**DEFAULT_NORMALIZE, **block}
    _validate_normalize_settings(settings)
    return settings


def sharding_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return sharding tunables. ``sharding`` is optional on inline configs."""
    block = config.get("sharding") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'sharding' must be a mapping")
    settings = {**DEFAULT_SHARDING, **block}
    _validate_sharding_settings(
        settings,
        raw_log_dir=str(config["paths"]["raw_log_dir"]),
    )
    return settings


def copilot_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return copilot YAML flags. ``copilot`` is optional on inline configs.

    Dual-gate with env ``COPILOT_ENABLED`` via ``src.copilot.is_copilot_runtime_enabled``.
    Provider secrets are never read from YAML — use ``code/.env``.
    """
    block = config.get("copilot") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'copilot' must be a mapping")
    settings = {**DEFAULT_COPILOT, **block}
    insight = block.get("ai_insight", DEFAULT_COPILOT_AI_INSIGHT)
    if not isinstance(insight, dict):
        raise ConfigError("copilot.ai_insight must be a mapping")
    settings["ai_insight"] = {**DEFAULT_COPILOT_AI_INSIGHT, **insight}
    _validate_copilot_settings(settings)
    return settings


def _validate_copilot_settings(settings: dict[str, Any]) -> None:
    enabled = settings.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("copilot.enabled must be a boolean")
    settings["enabled"] = enabled

    for key in ("max_attachment_chars", "max_timeline_events"):
        value = settings.get(key)
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"copilot.{key} must be a positive integer") from exc
        if isinstance(value, bool) or number < 1:
            raise ConfigError(f"copilot.{key} must be a positive integer")
        settings[key] = number

    insight = settings.get("ai_insight") or {}
    if not isinstance(insight, dict):
        raise ConfigError("copilot.ai_insight must be a mapping")
    insight = {**DEFAULT_COPILOT_AI_INSIGHT, **insight}
    insight_enabled = insight.get("enabled", False)
    if not isinstance(insight_enabled, bool):
        raise ConfigError("copilot.ai_insight.enabled must be a boolean")
    insight["enabled"] = insight_enabled
    settings["ai_insight"] = insight


def _validate_sharding_settings(
    settings: dict[str, Any],
    *,
    raw_log_dir: str,
) -> None:
    enabled = settings.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("sharding.enabled must be a boolean")
    settings["enabled"] = enabled

    prefer = settings.get("prefer_server_path", True)
    if not isinstance(prefer, bool):
        raise ConfigError("sharding.prefer_server_path must be a boolean")
    settings["prefer_server_path"] = prefer

    output_dir = settings.get("output_dir")
    if not isinstance(output_dir, str) or not output_dir.strip():
        raise ConfigError("sharding.output_dir must be a non-empty path string")
    settings["output_dir"] = output_dir.strip()

    target_bytes = settings.get("target_shard_bytes", DEFAULT_SHARDING["target_shard_bytes"])
    target_lines = settings.get("target_shard_lines", DEFAULT_SHARDING["target_shard_lines"])
    if target_bytes is not None:
        try:
            bytes_n = int(target_bytes)
        except (TypeError, ValueError) as exc:
            raise ConfigError(
                "sharding.target_shard_bytes must be null or a positive integer"
            ) from exc
        if isinstance(target_bytes, bool) or bytes_n < 1:
            raise ConfigError(
                "sharding.target_shard_bytes must be null or a positive integer"
            )
        settings["target_shard_bytes"] = bytes_n
    else:
        settings["target_shard_bytes"] = None

    if target_lines is not None:
        try:
            lines_n = int(target_lines)
        except (TypeError, ValueError) as exc:
            raise ConfigError(
                "sharding.target_shard_lines must be null or a positive integer"
            ) from exc
        if isinstance(target_lines, bool) or lines_n < 1:
            raise ConfigError(
                "sharding.target_shard_lines must be null or a positive integer"
            )
        settings["target_shard_lines"] = lines_n
    else:
        settings["target_shard_lines"] = None

    if settings["target_shard_bytes"] is None and settings["target_shard_lines"] is None:
        raise ConfigError(
            "sharding requires target_shard_bytes and/or target_shard_lines"
        )

    try:
        max_shards = int(settings.get("max_shards", DEFAULT_SHARDING["max_shards"]))
    except (TypeError, ValueError) as exc:
        raise ConfigError("sharding.max_shards must be a positive integer") from exc
    if isinstance(settings.get("max_shards"), bool) or max_shards < 1:
        raise ConfigError("sharding.max_shards must be a positive integer")
    settings["max_shards"] = max_shards

    window = settings.get("analysis_window") or {}
    if not isinstance(window, dict):
        raise ConfigError("sharding.analysis_window must be a mapping")
    window = {**DEFAULT_SHARDING_ANALYSIS_WINDOW, **window}
    win_enabled = window.get("enabled", False)
    if not isinstance(win_enabled, bool):
        raise ConfigError("sharding.analysis_window.enabled must be a boolean")
    window["enabled"] = win_enabled
    try:
        last_days = int(window.get("last_days", 30))
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            "sharding.analysis_window.last_days must be a positive integer"
        ) from exc
    if isinstance(window.get("last_days"), bool) or last_days < 1:
        raise ConfigError(
            "sharding.analysis_window.last_days must be a positive integer"
        )
    window["last_days"] = last_days

    start_raw = window.get("start_utc")
    end_raw = window.get("end_utc")
    if start_raw is None and end_raw is None:
        window["start_utc"] = None
        window["end_utc"] = None
    else:
        if start_raw is None or end_raw is None:
            raise ConfigError(
                "sharding.analysis_window.start_utc and end_utc must both "
                "be set (or both omitted for last_days mode)"
            )

        def _parse_window_ts(raw: Any, *, field_name: str) -> datetime:
            if isinstance(raw, datetime):
                value = raw
            elif isinstance(raw, str) and raw.strip():
                text = raw.strip()
                if text.endswith("Z"):
                    text = text[:-1] + "+00:00"
                try:
                    value = datetime.fromisoformat(text)
                except ValueError as exc:
                    raise ConfigError(
                        f"{field_name} must be ISO-8601 UTC (got {raw!r})"
                    ) from exc
            else:
                raise ConfigError(
                    f"{field_name} must be a non-empty ISO-8601 timestamp"
                )
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)

        start_dt = _parse_window_ts(
            start_raw, field_name="sharding.analysis_window.start_utc"
        )
        end_dt = _parse_window_ts(
            end_raw, field_name="sharding.analysis_window.end_utc"
        )
        if start_dt > end_dt:
            raise ConfigError(
                "sharding.analysis_window.start_utc must be <= end_utc"
            )
        window["start_utc"] = start_dt.isoformat()
        window["end_utc"] = end_dt.isoformat()

    settings["analysis_window"] = window

    out_resolved = Path(settings["output_dir"]).resolve()
    raw_resolved = Path(raw_log_dir).resolve()
    try:
        out_resolved.relative_to(raw_resolved)
    except ValueError as exc:
        raise ConfigError(
            "sharding.output_dir must resolve inside paths.raw_log_dir "
            "(shards stay under the raw tree for custody)"
        ) from exc


def _normalize_suffix_list(value: Any, *, field_name: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{field_name} must be a non-empty list")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(f"{field_name} entries must be non-empty strings")
        suffix = item.strip().lower()
        if not suffix.startswith("."):
            suffix = f".{suffix}"
        normalized.append(suffix)
    return normalized


def _validate_normalize_settings(settings: dict[str, Any]) -> None:
    enabled = settings.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("normalize.enabled must be a boolean")
    settings["enabled"] = enabled

    clear_output = settings.get("clear_output_on_run", True)
    if not isinstance(clear_output, bool):
        raise ConfigError("normalize.clear_output_on_run must be a boolean")
    settings["clear_output_on_run"] = clear_output

    input_dir = settings.get("input_dir")
    if input_dir is not None:
        if not isinstance(input_dir, str) or not input_dir.strip():
            raise ConfigError(
                "normalize.input_dir must be null or a non-empty path string"
            )
        settings["input_dir"] = input_dir.strip()
    else:
        settings["input_dir"] = None

    output_dir = settings.get("output_dir")
    if not isinstance(output_dir, str) or not output_dir.strip():
        raise ConfigError("normalize.output_dir must be a non-empty path string")
    settings["output_dir"] = output_dir.strip()

    converters = settings.get("converters")
    if not isinstance(converters, list) or not converters:
        raise ConfigError("normalize.converters must be a non-empty list")
    cleaned: list[str] = []
    for item in converters:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError("normalize.converters entries must be non-empty strings")
        name = item.strip()
        if name not in KNOWN_NORMALIZE_CONVERTERS:
            raise ConfigError(
                f"normalize.converters unknown id {name!r}; "
                f"allowed: {sorted(KNOWN_NORMALIZE_CONVERTERS)}"
            )
        cleaned.append(name)
    settings["converters"] = cleaned

    on_unsupported = settings.get("on_unsupported", "dead_letter")
    if on_unsupported not in KNOWN_NORMALIZE_ON_UNSUPPORTED:
        raise ConfigError(
            "normalize.on_unsupported must be one of "
            f"{sorted(KNOWN_NORMALIZE_ON_UNSUPPORTED)}, got {on_unsupported!r}"
        )
    settings["on_unsupported"] = str(on_unsupported)

    for key in (
        "max_members_per_archive",
        "max_member_bytes",
        "max_total_output_bytes",
    ):
        value = settings.get(key)
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"normalize.{key} must be a positive integer") from exc
        if isinstance(value, bool) or number < 1:
            raise ConfigError(f"normalize.{key} must be a positive integer")
        settings[key] = number

    settings["allow_suffixes_passthrough"] = _normalize_suffix_list(
        settings.get("allow_suffixes_passthrough"),
        field_name="normalize.allow_suffixes_passthrough",
    )

    evtx = settings.get("evtx") or {}
    if not isinstance(evtx, dict):
        raise ConfigError("normalize.evtx must be a mapping")
    evtx = {**DEFAULT_NORMALIZE["evtx"], **evtx}
    fmt = evtx.get("output_format", "text_oneline")
    if fmt not in KNOWN_EVTX_OUTPUT_FORMATS:
        raise ConfigError(
            "normalize.evtx.output_format must be one of "
            f"{sorted(KNOWN_EVTX_OUTPUT_FORMATS)}, got {fmt!r}"
        )
    evtx["output_format"] = str(fmt)
    try:
        max_events = int(evtx.get("max_events", 500_000))
    except (TypeError, ValueError) as exc:
        raise ConfigError("normalize.evtx.max_events must be a positive integer") from exc
    if isinstance(evtx.get("max_events"), bool) or max_events < 1:
        raise ConfigError("normalize.evtx.max_events must be a positive integer")
    evtx["max_events"] = max_events
    settings["evtx"] = evtx

    journal = settings.get("journal") or {}
    if not isinstance(journal, dict):
        raise ConfigError("normalize.journal must be a mapping")
    journal = {**DEFAULT_NORMALIZE["journal"], **journal}
    jfmt = journal.get("output_format", "short_iso")
    if jfmt not in KNOWN_JOURNAL_OUTPUT_FORMATS:
        raise ConfigError(
            "normalize.journal.output_format must be one of "
            f"{sorted(KNOWN_JOURNAL_OUTPUT_FORMATS)}, got {jfmt!r}"
        )
    journal["output_format"] = str(jfmt)
    try:
        max_lines = int(journal.get("max_lines", 500_000))
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            "normalize.journal.max_lines must be a positive integer"
        ) from exc
    if isinstance(journal.get("max_lines"), bool) or max_lines < 1:
        raise ConfigError("normalize.journal.max_lines must be a positive integer")
    journal["max_lines"] = max_lines
    settings["journal"] = journal


def effective_upload_allowed_suffixes(config: dict[str, Any]) -> list[str]:
    """Upload allowlist; when normalize is enabled, archive + ``.ndjson`` are added."""
    settings = pipeline_ui_settings(config)
    allowed = list(settings["allowed_suffixes"])
    if normalize_settings(config)["enabled"]:
        seen = {s.lower() for s in allowed}
        for suffix in NORMALIZE_EXTRA_UPLOAD_SUFFIXES:
            if suffix.lower() not in seen:
                allowed.append(suffix)
                seen.add(suffix.lower())
    return allowed


def _validate_pipeline_ui_settings(
    settings: dict[str, Any],
    *,
    raw_log_dir: str,
) -> None:
    upload_dir = settings.get("upload_dir")
    if not isinstance(upload_dir, str) or not upload_dir.strip():
        raise ConfigError("pipeline_ui.upload_dir must be a non-empty path string")
    settings["upload_dir"] = upload_dir.strip()

    for key in ("max_upload_bytes", "max_files_per_request"):
        value = settings.get(key)
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"pipeline_ui.{key} must be a positive integer") from exc
        if isinstance(value, bool) or number < 1:
            raise ConfigError(f"pipeline_ui.{key} must be a positive integer")
        settings[key] = number

    suffixes = settings.get("allowed_suffixes")
    if not isinstance(suffixes, list) or not suffixes:
        raise ConfigError("pipeline_ui.allowed_suffixes must be a non-empty list")
    normalized: list[str] = []
    for item in suffixes:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(
                "pipeline_ui.allowed_suffixes entries must be non-empty strings"
            )
        suffix = item.strip().lower()
        if not suffix.startswith("."):
            suffix = f".{suffix}"
        normalized.append(suffix)
    settings["allowed_suffixes"] = normalized

    upload_resolved = Path(settings["upload_dir"]).resolve()
    raw_resolved = Path(raw_log_dir).resolve()
    try:
        upload_resolved.relative_to(raw_resolved)
    except ValueError as exc:
        raise ConfigError(
            "pipeline_ui.upload_dir must resolve inside paths.raw_log_dir "
            "so ingest can see uploaded files"
        ) from exc


def _validate_cors_origins(value: Any) -> list[str]:
    """Allowlist of http(s) localhost / 127.0.0.1 origins. Never '*'."""
    if not isinstance(value, list):
        raise ConfigError("dashboard.cors_origins must be a list of origin URLs")
    origins: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError("dashboard.cors_origins entries must be non-empty strings")
        origin = item.strip().rstrip("/")
        if origin == "*":
            raise ConfigError("dashboard.cors_origins must not include '*'")
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"}:
            raise ConfigError(
                f"dashboard.cors_origins entry must be http(s): {item!r}"
            )
        host = (parsed.hostname or "").lower()
        if host not in ALLOWED_CORS_HOSTS:
            raise ConfigError(
                "dashboard.cors_origins hosts must be localhost or 127.0.0.1"
            )
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ConfigError(
                f"dashboard.cors_origins must be an origin (no path): {item!r}"
            )
        origins.append(origin)
    return origins


def explainability_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return R7 explainability tunables. Optional on inline test configs."""
    block = config.get("explainability") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'explainability' must be a mapping")
    settings = {**DEFAULT_EXPLAINABILITY, **block}
    _validate_explainability_settings(settings)
    return settings


def _validate_explainability_settings(settings: dict[str, Any]) -> None:
    playbooks_path = settings.get("playbooks_path", "config/playbooks.yaml")
    if not isinstance(playbooks_path, str) or not playbooks_path.strip():
        raise ConfigError("explainability.playbooks_path must be a non-empty string")
    settings["playbooks_path"] = playbooks_path.strip()
    for key in ("log_source_limit", "ml_top_templates", "spectral_top_js_bins"):
        value = settings.get(key)
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(
                f"explainability.{key} must be a positive integer"
            ) from exc
        if isinstance(value, bool) or number < 1:
            raise ConfigError(f"explainability.{key} must be a positive integer")
        settings[key] = number
    gap = settings.get("gap_zero_fraction", 0.5)
    if not isinstance(gap, (int, float)) or isinstance(gap, bool):
        raise ConfigError("explainability.gap_zero_fraction must be in [0, 1]")
    gap_f = float(gap)
    if not (0.0 <= gap_f <= 1.0):
        raise ConfigError("explainability.gap_zero_fraction must be in [0, 1]")
    settings["gap_zero_fraction"] = gap_f
    warn_band = settings.get("warn_band", 0.5)
    if not isinstance(warn_band, (int, float)) or isinstance(warn_band, bool):
        raise ConfigError("explainability.warn_band must be a non-negative number")
    warn_f = float(warn_band)
    if warn_f < 0.0:
        raise ConfigError("explainability.warn_band must be a non-negative number")
    settings["warn_band"] = warn_f


def ui_honesty_settings(config: dict[str, Any]) -> dict[str, Any]:
    """R8 display policy: warn_band and detector cutoffs. Does not change flagging."""
    expl = explainability_settings(config)
    statistical = config.get("statistical") or {}
    spectral = config.get("spectral") or {}
    if not isinstance(statistical, dict):
        raise ConfigError("Config 'statistical' must be a mapping")
    if not isinstance(spectral, dict):
        raise ConfigError("Config 'spectral' must be a mapping")
    try:
        stat_z = float(statistical.get("z_threshold", 4.0))
        spec_z = float(spectral.get("z_threshold", 4.0))
    except (TypeError, ValueError) as exc:
        raise ConfigError("z_threshold must be numeric") from exc
    dash = dashboard_settings(config)
    return {
        "warn_band": expl["warn_band"],
        "statistical_z_threshold": stat_z,
        "spectral_z_threshold": spec_z,
        "ml_mad_k": ml_settings(config)["mad_k"],
        "operator_label": dash["operator_label"],
    }


def spectral_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return spectral FFT tunables with defaults applied.

    ``window`` is the SciPy taper (Hann/Hamming/boxcar/…). Distinct from
    ``spectral.window_hours``, which is the STFT duration.
    """
    block = config.get("spectral") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'spectral' must be a mapping")
    settings = {**DEFAULT_SPECTRAL_FFT, **block}
    _validate_spectral_fft_settings(settings)
    return {
        "window": settings["window"],
        "min_welch_length": settings["min_welch_length"],
    }


def spectral_flagging_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Return resolved spectral flag thresholds / mode (Phase 51).

    ``energy_z_threshold`` / ``shape_js_z_threshold`` null → use ``z_threshold``.
    Default ``flag_mode`` is ``or`` (legacy dual-OR).
    """
    block = config.get("spectral") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'spectral' must be a mapping")
    merged = {**DEFAULT_SPECTRAL_FLAGGING, **block}
    _validate_spectral_flagging_settings(merged)
    z_threshold = float(merged["z_threshold"])
    energy_raw = merged.get("energy_z_threshold")
    shape_raw = merged.get("shape_js_z_threshold")
    energy_thr = z_threshold if energy_raw is None else float(energy_raw)
    shape_thr = z_threshold if shape_raw is None else float(shape_raw)
    flag_mode = str(merged["flag_mode"]).strip().lower()
    return {
        "z_threshold": z_threshold,
        "energy_z_threshold": energy_thr,
        "shape_js_z_threshold": shape_thr,
        "flag_mode": flag_mode,
        "discount_last_window": bool(merged["discount_last_window"]),
        "rule": spectral_flag_rule_label(flag_mode),
    }


def spectral_flag_rule_label(flag_mode: str) -> str:
    """Anomaly metadata ``rule`` string for the active spectral flag mode."""
    return {
        "or": "energy_or_shape",
        "and": "energy_and_shape",
        "energy_only": "energy_only",
        "shape_only": "shape_only",
    }.get(flag_mode, "energy_or_shape")


def _validate_spectral_flagging_settings(settings: dict[str, Any]) -> None:
    z_threshold = settings.get("z_threshold")
    if not isinstance(z_threshold, (int, float)) or isinstance(z_threshold, bool):
        raise ConfigError(
            f"spectral.z_threshold must be numeric, got {z_threshold!r}"
        )

    for key in ("energy_z_threshold", "shape_js_z_threshold"):
        value = settings.get(key, None)
        if value is None:
            continue
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ConfigError(f"spectral.{key} must be numeric or null")

    flag_mode = settings.get("flag_mode", "or")
    if not isinstance(flag_mode, str) or not flag_mode.strip():
        raise ConfigError(
            "spectral.flag_mode must be one of "
            f"{sorted(KNOWN_SPECTRAL_FLAG_MODES)}"
        )
    normalized = flag_mode.strip().lower()
    if normalized not in KNOWN_SPECTRAL_FLAG_MODES:
        raise ConfigError(
            f"spectral.flag_mode must be one of {sorted(KNOWN_SPECTRAL_FLAG_MODES)}, "
            f"got {flag_mode!r}"
        )
    settings["flag_mode"] = normalized

    discount = settings.get("discount_last_window", False)
    if not isinstance(discount, bool):
        raise ConfigError("spectral.discount_last_window must be a boolean")
    settings["discount_last_window"] = discount


def _validate_spectral_fft_settings(settings: dict[str, Any]) -> None:
    raw_window = settings.get("window", DEFAULT_FFT_WINDOW)
    if not isinstance(raw_window, str) or not raw_window.strip():
        raise ConfigError(
            "spectral.window must be a non-empty string "
            f"(one of {sorted(ALLOWED_FFT_WINDOWS)})"
        )
    window = raw_window.strip().lower()
    if window not in ALLOWED_FFT_WINDOWS:
        raise ConfigError(
            f"spectral.window must be one of {sorted(ALLOWED_FFT_WINDOWS)}, "
            f"got {raw_window!r}"
        )
    settings["window"] = window

    min_length = settings.get("min_welch_length", MIN_WELCH_LENGTH)
    try:
        min_length_int = int(min_length)
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            "spectral.min_welch_length must be an integer >= 2"
        ) from exc
    if isinstance(min_length, bool) or min_length_int < 2:
        raise ConfigError("spectral.min_welch_length must be an integer >= 2")
    settings["min_welch_length"] = min_length_int


def spectral_cluster_min_entities(config: dict[str, Any]) -> int:
    """Return spectral.cluster_min_entities with default 20."""
    block = config.get("spectral") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'spectral' must be a mapping")
    return _validate_spectral_cluster_min_entities(
        block.get("cluster_min_entities", DEFAULT_SPECTRAL_CLUSTER_MIN_ENTITIES)
    )


def _validate_spectral_cluster_min_entities(value: Any) -> int:
    try:
        minimum = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            "spectral.cluster_min_entities must be a positive integer"
        ) from exc
    if isinstance(value, bool) or minimum < 1:
        raise ConfigError("spectral.cluster_min_entities must be a positive integer")
    return minimum


def spectral_max_buckets_per_entity(config: dict[str, Any]) -> int:
    """Return spectral.max_buckets_per_entity (STFT memory cap)."""
    block = config.get("spectral") or {}
    if not isinstance(block, dict):
        raise ConfigError("Config 'spectral' must be a mapping")
    return _validate_spectral_max_buckets(
        block.get("max_buckets_per_entity", DEFAULT_SPECTRAL_MAX_BUCKETS_PER_ENTITY)
    )


def _validate_spectral_max_buckets(value: Any) -> int:
    try:
        maximum = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            "spectral.max_buckets_per_entity must be a positive integer"
        ) from exc
    if isinstance(value, bool) or maximum < 1:
        raise ConfigError("spectral.max_buckets_per_entity must be a positive integer")
    return maximum


def ensure_data_directories(config: dict[str, Any]) -> None:
    """Create configured data directories if missing.

    Creates `data/raw/` empty if needed but never writes log content into it.
    Also ensures the parent directory of `db_path` exists.
    """
    paths = config["paths"]
    directory_keys = (
        "raw_log_dir",
        "parsed_dir",
        "timeseries_dir",
        "baseline_dir",
        "scores_dir",
        "report_dir",
        "analyses_dir",
    )
    for key in directory_keys:
        value = paths.get(key)
        if key == "analyses_dir" and (not isinstance(value, str) or not value.strip()):
            value = DEFAULT_ANALYSES_DIR
            paths["analyses_dir"] = value
        Path(value).mkdir(parents=True, exist_ok=True)

    Path(paths["db_path"]).parent.mkdir(parents=True, exist_ok=True)
    ui = config.get("pipeline_ui") or {}
    upload_dir = ui.get("upload_dir") if isinstance(ui, dict) else None
    if isinstance(upload_dir, str) and upload_dir.strip():
        Path(upload_dir.strip()).mkdir(parents=True, exist_ok=True)
    else:
        Path(DEFAULT_PIPELINE_UI["upload_dir"]).mkdir(parents=True, exist_ok=True)

    normalize_block = config.get("normalize") or {}
    if isinstance(normalize_block, dict):
        out = normalize_block.get("output_dir", DEFAULT_NORMALIZE["output_dir"])
    else:
        out = DEFAULT_NORMALIZE["output_dir"]
    if isinstance(out, str) and out.strip():
        output_path = Path(out.strip())
        output_path.mkdir(parents=True, exist_ok=True)
        (output_path.parent / "normalize_dead_letter").mkdir(parents=True, exist_ok=True)
    else:
        Path(str(DEFAULT_NORMALIZE["output_dir"])).mkdir(parents=True, exist_ok=True)
        Path("data/raw/normalize_dead_letter").mkdir(parents=True, exist_ok=True)

    sharding_block = config.get("sharding") or {}
    if isinstance(sharding_block, dict):
        shard_out = sharding_block.get("output_dir", DEFAULT_SHARDING["output_dir"])
    else:
        shard_out = DEFAULT_SHARDING["output_dir"]
    if isinstance(shard_out, str) and shard_out.strip():
        Path(shard_out.strip()).mkdir(parents=True, exist_ok=True)
    else:
        Path(str(DEFAULT_SHARDING["output_dir"])).mkdir(parents=True, exist_ok=True)
