"""run-all fails real CorrelationError; skips only NothingToCorrelate."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from src import pipeline
from src.db.connection import get_connection

CODE_ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "src.pipeline", *args],
        cwd=cwd or CODE_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_isolated_yaml(tmp_path: Path, *, session_gap_minutes: int) -> Path:
    data = tmp_path / "data"
    raw = data / "raw"
    raw.mkdir(parents=True)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(CODE_ROOT / "config" / "drain3.ini", config_dir / "drain3.ini")
    config_path = config_dir / "pipeline.yaml"
    config_path.write_text(
        "\n".join(
            [
                "paths:",
                f"  raw_log_dir: {raw.as_posix()}/",
                f"  parsed_dir: {(data / 'parsed').as_posix()}/",
                f"  timeseries_dir: {(data / 'timeseries').as_posix()}/",
                f"  baseline_dir: {(data / 'baselines').as_posix()}/",
                f"  scores_dir: {(data / 'scores').as_posix()}/",
                f"  report_dir: {(data / 'reports').as_posix()}/",
                f"  db_path: {(data / 'warehouse.duckdb').as_posix()}",
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
                f"  session_gap_minutes: {session_gap_minutes}",
                "  same_ip_link: true",
                "  same_host_link: true",
                "reporting:",
                "  template_path: src/reporting/templates/incident_report.md.j2",
                "  use_llm_narrative: false",
                "  llm_model: qwen3-coder:30b",
                "orchestration:",
                "  parallel_backend: dask",
                "  n_workers: 8",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config_path


def _full_config(tmp_path: Path) -> dict:
    data = tmp_path / "data"
    data.mkdir(parents=True)
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
        "orchestration": {"parallel_backend": "dask", "n_workers": 8},
    }


def _summary_line(text: str, label: str) -> str:
    for line in text.splitlines():
        if line.strip().startswith(f"{label}:"):
            return line
    raise AssertionError(f"missing {label!r} summary line in:\n{text}")


def test_run_all_invalid_session_gap_fails_correlate(tmp_path: Path) -> None:
    config_path = _write_isolated_yaml(tmp_path, session_gap_minutes=-1)
    result = _run("run-all", "--config", str(config_path), cwd=CODE_ROOT)
    assert result.returncode != 0, result.stderr + result.stdout
    combined = result.stdout + result.stderr
    assert "correlate" in _summary_line(combined, "failed")
    assert "stage 'correlate' failed" in result.stderr


def test_run_all_require_complete_cli_flag() -> None:
    parser = pipeline.build_parser()
    args = parser.parse_args(["run-all", "--require", "complete"])
    assert args.require == "complete"


def test_run_all_empty_sources_skips_correlate(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    config = _full_config(tmp_path)
    get_connection(config).close()

    def ok(_config: dict, _path: str | None = None) -> None:
        return None

    for stage in pipeline.STAGE_ORDER:
        if stage != "correlate":
            monkeypatch.setitem(pipeline.STAGE_HANDLERS, stage, ok)

    rc = pipeline.run_all(config, config_path=None)
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert rc == 0
    assert "correlate" in _summary_line(combined, "skipped")
    assert "(none)" in _summary_line(combined, "failed")


def test_run_all_require_complete_treats_skip_as_failure(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    config = _full_config(tmp_path)
    get_connection(config).close()

    def ok(_config: dict, _path: str | None = None) -> None:
        return None

    for stage in pipeline.STAGE_ORDER:
        if stage != "correlate":
            monkeypatch.setitem(pipeline.STAGE_HANDLERS, stage, ok)

    rc = pipeline.run_all(config, config_path=None, require_complete=True)
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert rc != 0
    assert "require-complete" in combined
    assert "correlate" in combined


def test_run_all_require_complete_yaml(tmp_path: Path, capsys, monkeypatch) -> None:
    config = _full_config(tmp_path)
    config["orchestration"]["run_all_require_complete"] = True
    get_connection(config).close()

    def ok(_config: dict, _path: str | None = None) -> None:
        return None

    for stage in pipeline.STAGE_ORDER:
        if stage != "report":
            monkeypatch.setitem(pipeline.STAGE_HANDLERS, stage, ok)

    rc = pipeline.run_all(config, config_path=None)
    captured = capsys.readouterr()
    assert rc != 0
    assert "require-complete" in captured.out + captured.err

