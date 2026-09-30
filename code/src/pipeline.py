"""CLI entrypoint for the log anomaly detection pipeline.

Usage (from the `code/` project root):
    python -m src.pipeline <subcommand> --config config/pipeline.yaml

Phase 9: full detection → correlation → report path is implemented.
``run-all`` soft-skips cluster when no spectral features, correlate when no
flagged sources (``NothingToCorrelate``), and report when no incidents.
Other ``CorrelationError`` values (invalid config, logic) fail the correlate stage.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from src.db.writer_lock import WarehouseBusyError
from src.config import ConfigError, load_config, orchestration_settings, sharding_settings
from src.correlation.merge_scores import CorrelationError, NothingToCorrelate
from src.correlation.persist import run_correlate
from src.detectors.changepoint.persist import ChangepointError, run_detect_changepoint
from src.detectors.seasonal.persist import SeasonalError, run_detect_seasonal
from src.detectors.ml.onnx_scorer import ModelNotConfiguredError
from src.detectors.ml.persist import MlError, run_detect_ml
from src.detectors.spectral.persist import (
    ClusterError,
    NothingToCluster,
    SpectralError,
    run_cluster,
    run_detect_spectral,
)
from src.detectors.statistical.persist import StatisticalError, run_detect_statistical
from src.evaluation.persist import EvaluationError, run_evaluate
from src.ingestion.persist import run_ingest
from src.ingestion.sharding.split import ShardError, split_log_file
from src.ingestion.sharding.orchestrate import run_sharded_pipeline
from src.normalize.persist import run_normalize
from src.parsing.persist import run_parse
from src.reporting.persist import run_report
from src.reporting.report_generator import NothingToReport, ReportingError
from src.timeseries.persist import BucketError, run_bucket# Exit code for intentionally unimplemented stage handlers.
EXIT_NOT_IMPLEMENTED = 2

# stage, status (running|success|skipped|failed), optional detail
StageProgressCallback = Callable[[str, str, str | None], None]

STAGE_PHASE: dict[str, int] = {
    "normalize": 80,
    "ingest": 2,
    "parse": 3,
    "bucket": 4,
    "detect-statistical": 5,
    "detect-spectral": 6,
    "cluster": 6,
    "detect-ml": 7,
    "detect-changepoint": 52,
    "detect-seasonal": 61,
    "correlate": 8,
    "report": 9,
}

STAGE_ORDER: tuple[str, ...] = (
    "normalize",
    "ingest",
    "parse",
    "bucket",
    "detect-statistical",
    "detect-spectral",
    "cluster",
    "detect-ml",
    "detect-changepoint",
    "detect-seasonal",
    "correlate",
    "report",
)


class NotImplementedStage(Exception):
    """Raised when a pipeline stage has not been implemented yet."""

    def __init__(self, stage: str) -> None:
        self.stage = stage
        phase = STAGE_PHASE[stage]
        super().__init__(
            f"Stage '{stage}' is not implemented yet (planned in Phase {phase})."
        )


def _stub_stage(stage: str) -> Callable[[dict[str, Any], str | None], None]:
    def handler(config: dict[str, Any], config_path: str | None = None) -> None:
        _ = config, config_path
        raise NotImplementedStage(stage)

    handler.__name__ = f"run_{stage.replace('-', '_')}"
    return handler


def _run_normalize_stage(config: dict[str, Any], config_path: str | None = None) -> None:
    run_normalize(config, config_path=config_path)


def _run_ingest_stage(config: dict[str, Any], config_path: str | None = None) -> None:
    run_ingest(config, config_path=config_path)


def _run_parse_stage(config: dict[str, Any], config_path: str | None = None) -> None:
    run_parse(config, config_path=config_path)


def _run_bucket_stage(config: dict[str, Any], config_path: str | None = None) -> None:
    run_bucket(config, config_path=config_path)


def _run_detect_statistical_stage(
    config: dict[str, Any], config_path: str | None = None
) -> None:
    run_detect_statistical(config, config_path=config_path)


def _run_detect_spectral_stage(
    config: dict[str, Any], config_path: str | None = None
) -> None:
    run_detect_spectral(config, config_path=config_path)


def _run_cluster_stage(config: dict[str, Any], config_path: str | None = None) -> None:
    run_cluster(config, config_path=config_path)


def _run_detect_ml_stage(
    config: dict[str, Any], config_path: str | None = None
) -> None:
    run_detect_ml(config, config_path=config_path)


def _run_detect_changepoint_stage(
    config: dict[str, Any], config_path: str | None = None
) -> None:
    run_detect_changepoint(config, config_path=config_path)


def _run_detect_seasonal_stage(
    config: dict[str, Any], config_path: str | None = None
) -> None:
    run_detect_seasonal(config, config_path=config_path)


def _run_correlate_stage(
    config: dict[str, Any], config_path: str | None = None
) -> None:
    run_correlate(config, config_path=config_path)


def _run_report_stage(config: dict[str, Any], config_path: str | None = None) -> None:
    run_report(config, config_path=config_path)


def _run_evaluate_stage(
    config: dict[str, Any],
    config_path: str | None = None,
    *,
    cold_start_synthetic: bool = False,
) -> None:
    run_evaluate(
        config,
        config_path=config_path,
        cold_start_synthetic=cold_start_synthetic,
    )


STAGE_HANDLERS: dict[str, Callable[[dict[str, Any], str | None], None]] = {
    stage: _stub_stage(stage) for stage in STAGE_ORDER
}
STAGE_HANDLERS["normalize"] = _run_normalize_stage
STAGE_HANDLERS["ingest"] = _run_ingest_stage
STAGE_HANDLERS["parse"] = _run_parse_stage
STAGE_HANDLERS["bucket"] = _run_bucket_stage
STAGE_HANDLERS["detect-statistical"] = _run_detect_statistical_stage
STAGE_HANDLERS["detect-spectral"] = _run_detect_spectral_stage
STAGE_HANDLERS["cluster"] = _run_cluster_stage
STAGE_HANDLERS["detect-ml"] = _run_detect_ml_stage
STAGE_HANDLERS["detect-changepoint"] = _run_detect_changepoint_stage
STAGE_HANDLERS["detect-seasonal"] = _run_detect_seasonal_stage
STAGE_HANDLERS["correlate"] = _run_correlate_stage
STAGE_HANDLERS["report"] = _run_report_stage


def resolve_stage_list(stages: Sequence[str] | None) -> list[str]:
    """Return stages in ``STAGE_ORDER``, optionally filtered to an allow-list."""
    if stages is None:
        return list(STAGE_ORDER)
    requested = list(stages)
    unknown = [name for name in requested if name not in STAGE_ORDER]
    if unknown:
        raise ValueError(
            "Unknown stage(s): "
            + ", ".join(unknown)
            + f". Allowed: {', '.join(STAGE_ORDER)}"
        )
    allow = set(requested)
    return [name for name in STAGE_ORDER if name in allow]


def run_stages(
    config: dict[str, Any],
    config_path: str | None = None,
    *,
    stages: Sequence[str] | None = None,
    require_complete: bool = False,
    on_stage: StageProgressCallback | None = None,
    emit_summary: bool = True,
) -> int:
    """Walk selected stages in order; soft-skip empty corpus cases; summarize.

    Soft-skips match CLI ``run-all`` (``NotImplementedStage``, ``NothingToCluster``,
    ``NothingToCorrelate``, ``NothingToReport``). Hard failures and warehouse busy
    mark the stage failed; busy also stops the remaining chain.
    """
    selected = resolve_stage_list(stages)
    ran: list[str] = []
    skipped: list[str] = []
    failed: list[str] = []
    settings = orchestration_settings(config)
    require = bool(require_complete) or bool(settings["run_all_require_complete"])

    def _notify(stage: str, status: str, detail: str | None = None) -> None:
        if on_stage is not None:
            on_stage(stage, status, detail)

    for stage in selected:
        handler = STAGE_HANDLERS[stage]
        _notify(stage, "running", None)
        try:
            handler(config, config_path)
            ran.append(stage)
            _notify(stage, "success", None)
        except NotImplementedStage as exc:
            detail = str(exc)
            print(f"WARNING: {exc} Skipping.", file=sys.stderr, flush=True)
            skipped.append(stage)
            _notify(stage, "skipped", detail)
        except NothingToCluster as exc:
            detail = str(exc)
            print(
                f"WARNING: stage 'cluster' skipped: {exc}",
                file=sys.stderr,
                flush=True,
            )
            skipped.append(stage)
            _notify(stage, "skipped", detail)
        except NothingToCorrelate as exc:
            detail = str(exc)
            print(
                f"WARNING: stage 'correlate' skipped: {exc}",
                file=sys.stderr,
                flush=True,
            )
            skipped.append(stage)
            _notify(stage, "skipped", detail)
        except CorrelationError as exc:
            detail = str(exc)
            print(
                f"ERROR: stage 'correlate' failed: {exc}",
                file=sys.stderr,
                flush=True,
            )
            failed.append(stage)
            _notify(stage, "failed", detail)
        except NothingToReport as exc:
            detail = str(exc)
            print(
                f"WARNING: stage 'report' skipped: {exc}",
                file=sys.stderr,
                flush=True,
            )
            skipped.append(stage)
            _notify(stage, "skipped", detail)
        except WarehouseBusyError as exc:
            detail = str(exc)
            print(f"ERROR: warehouse busy: {exc}", file=sys.stderr, flush=True)
            failed.append(stage)
            _notify(stage, "failed", detail)
            break
        except Exception as exc:  # noqa: BLE001 — surface unexpected stage failures
            detail = str(exc)
            print(f"ERROR: stage '{stage}' failed: {exc}", file=sys.stderr, flush=True)
            failed.append(stage)
            _notify(stage, "failed", detail)

    if emit_summary:
        print("\nrun-all summary", flush=True)
        print(f"  ran:     {', '.join(ran) if ran else '(none)'}", flush=True)
        print(f"  skipped: {', '.join(skipped) if skipped else '(none)'}", flush=True)
        print(f"  failed:  {', '.join(failed) if failed else '(none)'}", flush=True)

    if failed:
        return 1
    if require and skipped:
        if emit_summary:
            print(
                "require-complete: skipped stages treated as failure: "
                + ", ".join(skipped),
                flush=True,
            )
        return 1
    return 0


def run_all(
    config: dict[str, Any],
    config_path: str | None = None,
    *,
    require_complete: bool = False,
) -> int:
    """Walk all stages in order; run implemented, skip soft failures; summarize."""
    return run_stages(
        config,
        config_path=config_path,
        require_complete=require_complete,
    )


def run_shard_split(
    config: dict[str, Any],
    *,
    input_path: str | Path,
    run_id: str | None = None,
    target_shard_bytes: int | None = None,
    target_shard_lines: int | None = None,
) -> int:
    """Split one on-disk log into line-safe shards; does not start detectors."""
    settings = sharding_settings(config)
    bytes_target = (
        target_shard_bytes
        if target_shard_bytes is not None
        else settings["target_shard_bytes"]
    )
    lines_target = (
        target_shard_lines
        if target_shard_lines is not None
        else settings["target_shard_lines"]
    )
    result = split_log_file(
        input_path,
        output_dir=settings["output_dir"],
        target_shard_bytes=bytes_target,
        target_shard_lines=lines_target,
        max_shards=int(settings["max_shards"]),
        run_id=run_id,
    )
    print(
        f"shard-split: run_id={result.run_id} shards={result.shard_count} "
        f"manifest={result.manifest_path}",
        flush=True,
    )
    for record in result.records:
        print(
            f"  shard[{record.shard_index}] bytes={record.byte_start}.."
            f"{record.byte_end} lines={record.line_start}..{record.line_end} "
            f"path={record.shard_path}",
            flush=True,
        )
    return 0


def run_sharded(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
    through: str = "report",
    manifest_path: str | Path | None = None,
    input_path: str | Path | None = None,
    split_run_id: str | None = None,
    require_complete: bool = False,
) -> int:
    """Sharded corpus orchestration (Phases 89–90)."""
    result = run_sharded_pipeline(
        config,
        config_path=config_path,
        through=through,
        manifest_path=manifest_path,
        input_path=input_path,
        split_run_id=split_run_id,
        require_complete=require_complete,
    )
    if through == "report" and result.post_merge_exit_code is not None:
        return int(result.post_merge_exit_code)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.pipeline",
        description="Log anomaly detection pipeline (Phase 9: through report live).",
    )
    # Shared so `--config` works before or after the subcommand (SDD §9).
    config_parent = argparse.ArgumentParser(add_help=False)
    config_parent.add_argument(
        "--config",
        default="config/pipeline.yaml",
        help="Path to pipeline YAML (default: config/pipeline.yaml)",
    )
    parser.add_argument(
        "--config",
        default="config/pipeline.yaml",
        help="Path to pipeline YAML (default: config/pipeline.yaml)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for stage in STAGE_ORDER:
        subparsers.add_parser(
            stage,
            parents=[config_parent],
            help=f"Run the {stage} stage",
        )

    run_all_parser = subparsers.add_parser(
        "run-all",
        parents=[config_parent],
        help="Run all stages in order (skip soft failures)",
    )
    run_all_parser.add_argument(
        "--require",
        choices=["complete"],
        default=None,
        help="Treat skipped stages as failure (same as orchestration.run_all_require_complete)",
    )
    evaluate_parser = subparsers.add_parser(
        "evaluate",
        parents=[config_parent],
        help="Score warehouse detections against a labels file (not part of run-all)",
    )
    evaluate_parser.add_argument(
        "--cold-start-synthetic",
        action="store_true",
        help="Append a synthetic spectral 1d/3d/7d/14d cold-start table to the report",
    )
    shard_split_parser = subparsers.add_parser(
        "shard-split",
        parents=[config_parent],
        help="Split one on-disk log into line-safe shards + manifest (Phase 88)",
    )
    shard_split_parser.add_argument(
        "--input",
        required=True,
        help="Path to the oversized text log on disk",
    )
    shard_split_parser.add_argument(
        "--run-id",
        default=None,
        help="Optional split run id (default: random hex); output under sharding.output_dir",
    )
    shard_split_parser.add_argument(
        "--target-bytes",
        type=int,
        default=None,
        help="Override sharding.target_shard_bytes for this run",
    )
    shard_split_parser.add_argument(
        "--target-lines",
        type=int,
        default=None,
        help="Override sharding.target_shard_lines for this run",
    )
    run_sharded_parser = subparsers.add_parser(
        "run-sharded",
        parents=[config_parent],
        help="Shard ingest/parse then one post-merge detect chain (Phases 89–90)",
    )
    run_sharded_parser.add_argument(
        "--through",
        choices=["parse", "report"],
        default="report",
        help="Stop after parse (debug) or run post-merge bucket→…→report (default)",
    )
    run_sharded_parser.add_argument(
        "--input",
        default=None,
        help="Large on-disk log to shard-split then ingest/parse",
    )
    run_sharded_parser.add_argument(
        "--manifest",
        default=None,
        help="Existing Phase 88 manifest.jsonl (skips split)",
    )
    run_sharded_parser.add_argument(
        "--run-id",
        default=None,
        help="Existing split run id under sharding.output_dir",
    )
    run_sharded_parser.add_argument(
        "--require",
        choices=["complete"],
        default=None,
        help="Treat post-merge soft-skips as failure (same as run-all)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 1

    if args.command == "run-all":
        return run_all(
            config,
            config_path=args.config,
            require_complete=getattr(args, "require", None) == "complete",
        )

    if args.command == "evaluate":
        try:
            _run_evaluate_stage(
                config,
                args.config,
                cold_start_synthetic=bool(
                    getattr(args, "cold_start_synthetic", False)
                ),
            )
        except EvaluationError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print(f"Stage 'evaluate' failed: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.command == "shard-split":
        try:
            return run_shard_split(
                config,
                input_path=args.input,
                run_id=getattr(args, "run_id", None),
                target_shard_bytes=getattr(args, "target_bytes", None),
                target_shard_lines=getattr(args, "target_lines", None),
            )
        except ShardError as exc:
            print(f"shard-split failed: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print(f"shard-split failed: {exc}", file=sys.stderr)
            return 1

    if args.command == "run-sharded":
        try:
            return run_sharded(
                config,
                config_path=args.config,
                through=getattr(args, "through", "report"),
                manifest_path=getattr(args, "manifest", None),
                input_path=getattr(args, "input", None),
                split_run_id=getattr(args, "run_id", None),
                require_complete=getattr(args, "require", None) == "complete",
            )
        except ShardError as exc:
            print(f"run-sharded failed: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print(f"run-sharded failed: {exc}", file=sys.stderr)
            return 1

    handler = STAGE_HANDLERS[args.command]
    try:
        handler(config, args.config)
    except NotImplementedStage as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_NOT_IMPLEMENTED
    except BucketError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except StatisticalError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except SpectralError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ClusterError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except NothingToCluster as exc:
        # Empty spectral features is a successful no-op for direct CLI.
        print(str(exc), flush=True)
        return 0
    except MlError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ChangepointError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except SeasonalError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ModelNotConfiguredError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except CorrelationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ReportingError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except NothingToReport as exc:
        # Empty incidents is a successful no-op for direct CLI.
        print(str(exc), flush=True)
        return 0
    except WarehouseBusyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"Stage '{args.command}' failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
