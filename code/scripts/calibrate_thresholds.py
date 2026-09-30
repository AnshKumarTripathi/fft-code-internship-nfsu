"""Sweep detector cutoffs against labels using stored window scores (Phase 50).

From the ``code/`` directory::

    python scripts/calibrate_thresholds.py --config config/pipeline.yaml
    python scripts/calibrate_thresholds.py --config config/pipeline.yaml \\
        --labels tests/fixtures/labels/demo_eval.csv

Writes ``data/reports/eval/calibration.json`` and ``calibration.md`` (or
``evaluation.output_dir``). Does not re-run detectors and does not change YAML.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[1]
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from src.config import load_config  # noqa: E402
from src.evaluation.calibrate import DEFAULT_TAUS, run_calibration  # noqa: E402
from src.evaluation.labels import EvaluationError  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Phase 50: recompute flags from stored scores across τ grid; "
            "write calibration.json + calibration.md"
        )
    )
    parser.add_argument(
        "--config",
        default="config/pipeline.yaml",
        help="Path to pipeline.yaml (default: config/pipeline.yaml)",
    )
    parser.add_argument(
        "--labels",
        default=None,
        help=(
            "Labels CSV/Parquet (default: evaluation.labels_path or "
            "tests/fixtures/labels/demo_eval.csv)"
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Override evaluation.output_dir for calibration artifacts",
    )
    parser.add_argument(
        "--taus",
        default=None,
        help="Comma-separated cutoffs (default: 3.0,3.5,4.0,4.5,5.0)",
    )
    args = parser.parse_args(argv)

    config_path = Path(args.config)
    if not config_path.is_file():
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1

    try:
        config = load_config(config_path)
        taus = DEFAULT_TAUS
        if args.taus:
            taus = tuple(float(part.strip()) for part in args.taus.split(",") if part.strip())
            if not taus:
                raise EvaluationError("--taus must list at least one number")
        summary = run_calibration(
            config,
            config_path=str(config_path),
            labels_path=args.labels,
            taus=taus,
            output_dir=args.output_dir,
        )
    except (EvaluationError, ValueError, OSError) as exc:
        print(f"calibrate_thresholds failed: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote {summary.output_json_path}")
    print(f"Wrote {summary.output_md_path}")
    print(f"Decision: {summary.decision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
