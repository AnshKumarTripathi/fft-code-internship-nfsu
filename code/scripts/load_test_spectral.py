"""Manual STFT load test (R6). Not a CI pass/fail gate.

From the ``code/`` directory::

    python scripts/load_test_spectral.py --baseline-buckets 4320 --scale 10

Times ``compute_entity_spectral`` on a synthetic count series. ``--scale 10``
is a 10× bucket count versus the baseline length. Peak RSS is reported when
the platform provides it (Unix ``resource``, or ``psutil`` if installed).
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[1]
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from src.detectors.spectral.persist import SpectralEntityWork, compute_entity_spectral


def _peak_rss_bytes() -> int | None:
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return int(usage)
        return int(usage) * 1024
    except (ImportError, OSError, AttributeError):
        pass
    try:
        import psutil

        return int(psutil.Process().memory_info().rss)
    except Exception:
        return None


def _series(n_buckets: int, bucket_seconds: int) -> SpectralEntityWork:
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    starts = tuple(
        start + timedelta(seconds=i * bucket_seconds) for i in range(n_buckets)
    )
    period = max(1, (24 * 3600) // bucket_seconds)
    counts = tuple(float(3 + (i % period == 0)) for i in range(n_buckets))
    window_buckets = max(4, (72 * 3600) // bucket_seconds)
    return SpectralEntityWork(
        entity_id="loadtest",
        bucket_starts=starts,
        event_counts=counts,
        bucket_seconds=bucket_seconds,
        window_buckets=window_buckets,
        step_buckets=max(1, window_buckets // 3),
        z_threshold=4.0,
        baseline_max_nperseg=1440,
        fft_window="hann",
        min_welch_length=4,
        max_buckets_per_entity=10_000_000,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline-buckets",
        type=int,
        default=4320,
        help="Baseline series length (default 4320 = 30 days at 600 s)",
    )
    parser.add_argument(
        "--scale",
        type=float,
        default=10.0,
        help="Multiply baseline length (default 10 = 10× load)",
    )
    parser.add_argument("--bucket-seconds", type=int, default=600)
    args = parser.parse_args(argv)
    n_buckets = max(4, int(args.baseline_buckets * args.scale))
    work = _series(n_buckets, args.bucket_seconds)
    started = time.perf_counter()
    result = compute_entity_spectral(work)
    elapsed = time.perf_counter() - started
    rss = _peak_rss_bytes()
    print(f"buckets: {n_buckets}")
    print(f"scale: {args.scale}")
    print(f"elapsed_s: {elapsed:.3f}")
    if rss is None:
        print("peak_rss_bytes: (unavailable on this platform)")
    else:
        print(f"peak_rss_bytes: {rss}")
        print(f"peak_rss_mib: {rss / (1024 * 1024):.1f}")
    print(f"skip_reason: {result.skip_reason}")
    print(f"windows: {len(result.window_rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
