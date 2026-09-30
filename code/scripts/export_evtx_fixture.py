#!/usr/bin/env python3
"""Optional helper: document / fetch the Phase 81 EVTX fixture.

Does not export live host Event Logs into the repo (avoid capturing local activity).
Default action downloads the public python-evtx ``issue_38.evtx`` sample.
"""

from __future__ import annotations

import argparse
import urllib.request
from pathlib import Path

DEFAULT_URL = (
    "https://raw.githubusercontent.com/williballenthin/python-evtx/"
    "master/tests/data/issue_38.evtx"
)
DEFAULT_OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "normalize" / "sample_security.evtx"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {args.url} -> {args.out}")
    urllib.request.urlretrieve(args.url, args.out)
    print(f"Wrote {args.out.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
