"""Allow `python -m src` to delegate to the pipeline CLI."""

from __future__ import annotations

import sys

from src.pipeline import main

if __name__ == "__main__":
    sys.exit(main())
