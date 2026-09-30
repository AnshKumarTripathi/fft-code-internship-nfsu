"""Pre-ingest normalize stage (Phase 80) — archives → text/JSON under normalized/."""

from src.normalize.persist import run_normalize

__all__ = ["run_normalize"]
