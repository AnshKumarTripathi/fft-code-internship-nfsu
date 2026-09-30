"""Phase 18: exploratory notebook is committed (D19)."""

from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[1]


def test_exploratory_notebook_exists() -> None:
    path = CODE_ROOT / "notebooks" / "exploratory_analysis.ipynb"
    assert path.is_file(), f"missing notebook: {path}"
