"""Import boundary tests for the spectral detector."""

from __future__ import annotations

import ast
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[1]
SPECTRAL_DIR = CODE_ROOT / "src" / "detectors" / "spectral"

FORBIDDEN_IMPORT_PREFIXES = (
    "src.detectors.statistical",
    "src.detectors.ml",
)


def _collect_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)
    return imports


def test_spectral_modules_do_not_import_statistical_or_ml() -> None:
    for path in SPECTRAL_DIR.glob("*.py"):
        imports = _collect_imports(path)
        for forbidden in FORBIDDEN_IMPORT_PREFIXES:
            assert not any(
                imp == forbidden or imp.startswith(f"{forbidden}.") for imp in imports
            ), f"{path.name} imports forbidden module {forbidden!r}"
