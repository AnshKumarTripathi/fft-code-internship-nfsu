"""R3: operator limitations catalogue exists; default thresholds stay 4.0."""

from __future__ import annotations

from pathlib import Path

from src.config import load_config, ml_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_ROOT = Path(__file__).resolve().parents[1]
LIMITATIONS = REPO_ROOT / "KNOWN_LIMITATIONS.md"
README = CODE_ROOT / "README.md"
PIPELINE_YAML = CODE_ROOT / "config" / "pipeline.yaml"


def test_known_limitations_file_covers_threshold_and_failures() -> None:
    assert LIMITATIONS.is_file(), "KNOWN_LIMITATIONS.md must live at the repo root"
    text = LIMITATIONS.read_text(encoding="utf-8")
    for needle in (
        "4.0 is a lab convention",
        "0.6745",
        "energy_z",
        "shape_js_z",
        "FDR",
        "Shift-work",
        "Bucket aliasing",
        "Drain3 drift",
        "Cold start",
        "Legitimate bursts",
        "STFT cap",
        "Schedule change vs beacon",
        "Harmonics vs",
        "argmax",
    ):
        assert needle in text, f"missing operator topic {needle!r}"


def test_readme_links_known_limitations() -> None:
    readme = README.read_text(encoding="utf-8")
    assert "KNOWN_LIMITATIONS.md" in readme
    assert "../KNOWN_LIMITATIONS.md" in readme


def test_default_thresholds_unchanged() -> None:
    config = load_config(PIPELINE_YAML)
    assert config["statistical"]["z_threshold"] == 4.0
    assert config["spectral"]["z_threshold"] == 4.0
    assert ml_settings(config)["mad_k"] == 4.0
