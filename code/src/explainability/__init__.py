"""R7 structured flag explanations for the API and deterministic reports."""

from src.explainability.payload import (
    ExplainMergeSettings,
    explanation_from_anomaly,
    spectral_crossing_legs,
    uncertainty_band,
)
from src.explainability.playbooks import DEFAULT_PLAYBOOKS, load_playbooks, playbook_for

__all__ = [
    "DEFAULT_PLAYBOOKS",
    "ExplainMergeSettings",
    "explanation_from_anomaly",
    "load_playbooks",
    "playbook_for",
    "spectral_crossing_legs",
    "uncertainty_band",
]
