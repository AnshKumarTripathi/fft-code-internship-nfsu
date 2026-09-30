"""Unit tests for optional Ollama narrative layer."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.reporting.narrative_llm import (
    NarrativeLlmError,
    build_incident_brief,
    summarize_incident,
)


def test_build_incident_brief_truncates_timeline() -> None:
    context = {
        "incident": {
            "incident_id": "inc-1",
            "severity": "high",
            "start_time": "t0",
            "end_time": "t1",
            "summary_text": "stub",
        },
        "entity": {"entity_id": "alice", "entity_type": "user"},
        "anomalies": [{"source_detector": "ml", "score": 0.9, "metadata": {}}],
        "timeline": [
            {"event_timestamp": f"t{i}", "relation_type": "precedes", "snippet": "x"}
            for i in range(50)
        ],
    }
    brief = build_incident_brief(context)
    assert len(brief["timeline"]) == 20
    assert brief["incident_id"] == "inc-1"


def test_summarize_retries_then_raises() -> None:
    context = {
        "incident": {"incident_id": "inc-1", "severity": "low"},
        "entity": {"entity_id": "alice"},
        "anomalies": [],
        "timeline": [],
    }
    with patch(
        "src.reporting.narrative_llm._call_ollama",
        side_effect=NarrativeLlmError("down"),
    ) as mock_call:
        with pytest.raises(NarrativeLlmError, match="failed after retry"):
            summarize_incident(context, model="test-model")
        assert mock_call.call_count == 2


def test_summarize_success() -> None:
    context = {
        "incident": {"incident_id": "inc-1", "severity": "low"},
        "entity": {"entity_id": "alice"},
        "anomalies": [],
        "timeline": [],
    }
    with patch(
        "src.reporting.narrative_llm._call_ollama",
        return_value="Analyst prose here.",
    ):
        text = summarize_incident(context, model="test-model")
    assert text == "Analyst prose here."


def test_call_ollama_uses_urllib_when_invoked() -> None:
    """Ensure network path is mockable via urllib.request.urlopen."""
    fake_response = MagicMock()
    fake_response.read.return_value = b'{"response": "ok narrative"}'
    fake_response.__enter__.return_value = fake_response
    fake_response.__exit__.return_value = False

    with patch("urllib.request.urlopen", return_value=fake_response) as mock_open:
        text = summarize_incident(
            {
                "incident": {"incident_id": "i", "severity": "low"},
                "entity": {},
                "anomalies": [],
                "timeline": [],
            },
            model="m",
        )
    assert text == "ok narrative"
    assert mock_open.called
    request = mock_open.call_args[0][0]
    payload = json.loads(request.data.decode("utf-8"))
    assert payload["options"]["temperature"] == 0
    assert payload["options"]["seed"] == 42
