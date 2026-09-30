"""Optional local Ollama narrative layer over structured incident context (SDD §7.8)."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
DEFAULT_TIMEOUT_SECONDS = 30
BRIEF_TIMELINE_CAP = 20


class NarrativeLlmError(Exception):
    """Raised when the Ollama narrative call fails after retry."""


def build_incident_brief(context: dict[str, Any]) -> dict[str, Any]:
    """Compact structured slice for the LLM — never the raw corpus."""
    timeline = context.get("timeline") or []
    anomalies = context.get("anomalies") or []
    incident = context.get("incident") or {}
    entity = context.get("entity") or {}
    return {
        "incident_id": incident.get("incident_id"),
        "severity": incident.get("severity"),
        "entity_id": entity.get("entity_id") or incident.get("entity_id"),
        "entity_type": entity.get("entity_type"),
        "start_time": str(incident.get("start_time")),
        "end_time": str(incident.get("end_time")),
        "summary_text": incident.get("summary_text"),
        "anomalies": [
            {
                "source_detector": a.get("source_detector"),
                "score": a.get("score"),
                "window_start": str(a.get("window_start")),
                "window_end": str(a.get("window_end")),
                "metadata": a.get("metadata") or {},
            }
            for a in anomalies
        ],
        "timeline": [
            {
                "event_timestamp": str(row.get("event_timestamp")),
                "relation_type": row.get("relation_type"),
                "snippet": row.get("snippet"),
            }
            for row in timeline[:BRIEF_TIMELINE_CAP]
        ],
    }


def _call_ollama(
    prompt: str,
    *,
    model: str,
    timeout_seconds: float,
    url: str = OLLAMA_URL,
) -> str:
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0, "seed": 42},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8")
    data = json.loads(body)
    text = data.get("response")
    if not text or not str(text).strip():
        raise NarrativeLlmError("Ollama returned an empty response")
    return str(text).strip()


def summarize_incident(
    context: dict[str, Any],
    *,
    model: str,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    url: str = OLLAMA_URL,
) -> str:
    """Ask local Ollama for a short prose narrative; retry once on failure."""
    brief = build_incident_brief(context)
    prompt = (
        "You are a security analyst assistant. Write a short (3-6 sentence) "
        "narrative summarizing this log anomaly incident for an analyst. "
        "Use only the facts in the JSON. Do not invent IOCs or actions.\n\n"
        f"{json.dumps(brief, default=str)}"
    )
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            return _call_ollama(
                prompt, model=model, timeout_seconds=timeout_seconds, url=url
            )
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, json.JSONDecodeError, NarrativeLlmError) as exc:
            last_error = exc
            logger.warning(
                "Ollama narrative attempt %d failed: %s", attempt + 1, exc
            )
    raise NarrativeLlmError(
        f"Ollama narrative failed after retry: {last_error}"
    ) from last_error
