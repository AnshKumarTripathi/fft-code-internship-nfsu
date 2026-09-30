"""Phase 96 — Pocket Flow chat, allow-listed tools, mocked LLM."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from src.api.main import create_app
from src.copilot.docs_loader import load_docs_markdown
from src.copilot.flow import run_chat_turn
from src.copilot.settings import CopilotEnvSettings
from src.copilot.tools import ToolContext, ToolError, run_tool
from src.db.connection import get_connection

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from tests.test_api_dashboard import (  # noqa: E402
    _full_config,
    _seed_incident_warehouse,
    _write_config,
)


class _FakeProvider:
    def __init__(self) -> None:
        self.last_messages: list[dict[str, str]] | None = None

    def generate(
        self,
        messages_or_prompt: Any,
        *,
        model: str | None = None,
        timeout: float | None = None,
    ) -> str:
        self.last_messages = list(messages_or_prompt)
        # Prove attachments landed in the structured evidence system message.
        blob = "\n".join(
            str(item.get("content") or "")
            for item in self.last_messages
            if isinstance(item, dict)
        )
        if "Why flagged chip" in blob or "page selection" in blob.lower():
            return "Reply saw attachment context."
        if "incident_id" in blob:
            return "Reply grounded on incident brief."
        return "Generic assistive reply."


def _env() -> CopilotEnvSettings:
    return CopilotEnvSettings(
        enabled=True,
        provider="ollama",
        model="test-model",
        ollama_base_url="http://127.0.0.1:11434",
        openai_api_key=None,
        openai_base_url="https://api.openai.com/v1",
        gemini_api_key=None,
        gemini_base_url="https://generativelanguage.googleapis.com/v1beta",
        timeout_seconds=30.0,
    )


def _enable_copilot_yaml(config: dict[str, Any]) -> dict[str, Any]:
    config = dict(config)
    config["copilot"] = {
        "enabled": True,
        "max_attachment_chars": 4000,
        "max_timeline_events": 20,
        "ai_insight": {"enabled": False},
    }
    return config


def test_unknown_tool_refused() -> None:
    ctx = ToolContext(
        connection=None,
        config={},
        report_dir=Path("."),
    )
    with pytest.raises(ToolError, match="unknown tool refused"):
        run_tool("drop_table", ctx)


def test_docs_section_loads_getting_started() -> None:
    payload = load_docs_markdown("getting-started", max_chars=2000)
    assert payload["slug"] == "getting-started"
    assert "Pipeline at a glance" in str(payload["markdown"])


def test_resolve_docs_slugs_for_project_question() -> None:
    from src.copilot.docs_loader import resolve_docs_slugs_for_query

    slugs = resolve_docs_slugs_for_query("EXPLAIN THE PROJECT")
    assert "getting-started" in slugs or "getting-started/what-this-is" in slugs


def test_to_plain_text_strips_markdown() -> None:
    from src.copilot.flow import _to_plain_text

    raw = (
        "### What It Is\n"
        "This is a **batch** lab.\n"
        "- Statistical: rate\n"
        "1. Normalize\n"
        "---\n"
        "See [Docs](/docs/getting-started)."
    )
    plain = _to_plain_text(raw)
    assert "###" not in plain
    assert "**" not in plain
    assert "- Statistical" not in plain
    assert "1. Normalize" not in plain
    assert "[" not in plain
    assert "batch" in plain
    assert "Statistical: rate" in plain
    assert "Docs" in plain


def test_flow_auto_fetches_docs_for_project_question(tmp_path: Path) -> None:
    config = _enable_copilot_yaml(_full_config(tmp_path))
    provider = _FakeProvider()
    result = run_chat_turn(
        messages=[{"role": "user", "content": "EXPLAIN THE PROJECT"}],
        incident_id=None,
        tool_context=ToolContext(
            connection=None,
            config=config,
            report_dir=Path(config["paths"]["report_dir"]),
        ),
        provider=provider,
        env_settings=_env(),
    )

    assert "get_docs_section" in result["tools_used"]
    docs = result["tool_results"]["get_docs_section"]
    assert isinstance(docs, list)
    assert docs
    assert all("error" not in row for row in docs if isinstance(row, dict))
    joined = "\n".join(str(row.get("markdown") or "") for row in docs if isinstance(row, dict))
    assert "batch" in joined.lower() or "pipeline" in joined.lower() or "anomaly" in joined.lower()
    assert any(c["source"] == "docs_section" for c in result["citations"])
    assert provider.last_messages is not None
    evidence = provider.last_messages[1]["content"]
    assert "get_docs_section" in evidence or "getting-started" in evidence


def test_flow_prefers_docs_over_incident_for_project_question(tmp_path: Path) -> None:
    config = _enable_copilot_yaml(_full_config(tmp_path))
    _seed_incident_warehouse(config)
    conn = get_connection(config)
    provider = _FakeProvider()
    try:
        result = run_chat_turn(
            messages=[{"role": "user", "content": "Explain the project"}],
            incident_id="inc-1",
            tool_context=ToolContext(
                connection=conn,
                config=config,
                report_dir=Path(config["paths"]["report_dir"]),
            ),
            provider=provider,
            env_settings=_env(),
        )
    finally:
        conn.close()

    assert "get_docs_section" in result["tools_used"]
    assert result["tools_used"][0] == "get_docs_section"
    assert any(c["source"] == "docs_section" for c in result["citations"])


def test_flow_packs_attachments_and_fetches_brief(tmp_path: Path) -> None:
    config = _enable_copilot_yaml(_full_config(tmp_path))
    _seed_incident_warehouse(config)
    conn = get_connection(config)
    provider = _FakeProvider()
    try:
        result = run_chat_turn(
            messages=[{"role": "user", "content": "Explain this simply"}],
            attachments=[
                {
                    "kind": "page_selection",
                    "route": "/incidents/inc-1/overview",
                    "label": "Why flagged chip",
                    "text": "page selection evidence",
                    "incident_id": "inc-1",
                }
            ],
            incident_id="inc-1",
            tool_context=ToolContext(
                connection=conn,
                config=config,
                report_dir=Path(config["paths"]["report_dir"]),
            ),
            provider=provider,
            env_settings=_env(),
        )
    finally:
        conn.close()

    assert "get_incident_brief" in result["tools_used"]
    assert result["brief"] is not None
    assert result["brief"]["incident_id"] == "inc-1"
    assert "attachment" in result["reply"].lower() or "Reply" in result["reply"]
    assert provider.last_messages is not None
    evidence = provider.last_messages[1]["content"]
    assert "Why flagged chip" in evidence
    assert "page selection evidence" in evidence


def test_flow_fetches_why_flagged_when_asked(tmp_path: Path) -> None:
    config = _enable_copilot_yaml(_full_config(tmp_path))
    _seed_incident_warehouse(config)
    conn = get_connection(config)
    provider = _FakeProvider()
    try:
        result = run_chat_turn(
            messages=[
                {
                    "role": "user",
                    "content": "Why was this flagged? Explain the playbook.",
                }
            ],
            incident_id="inc-1",
            tool_context=ToolContext(
                connection=conn,
                config=config,
                report_dir=Path(config["paths"]["report_dir"]),
            ),
            provider=provider,
            env_settings=_env(),
        )
    finally:
        conn.close()

    assert "get_incident_brief" in result["tools_used"]
    assert "get_why_flagged" in result["tools_used"]
    assert "get_why_flagged" in result["tool_results"]
    why = result["tool_results"]["get_why_flagged"]
    assert "error" not in why or why.get("why_flagged") is not None


def test_flow_fetches_report_when_asking_about_report(tmp_path: Path) -> None:
    config = _enable_copilot_yaml(_full_config(tmp_path))
    _seed_incident_warehouse(config)
    report_dir = Path(config["paths"]["report_dir"])
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "incident_inc-1.md").write_text(
        "# Incident Report\n\nSeverity: critical\n\n"
        "svc-api had rate and seasonal anomalies. Highest score 14.21.\n",
        encoding="utf-8",
    )
    conn = get_connection(config)
    provider = _FakeProvider()
    try:
        result = run_chat_turn(
            messages=[
                {
                    "role": "user",
                    "content": "Explain the report, what it states, and its finding. Why it is critical",
                }
            ],
            attachments=[
                {
                    "kind": "page_context",
                    "route": "/reports/incident_inc-1.html",
                    "incident_id": "inc-1",
                    "label": "Report: incident_inc-1.html",
                    "text": "Viewing report incident_inc-1.html",
                }
            ],
            incident_id="inc-1",
            tool_context=ToolContext(
                connection=conn,
                config=config,
                report_dir=report_dir,
            ),
            provider=provider,
            env_settings=_env(),
        )
    finally:
        conn.close()

    assert "get_incident_brief" in result["tools_used"]
    assert "get_report_excerpt" in result["tools_used"]
    report = result["tool_results"]["get_report_excerpt"]
    assert "error" not in report
    assert "critical" in str(report.get("excerpt") or "").lower()
    evidence = "\n".join(
        str(item.get("content") or "")
        for item in (provider.last_messages or [])
        if isinstance(item, dict)
    )
    assert "get_report_excerpt" in evidence or "Highest score" in evidence


def test_api_copilot_status_reports_dual_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COPILOT_ENABLED", "false")
    monkeypatch.setenv("COPILOT_PROVIDER", "ollama")
    monkeypatch.setenv("COPILOT_MODEL", "lab-model")
    config = _enable_copilot_yaml(_full_config(tmp_path))
    _seed_incident_warehouse(config)
    client = TestClient(create_app(_write_config(tmp_path, config)))
    response = client.get("/api/v1/copilot/status")
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False
    assert body["provider"] == "ollama"
    assert "reason" in body

    monkeypatch.setenv("COPILOT_ENABLED", "true")
    monkeypatch.setenv("COPILOT_PROVIDER", "ollama")
    monkeypatch.setenv("COPILOT_MODEL", "lab-model")
    enabled = client.get("/api/v1/copilot/status")
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True
    assert enabled.json()["model"] == "lab-model"
    assert enabled.json().get("reason") in (None, "")


def test_api_copilot_disabled_returns_503(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COPILOT_ENABLED", "false")
    config = _enable_copilot_yaml(_full_config(tmp_path))
    _seed_incident_warehouse(config)
    client = TestClient(create_app(_write_config(tmp_path, config)))
    response = client.post(
        "/api/v1/copilot/chat",
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 503
    assert "disabled" in response.json()["detail"].lower()


def test_api_copilot_chat_mocked_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COPILOT_ENABLED", "true")
    monkeypatch.setenv("COPILOT_PROVIDER", "ollama")
    monkeypatch.setenv("COPILOT_MODEL", "test-model")

    config = _enable_copilot_yaml(_full_config(tmp_path))
    _seed_incident_warehouse(config)
    client = TestClient(create_app(_write_config(tmp_path, config)))

    fake = _FakeProvider()

    def _fake_build(settings=None):  # noqa: ANN001
        return fake

    monkeypatch.setattr("src.api.routes.v1.copilot.build_provider", _fake_build)

    response = client.post(
        "/api/v1/copilot/chat",
        json={
            "messages": [{"role": "user", "content": "Explain this simply"}],
            "incident_id": "inc-1",
            "attachments": [
                {
                    "kind": "page_selection",
                    "route": "/incidents/inc-1",
                    "label": "Why flagged chip",
                    "text": "page selection evidence",
                }
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "ollama"
    assert body["model"] == "test-model"
    assert "get_incident_brief" in body["tools_used"]
    assert body["reply"]
    assert any(c["source"] == "incident_brief" for c in body["citations"])


def test_flow_ranks_entities_for_suspect_question(tmp_path: Path) -> None:
    from datetime import datetime, timezone

    config = _enable_copilot_yaml(_full_config(tmp_path))
    _seed_incident_warehouse(config)
    conn = get_connection(config)
    start = datetime(2024, 1, 2, 12, tzinfo=timezone.utc)
    end = datetime(2024, 1, 2, 13, tzinfo=timezone.utc)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
            VALUES ('bob', 'host', ?, ?, 'Bob')
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end, source_detector, score, metadata)
            VALUES
              ('anom-b1', 'bob', ?, ?, 'statistical', 9.0, '{}'::JSON),
              ('anom-b2', 'bob', ?, ?, 'seasonal', 8.0, '{}'::JSON),
              ('anom-b3', 'bob', ?, ?, 'changepoint', 7.0, '{}'::JSON)
            """,
            [start, end, start, end, start, end],
        )
        provider = _FakeProvider()
        result = run_chat_turn(
            messages=[
                {
                    "role": "user",
                    "content": "Which entity is the most suspect? which have most anomalies?",
                }
            ],
            attachments=[
                {
                    "kind": "page_context",
                    "route": "/entities",
                    "label": "Entities registry",
                    "text": "Viewing Entities registry",
                }
            ],
            incident_id=None,
            tool_context=ToolContext(
                connection=conn,
                config=config,
                report_dir=Path(config["paths"]["report_dir"]),
            ),
            provider=provider,
            env_settings=_env(),
        )
    finally:
        conn.close()

    assert "rank_entities_by_anomalies" in result["tools_used"]
    ranked = result["tool_results"]["rank_entities_by_anomalies"]
    assert "error" not in ranked
    entities = ranked["entities"]
    assert entities
    assert entities[0]["entity_id"] == "bob"
    assert entities[0]["anomaly_count"] >= 3
    assert any(c["source"] == "entity_ranking" for c in result["citations"])


def test_agent_decide_soft_fails_on_garbage_yaml(tmp_path: Path) -> None:
    config = _enable_copilot_yaml(_full_config(tmp_path))
    _seed_incident_warehouse(config)
    conn = get_connection(config)

    class _GarbageDecideProvider(_FakeProvider):
        def generate(self, messages_or_prompt, *, model=None, timeout=None):  # noqa: ANN001
            self.last_messages = list(messages_or_prompt)
            blob = "\n".join(
                str(item.get("content") or "")
                for item in self.last_messages
                if isinstance(item, dict)
            )
            if "pick the next assistive-copilot tool" in blob.lower() or "Allowed tools" in blob:
                return "definitely not yaml {{{"
            return "Final answer after soft-fail."

    provider = _GarbageDecideProvider()
    try:
        result = run_chat_turn(
            messages=[
                {
                    "role": "user",
                    "content": "Please rank the worst hosts in the lab",
                }
            ],
            incident_id=None,
            tool_context=ToolContext(
                connection=conn,
                config=config,
                report_dir=Path(config["paths"]["report_dir"]),
            ),
            provider=provider,
            env_settings=_env(),
        )
    finally:
        conn.close()

    assert result["reply"]
    assert "error" not in result["reply"].lower() or "Final answer" in result["reply"]
