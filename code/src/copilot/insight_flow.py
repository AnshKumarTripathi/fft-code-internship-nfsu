"""Pocket Flow Workflow for opt-in AI Insight report artifacts (Phase 98).

Fixed graph (not the chat Agent loop): LoadBrief → Summarize → WriteFile.
Uses the Phase 95 provider adapter. Soft-fail at the call site — never raise
into the report stage for LLM/provider errors.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.copilot.pocketflow import Flow, Node
from src.copilot.provider import CopilotProviderError, LlmProvider, build_provider
from src.copilot.settings import CopilotEnvSettings, load_copilot_env_settings
from src.reporting.narrative_llm import build_incident_brief
from src.reporting.report_generator import report_filename

logger = logging.getLogger(__name__)

INSIGHT_DISCLAIMER = (
    "Assistive only — verify against Why flagged and the deterministic report. "
    "This summary does not change severity, detector scores, or flags."
)

INSIGHT_SYSTEM = """You are an assistive lab assistant summarizing a log anomaly incident.
Rules:
- Use ONLY facts in the provided JSON brief.
- Do not invent IOCs, CVEs, IPs, users, scores, or remediations.
- Do not change or reinterpret severity or detector scores as proof of compromise.
- Write plain language for mentors and demos (about 4–8 short sentences).
- Scores and flags are heuristics, not p-values."""


class InsightFlowError(Exception):
    """Insight workflow failed (caller should soft-skip)."""


def insight_filename(incident_id: str) -> str:
    """Return ``incident_{id}_ai_insight.md`` beside the Jinja report."""
    base = report_filename(incident_id, suffix="md")
    # report_filename → incident_{safe}.md → incident_{safe}_ai_insight.md
    stem = Path(base).stem
    return f"{stem}_ai_insight.md"


def is_ai_insight_filename(filename: str) -> bool:
    name = Path(filename).name
    return name.endswith("_ai_insight.md") and name.startswith("incident_")


def _format_insight_markdown(*, incident_id: str, body: str) -> str:
    prose = (body or "").strip()
    return (
        f"# AI Insight\n\n"
        f"> {INSIGHT_DISCLAIMER}\n\n"
        f"**Incident:** `{incident_id}`\n\n"
        f"{prose}\n"
    )


class LoadBrief(Node):
    """Build the capped structured brief (never the raw corpus)."""

    def prep(self, shared: dict[str, Any]) -> dict[str, Any]:
        context = shared.get("context")
        if not isinstance(context, dict):
            raise InsightFlowError("insight shared store missing context dict")
        return context

    def exec(self, prep_res: dict[str, Any]) -> dict[str, Any]:
        return build_incident_brief(prep_res)

    def post(
        self,
        shared: dict[str, Any],
        prep_res: dict[str, Any],
        exec_res: dict[str, Any],
    ) -> str:
        shared["brief"] = exec_res
        incident = (shared.get("context") or {}).get("incident") or {}
        shared["incident_id"] = str(
            incident.get("incident_id") or shared.get("incident_id") or ""
        )
        if not shared["incident_id"]:
            raise InsightFlowError("insight brief missing incident_id")
        return "default"


class Summarize(Node):
    """Call the Phase 95 LLM provider with the brief."""

    def prep(self, shared: dict[str, Any]) -> tuple[LlmProvider, dict[str, Any]]:
        provider = shared.get("provider")
        if provider is None:
            raise InsightFlowError("insight shared store missing provider")
        brief = shared.get("brief")
        if not isinstance(brief, dict):
            raise InsightFlowError("insight shared store missing brief")
        return provider, brief

    def exec(self, prep_res: tuple[LlmProvider, dict[str, Any]]) -> str:
        provider, brief = prep_res
        messages = [
            {"role": "system", "content": INSIGHT_SYSTEM},
            {
                "role": "user",
                "content": (
                    "Summarize this incident brief for a mentor demo:\n\n"
                    f"{json.dumps(brief, default=str)}"
                ),
            },
        ]
        try:
            return provider.generate(messages)
        except CopilotProviderError as exc:
            raise InsightFlowError(str(exc)) from exc

    def post(
        self,
        shared: dict[str, Any],
        prep_res: tuple[LlmProvider, dict[str, Any]],
        exec_res: str,
    ) -> str:
        text = (exec_res or "").strip()
        if not text:
            raise InsightFlowError("provider returned an empty AI Insight")
        shared["summary_text"] = text
        return "default"


class WriteFile(Node):
    """Write the labeled AI Insight markdown under report_dir."""

    def prep(self, shared: dict[str, Any]) -> tuple[Path, str, str]:
        report_dir = shared.get("report_dir")
        incident_id = shared.get("incident_id")
        summary_text = shared.get("summary_text")
        if not isinstance(report_dir, Path):
            raise InsightFlowError("insight shared store missing report_dir Path")
        if not incident_id or not isinstance(incident_id, str):
            raise InsightFlowError("insight shared store missing incident_id")
        if not summary_text or not isinstance(summary_text, str):
            raise InsightFlowError("insight shared store missing summary_text")
        return report_dir, incident_id, summary_text

    def exec(self, prep_res: tuple[Path, str, str]) -> Path:
        report_dir, incident_id, summary_text = prep_res
        report_dir.mkdir(parents=True, exist_ok=True)
        path = report_dir / insight_filename(incident_id)
        body = _format_insight_markdown(incident_id=incident_id, body=summary_text)
        path.write_text(body, encoding="utf-8")
        return path

    def post(
        self,
        shared: dict[str, Any],
        prep_res: tuple[Path, str, str],
        exec_res: Path,
    ) -> str:
        shared["insight_path"] = exec_res
        return "default"


def build_insight_flow() -> Flow:
    """Fixed Workflow: LoadBrief → Summarize → WriteFile."""
    load = LoadBrief()
    summarize = Summarize()
    write = WriteFile()
    load >> summarize >> write
    return Flow(start=load)


def run_insight_workflow(
    *,
    context: dict[str, Any],
    report_dir: Path,
    provider: LlmProvider | None = None,
    env_settings: CopilotEnvSettings | None = None,
) -> Path:
    """Run the Insight Workflow and return the written path.

    Raises ``InsightFlowError`` / ``CopilotProviderError`` on failure so the
    report stage can soft-skip without failing Jinja output.
    """
    resolved_provider = provider
    if resolved_provider is None:
        settings = (
            env_settings
            if env_settings is not None
            else load_copilot_env_settings()
        )
        try:
            resolved_provider = build_provider(settings)
        except CopilotProviderError as exc:
            raise InsightFlowError(str(exc)) from exc
        except ValueError as exc:
            raise InsightFlowError(str(exc)) from exc

    shared: dict[str, Any] = {
        "context": context,
        "report_dir": Path(report_dir),
        "provider": resolved_provider,
    }
    flow = build_insight_flow()
    try:
        flow.run(shared)
    except InsightFlowError:
        raise
    except CopilotProviderError as exc:
        raise InsightFlowError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — soft-fail boundary for report stage
        raise InsightFlowError(f"insight workflow failed: {exc}") from exc

    path = shared.get("insight_path")
    if not isinstance(path, Path):
        raise InsightFlowError("insight workflow did not produce a file path")
    return path
