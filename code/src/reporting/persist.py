"""Orchestrate Phase 9/17 report: incidents → Markdown + HTML files (+ optional LLM).

Phase 98: optional AI Insight artifact via Pocket Flow Workflow (soft-fail).
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from src.config import copilot_settings
from src.copilot.insight_flow import InsightFlowError, run_insight_workflow
from src.copilot.provider import CopilotProviderError, build_provider
from src.copilot.settings import load_copilot_env_settings
from src.db.connection import get_connection, record_run_finish, record_run_start
from src.reporting.narrative_llm import NarrativeLlmError, summarize_incident
from src.reporting.report_generator import (
    DEFAULT_HTML_TEMPLATE,
    DEFAULT_MD_TEMPLATE,
    NothingToReport,
    ReportingError,
    build_context,
    load_incidents,
    render_incident_html,
    render_incident_markdown,
    resolve_template_path,
    write_incident_report,
)

logger = logging.getLogger(__name__)


@dataclass
class ReportSummary:
    incidents_total: int = 0
    reports_written: int = 0
    llm_enabled: bool = False
    llm_successes: int = 0
    llm_failures: int = 0
    ai_insight_enabled: bool = False
    ai_insight_attempted: int = 0
    ai_insight_successes: int = 0
    ai_insight_skipped: int = 0
    nothing_to_report: bool = False
    report_paths: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ai_insight_enabled(config: dict[str, Any]) -> bool:
    """YAML ``copilot.ai_insight.enabled`` only (independent of chat dual-gate)."""
    return bool(copilot_settings(config)["ai_insight"]["enabled"])


def _try_write_ai_insight(
    *,
    context: dict[str, Any],
    report_dir: Path,
    incident_id: str,
    summary: ReportSummary,
) -> None:
    """Attempt Insight after Jinja write; never raise into the report stage."""
    summary.ai_insight_attempted += 1
    try:
        env = load_copilot_env_settings()
        provider = build_provider(env)
        path = run_insight_workflow(
            context=context,
            report_dir=report_dir,
            provider=provider,
            env_settings=env,
        )
        summary.ai_insight_successes += 1
        summary.report_paths.append(str(path))
        logger.info("AI Insight written for %s → %s", incident_id, path.name)
    except (InsightFlowError, CopilotProviderError, ValueError) as exc:
        summary.ai_insight_skipped += 1
        logger.warning(
            "AI Insight skipped for %s: %s — deterministic report kept",
            incident_id,
            exc,
        )
    except Exception as exc:  # noqa: BLE001 — soft-fail boundary
        summary.ai_insight_skipped += 1
        logger.warning(
            "AI Insight skipped for %s: unexpected %s — deterministic report kept",
            incident_id,
            exc,
        )


def _validate_reporting_config(
    config: dict[str, Any],
) -> tuple[str, str, bool, str, Path]:
    reporting = config.get("reporting") or {}
    template_path = reporting.get("template_path", DEFAULT_MD_TEMPLATE)
    html_template_path = reporting.get("html_template_path", DEFAULT_HTML_TEMPLATE)
    use_llm = bool(reporting.get("use_llm_narrative", False))
    llm_model = str(reporting.get("llm_model", "qwen3-coder:30b"))
    report_dir = Path(config["paths"]["report_dir"])

    if not isinstance(template_path, str) or not template_path.strip():
        raise ReportingError("reporting.template_path must be a non-empty string")
    if not isinstance(html_template_path, str) or not html_template_path.strip():
        raise ReportingError(
            "reporting.html_template_path must be a non-empty string"
        )

    resolved_md = resolve_template_path(template_path)
    if not resolved_md.is_file():
        raise ReportingError(f"report template not found: {resolved_md}")
    resolved_html = resolve_template_path(html_template_path)
    if not resolved_html.is_file():
        raise ReportingError(f"report template not found: {resolved_html}")

    return template_path, html_template_path, use_llm, llm_model, report_dir


def run_report(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
) -> ReportSummary:
    """Render Markdown and HTML files per incident under paths.report_dir."""
    connection = get_connection(config)
    template_path, html_template_path, use_llm, llm_model, report_dir = (
        _validate_reporting_config(config)
    )
    insight_enabled = _ai_insight_enabled(config)
    params = {
        "config_path": config_path,
        "template_path": template_path,
        "html_template_path": html_template_path,
        "use_llm_narrative": use_llm,
        "llm_model": llm_model,
        "report_dir": str(report_dir),
        "ai_insight_enabled": insight_enabled,
    }
    run_id = record_run_start(connection, stage="report", params=params)
    summary = ReportSummary(
        llm_enabled=use_llm,
        ai_insight_enabled=insight_enabled,
    )

    try:
        incidents = load_incidents(connection)
        summary.incidents_total = len(incidents)

        if not incidents:
            summary.nothing_to_report = True
            params_with_summary = {**params, "summary": summary.as_dict()}
            connection.execute(
                """
                UPDATE pipeline_runs
                SET params_json = ?::JSON
                WHERE run_id = ?
                """,
                [json.dumps(params_with_summary), run_id],
            )
            record_run_finish(connection, run_id, "success")
            print("report summary:")
            print("  nothing to report")
            logger.info("report: nothing to report")
            raise NothingToReport("nothing to report")

        for incident in incidents:
            context = build_context(connection, incident)
            narrative: str | None = None

            if use_llm:
                try:
                    narrative = summarize_incident(context, model=llm_model)
                    context["llm_narrative"] = narrative
                    connection.execute(
                        """
                        UPDATE incidents
                        SET summary_text = ?
                        WHERE incident_id = ?
                        """,
                        [narrative, incident.incident_id],
                    )
                    summary.llm_successes += 1
                except NarrativeLlmError as exc:
                    summary.llm_failures += 1
                    logger.warning(
                        "LLM narrative failed for %s: %s — writing deterministic report only",
                        incident.incident_id,
                        exc,
                    )

            markdown = render_incident_markdown(
                context, template_path=template_path
            )
            html = render_incident_html(
                context, template_path=html_template_path
            )
            md_path = write_incident_report(
                report_dir, incident.incident_id, markdown, suffix="md"
            )
            html_path = write_incident_report(
                report_dir, incident.incident_id, html, suffix="html"
            )
            summary.reports_written += 1
            summary.report_paths.append(str(md_path))
            summary.report_paths.append(str(html_path))

            # Phase 98 — opt-in AI Insight beside Jinja; soft-fail on LLM errors.
            if insight_enabled:
                _try_write_ai_insight(
                    context=context,
                    report_dir=report_dir,
                    incident_id=incident.incident_id,
                    summary=summary,
                )

        params_with_summary = {**params, "summary": summary.as_dict()}
        connection.execute(
            """
            UPDATE pipeline_runs
            SET params_json = ?::JSON
            WHERE run_id = ?
            """,
            [json.dumps(params_with_summary), run_id],
        )
        record_run_finish(connection, run_id, "success")

        logger.info("report summary: %s", summary.as_dict())
        print("report summary:")
        for key, value in summary.as_dict().items():
            if key == "report_paths" and len(value) > 5:
                print(f"  {key}: [{len(value)} files]")
            else:
                print(f"  {key}: {value}")
        return summary
    except NothingToReport:
        raise
    except ReportingError:
        record_run_finish(connection, run_id, "failed")
        raise
    except Exception:
        record_run_finish(connection, run_id, "failed")
        raise
    finally:
        connection.close()
