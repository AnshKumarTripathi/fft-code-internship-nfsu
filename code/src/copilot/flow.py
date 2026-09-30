"""Pocket Flow chat-turn graph for the assistive copilot (Phase 96).

Streaming (SSE) is deferred — MVP returns a single non-stream reply.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Sequence

from src.copilot.docs_loader import resolve_docs_slugs_for_query
from src.copilot.pocketflow import Flow, Node
from src.copilot.provider import CopilotProviderError, LlmProvider
from src.copilot.settings import CopilotEnvSettings
from src.copilot.tools import ToolContext, ToolError, run_tool

logger = logging.getLogger(__name__)

MAX_TOOL_LOOPS = 5
MAX_HISTORY_MESSAGES = 20
MAX_AUTO_DOCS = 2

SYSTEM_PROMPT = """You are an assistive lab copilot for a log anomaly detection product.
Rules:
- Use ONLY facts from the structured context (incident brief, Docs sections, tool results, attachments).
- When Docs sections are present, answer product / project / how-to questions from those Docs — do not claim there is "no project" or "no data" just because no incident is selected.
- When a report excerpt, incident brief, or Why flagged data is present, explain findings, severity, and criticality from those facts in clear descriptive plain language. Do not say the report is missing if tool_results contain get_report_excerpt or brief.
- When rank_entities_by_anomalies, list_incidents_ranked, or get_entity_overview results are present, answer ranking / suspect / most-anomalies questions from those counts — do not claim entity evidence is missing.
- Distinguish missing incident evidence (scores, entities, events) from product documentation (what the lab is, how to use it).
- Do not invent CVEs, IPs, users, scores, or events that are not present.
- If incident-specific evidence is missing, say so clearly; still use Docs for general product questions.
- Scores and flags are heuristics (robust z / detectors), not p-values or proof of compromise.
- Remind the operator to verify incident claims against Why flagged and the deterministic report.
- Prefer helpful detail over one-liners when evidence is available; stay plain-language; do not claim to dismiss or remediate.
- Reply in plain text only. Do not use Markdown (no headings like ###, no **bold**, no *italics*, no bullet markers like - or *, no numbered lists like 1., no code fences, no --- rules, no links like [text](url)). Write short paragraphs or simple sentences. If you need a list, use plain lines such as "First, … Next, …" or separate sentences."""

AGENT_DECIDE_PROMPT = """You pick the next assistive-copilot tool action.
Reply with YAML only (no markdown fences), using exactly:
decision: explore
tool: <tool_name>
args: {}
OR
decision: answer

Allowed tools: get_incident_brief, get_why_flagged, get_report_excerpt, get_docs_section, rank_entities_by_anomalies, list_incidents_ranked, get_entity_overview
Rules: explore only if a listed tool can add missing facts; never invent tool names; prefer rank_entities_by_anomalies for "most anomalies / most suspect" questions; prefer list_incidents_ranked for triage ranking; prefer get_entity_overview when an entity_id is known."""

EXPLORE_ACTIONS = {
    "get_incident_brief": "fetch_incident",
    "get_why_flagged": "fetch_why_flagged",
    "get_report_excerpt": "fetch_report",
    "get_docs_section": "fetch_docs",
    "rank_entities_by_anomalies": "fetch_rank_entities",
    "list_incidents_ranked": "fetch_incidents_ranked",
    "get_entity_overview": "fetch_entity_overview",
}


def _to_plain_text(reply: str) -> str:
    """Best-effort strip of common Markdown so the chat UI stays unformatted."""
    text = (reply or "").replace("\r\n", "\n").strip()
    if not text:
        return ""
    # Fenced code blocks → inner text
    text = re.sub(r"```[\w+-]*\n?(.*?)```", r"\1", text, flags=re.DOTALL)
    # Headings
    text = re.sub(r"(?m)^#{1,6}\s*", "", text)
    # Links / images
    text = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    # Bold / italic markers
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"__(.+?)__", r"\1", text)
    text = re.sub(r"(?<!\w)\*(.+?)\*(?!\w)", r"\1", text)
    text = re.sub(r"(?<!\w)_(.+?)_(?!\w)", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    # Horizontal rules
    text = re.sub(r"(?m)^\s*([-*_]\s*){3,}\s*$", "", text)
    # Bullet / numbered list markers
    text = re.sub(r"(?m)^\s*[-*+]\s+", "", text)
    text = re.sub(r"(?m)^\s*\d+\.\s+", "", text)
    # Collapse excess blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _last_user_text(shared: dict[str, Any]) -> str:
    messages = shared.get("messages") or []
    for item in reversed(messages):
        if isinstance(item, dict) and item.get("role") == "user":
            return str(item.get("content") or "")
    return ""


def _attachment_blob(shared: dict[str, Any]) -> str:
    parts: list[str] = []
    for item in shared.get("attachments") or []:
        if not isinstance(item, dict):
            continue
        label = item.get("label") or item.get("kind") or "attachment"
        route = item.get("route") or ""
        text = item.get("text") or ""
        slug = item.get("slug") or ""
        parts.append(f"[{label}] route={route} slug={slug}\n{text}")
    return "\n\n".join(parts)


def _docs_slugs_from_attachments(shared: dict[str, Any]) -> list[str]:
    slugs: list[str] = []
    for item in shared.get("attachments") or []:
        if not isinstance(item, dict):
            continue
        slug = item.get("slug")
        if isinstance(slug, str) and slug.strip():
            text = slug.strip().strip("/")
            if text and text not in slugs:
                slugs.append(text)
            continue
        route = str(item.get("route") or "")
        if "/docs/" in route:
            text = route.split("/docs/", 1)[1].strip("/") or ""
            if text and text not in slugs:
                slugs.append(text)
    return slugs


def _docs_slug_from_shared(shared: dict[str, Any]) -> str | None:
    attached = _docs_slugs_from_attachments(shared)
    if attached:
        return attached[0]
    text = _last_user_text(shared).lower()
    # Explicit "docs:<slug>" hint
    if "docs:" in text:
        after = text.split("docs:", 1)[1].strip().split()[0]
        return after.strip("/") or None
    return None


def _pending_docs_queue(shared: dict[str, Any]) -> list[str]:
    queue = shared.get("_pending_docs_slugs")
    if isinstance(queue, list):
        return [str(item).strip().strip("/") for item in queue if str(item).strip()]
    return []


def _ensure_docs_queue(shared: dict[str, Any]) -> list[str]:
    """Build a Docs slug queue from attachments, explicit hints, or query routing."""
    existing = _pending_docs_queue(shared)
    if existing:
        return existing

    fetched = {
        str(item).strip().strip("/")
        for item in (shared.get("_fetched_docs_slugs") or [])
        if str(item).strip()
    }
    candidates: list[str] = []

    def _push(slug: str | None) -> None:
        if not slug:
            return
        text = slug.strip().strip("/")
        if text and text not in candidates and text not in fetched:
            candidates.append(text)

    for slug in _docs_slugs_from_attachments(shared):
        _push(slug)

    user_text = _last_user_text(shared)
    lowered = user_text.lower()
    if "docs:" in lowered:
        after = lowered.split("docs:", 1)[1].strip().split()[0]
        _push(after)

    # Auto-route natural-language questions to in-app Docs (no attachment required).
    for slug in resolve_docs_slugs_for_query(user_text, max_slugs=MAX_AUTO_DOCS):
        _push(slug)

    shared["_pending_docs_slugs"] = candidates
    return candidates


def _cap_attachments(
    attachments: Sequence[dict[str, Any]] | None,
    *,
    max_chars: int,
) -> list[dict[str, Any]]:
    capped: list[dict[str, Any]] = []
    remaining = max(1, int(max_chars))
    for raw in attachments or []:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        text = str(item.get("text") or "")
        if len(text) > remaining:
            item["text"] = text[:remaining]
            item["truncated"] = True
            remaining = 0
        else:
            remaining -= len(text)
        capped.append(item)
        if remaining <= 0:
            break
    return capped


class PackContext(Node):
    """Normalize shared store before decide/tool/answer."""

    def prep(self, shared: dict[str, Any]) -> dict[str, Any]:
        return shared

    def exec(self, shared: dict[str, Any]) -> None:
        max_chars = int(shared.get("max_attachment_chars") or 4000)
        shared["attachments"] = _cap_attachments(
            shared.get("attachments"),
            max_chars=max_chars,
        )
        messages = shared.get("messages") or []
        if not isinstance(messages, list):
            messages = []
        cleaned: list[dict[str, str]] = []
        for item in messages[-MAX_HISTORY_MESSAGES:]:
            if not isinstance(item, dict):
                continue
            role = str(item.get("role") or "").strip()
            content = str(item.get("content") or "").strip()
            if role and content:
                cleaned.append({"role": role, "content": content})
        shared["messages"] = cleaned
        shared.setdefault("tool_results", {})
        shared.setdefault("tools_used", [])
        shared.setdefault("citations", [])
        shared.setdefault("tool_loop_count", 0)
        shared.setdefault("brief", None)
        shared["reply"] = shared.get("reply") or ""

    def post(self, shared, prep_res, exec_res) -> str:  # noqa: ANN001
        return "decide"


def _product_docs_intent(user_text: str) -> bool:
    """True when the question is about the product / Docs, not this incident."""
    text = (user_text or "").lower()
    if not text.strip():
        return False
    if "docs:" in text:
        return True
    markers = (
        "explain the project",
        "what is this project",
        "what is the project",
        "about the project",
        "about this project",
        "what is this product",
        "what is this system",
        "what is this lab",
        "what does this do",
        "what does this product",
        "how does this work",
        "how does the lab",
        "how does the product",
        "quick start",
        "getting started",
        "documentation",
        "non-goal",
        "assistive copilot",
    )
    if any(marker in text for marker in markers):
        return True
    # Short product-framed asks without incident-specific anchors.
    if any(token in text for token in ("project", "product", "platform")) and not any(
        token in text
        for token in ("incident", "this alert", "this flag", "why flagged", "score")
    ):
        return True
    return False


def _report_filename_from_shared(shared: dict[str, Any]) -> str | None:
    for item in shared.get("attachments") or []:
        if not isinstance(item, dict):
            continue
        route = str(item.get("route") or "")
        if "/reports/" not in route:
            continue
        name = route.rsplit("/", 1)[-1].strip()
        if name.lower().startswith("incident_") and (
            name.lower().endswith(".md") or name.lower().endswith(".html")
        ):
            return name
    return None


def _wants_report_context(combined: str) -> bool:
    text = (combined or "").lower()
    return any(
        token in text
        for token in (
            "report",
            "critical",
            "severity",
            "finding",
            "findings",
            "what it states",
        )
    )


def _attachment_routes(shared: dict[str, Any]) -> str:
    parts: list[str] = []
    for item in shared.get("attachments") or []:
        if isinstance(item, dict) and item.get("route"):
            parts.append(str(item.get("route")))
    return "\n".join(parts).lower()


def _entity_id_from_shared(shared: dict[str, Any]) -> str | None:
    for item in shared.get("attachments") or []:
        if not isinstance(item, dict):
            continue
        eid = item.get("entity_id")
        if isinstance(eid, str) and eid.strip():
            return eid.strip()
        route = str(item.get("route") or "")
        if route.startswith("/entities/"):
            rest = route[len("/entities/") :].strip("/")
            if rest and "/" not in rest:
                return rest
    return None


def _wants_entity_ranking(combined: str, routes: str) -> bool:
    text = f"{combined}\n{routes}".lower()
    if "/entities" in routes and any(
        token in text
        for token in (
            "suspect",
            "anomal",
            "most",
            "top",
            "which entity",
            "rank",
            "worst",
        )
    ):
        return True
    return any(
        token in text
        for token in (
            "most suspect",
            "most anomal",
            "which entity",
            "top entit",
            "rank entit",
            "entity is the most",
            "entities with most",
            "highest anomal",
        )
    )


def _wants_incident_ranking(combined: str, routes: str) -> bool:
    text = f"{combined}\n{routes}".lower()
    if "/triage" in routes or "/incidents" in routes:
        if any(token in text for token in ("top", "most", "rank", "worst", "priority")):
            return True
    return any(
        token in text
        for token in (
            "top incident",
            "worst incident",
            "rank incident",
            "most severe",
            "highest severity",
        )
    )


def _tool_result_ok(shared: dict[str, Any], name: str) -> bool:
    results = shared.get("tool_results") or {}
    payload = results.get(name)
    if payload is None:
        return False
    if isinstance(payload, list):
        return any(isinstance(item, dict) and "error" not in item for item in payload)
    return isinstance(payload, dict) and "error" not in payload


def _needs_more_evidence(shared: dict[str, Any]) -> bool:
    """True when the question likely needs another allow-listed tool before answering."""
    if int(shared.get("tool_loop_count") or 0) >= MAX_TOOL_LOOPS:
        return False
    user_text = _last_user_text(shared)
    combined = f"{user_text}\n{_attachment_blob(shared)}".lower()
    routes = _attachment_routes(shared)
    used = set(shared.get("tools_used") or [])

    if _wants_entity_ranking(combined, routes) and "rank_entities_by_anomalies" not in used:
        return True
    if _wants_incident_ranking(combined, routes) and "list_incidents_ranked" not in used:
        return True
    entity_id = _entity_id_from_shared(shared)
    if entity_id and "get_entity_overview" not in used and any(
        token in combined for token in ("entity", "this host", "this user", "overview")
    ):
        return True
    if shared.get("incident_id") and "get_incident_brief" not in used:
        return True
    if any(token in combined for token in ("suspect", "anomal", "rank", "top ", "most ")):
        if not (
            _tool_result_ok(shared, "rank_entities_by_anomalies")
            or _tool_result_ok(shared, "list_incidents_ranked")
            or _tool_result_ok(shared, "get_incident_brief")
            or _tool_result_ok(shared, "get_report_excerpt")
            or _tool_result_ok(shared, "get_docs_section")
        ):
            return True
    return False


def _parse_agent_decision(raw: str) -> dict[str, Any] | None:
    text = (raw or "").strip()
    if not text:
        return None
    text = re.sub(r"^```(?:yaml|yml)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    decision = None
    tool = None
    args: dict[str, Any] = {}
    in_args = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lower = stripped.lower()
        if lower.startswith("decision:"):
            decision = stripped.split(":", 1)[1].strip().lower()
            in_args = False
            continue
        if lower.startswith("tool:"):
            tool = stripped.split(":", 1)[1].strip()
            in_args = False
            continue
        if lower.startswith("args:"):
            in_args = True
            remainder = stripped.split(":", 1)[1].strip()
            if remainder and remainder not in {"{}", "null", "~"}:
                # Inline JSON-ish: {entity_id: alice} or entity_id: alice
                for part in remainder.strip("{}").split(","):
                    if ":" not in part:
                        continue
                    key, _, value = part.partition(":")
                    key = key.strip().strip("'\"")
                    value = value.strip().strip("'\"")
                    if key:
                        args[key] = value
            continue
        if in_args and ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip().lstrip("- ").strip("'\"")
            value = value.strip().strip("'\"")
            if key:
                args[key] = value
    if decision not in {"explore", "answer"}:
        return None
    if decision == "answer":
        return {"decision": "answer"}
    if not tool or tool not in EXPLORE_ACTIONS:
        return None
    return {"decision": "explore", "tool": tool, "args": args}


def _apply_agent_decision(shared: dict[str, Any]) -> str:
    """LLM explore/answer fallback; soft-fail to answer on any error."""
    provider: LlmProvider | None = shared.get("provider")
    if provider is None:
        return "answer"
    used = list(shared.get("tools_used") or [])
    facts = {
        "question": _last_user_text(shared),
        "incident_id": shared.get("incident_id"),
        "entity_id": _entity_id_from_shared(shared),
        "routes": _attachment_routes(shared),
        "tools_used": used,
        "tool_result_keys": list((shared.get("tool_results") or {}).keys()),
    }
    try:
        raw = provider.generate(
            [
                {"role": "system", "content": AGENT_DECIDE_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(facts, default=str),
                },
            ],
            model=shared.get("model") if isinstance(shared.get("model"), str) else None,
            timeout=min(30.0, float(shared.get("timeout") or 30.0)),
        )
        parsed = _parse_agent_decision(raw)
    except Exception as exc:  # noqa: BLE001 — soft-fail explore
        logger.debug("AgentDecide soft-fail: %s", exc)
        return "answer"
    if not parsed or parsed.get("decision") != "explore":
        return "answer"
    tool = str(parsed.get("tool") or "")
    if tool in used:
        return "answer"
    action = EXPLORE_ACTIONS.get(tool)
    if not action:
        return "answer"
    args = parsed.get("args") if isinstance(parsed.get("args"), dict) else {}
    pending = dict(shared.get("_pending_tool_args") or {})
    pending[tool] = args
    shared["_pending_tool_args"] = pending
    if tool == "get_docs_section":
        slug = args.get("slug")
        if isinstance(slug, str) and slug.strip():
            shared["_pending_docs_slug"] = slug.strip().strip("/")
            queue = _ensure_docs_queue(shared)
            if slug.strip().strip("/") not in queue:
                shared["_pending_docs_slugs"] = [slug.strip().strip("/"), *queue]
    return action


class Decide(Node):
    """Hybrid agent: rules first, then optional LLM explore/answer."""

    def exec(self, prep_res) -> None:  # noqa: ANN001
        return None

    def post(self, shared, prep_res, exec_res) -> str:  # noqa: ANN001
        loops = int(shared.get("tool_loop_count") or 0)
        if loops >= MAX_TOOL_LOOPS:
            return "answer"

        used = set(shared.get("tools_used") or [])
        incident_id = shared.get("incident_id")
        user_text = _last_user_text(shared)
        lowered = user_text.lower()
        attach_blob = _attachment_blob(shared).lower()
        combined = f"{lowered}\n{attach_blob}"
        routes = _attachment_routes(shared)
        report_name = _report_filename_from_shared(shared)
        wants_report = bool(report_name) or _wants_report_context(combined)
        wants_rank = _wants_entity_ranking(combined, routes)
        wants_incidents = _wants_incident_ranking(combined, routes)
        entity_id = _entity_id_from_shared(shared)
        prefer_docs = (
            _product_docs_intent(user_text) or bool(_docs_slugs_from_attachments(shared))
        ) and not wants_report and not wants_rank and not wants_incidents

        # Product / Docs questions: ground on Docs even if an incident is open.
        if prefer_docs:
            docs_queue = _ensure_docs_queue(shared)
            if docs_queue:
                shared["_pending_docs_slug"] = docs_queue[0]
                return "fetch_docs"

        # Entity ranking (Entities page / suspect questions).
        if wants_rank and "rank_entities_by_anomalies" not in used:
            return "fetch_rank_entities"

        if (
            entity_id
            and "get_entity_overview" not in used
            and (
                wants_rank
                or any(token in combined for token in ("this entity", "overview", "about"))
            )
        ):
            shared.setdefault("_pending_tool_args", {})["get_entity_overview"] = {
                "entity_id": entity_id
            }
            return "fetch_entity_overview"

        if wants_incidents and "list_incidents_ranked" not in used:
            return "fetch_incidents_ranked"

        # Incident evidence when an incident is in scope.
        if incident_id and "get_incident_brief" not in used:
            return "fetch_incident"

        # Report questions: load the report excerpt before / with why-flagged.
        if (
            (incident_id or report_name)
            and "get_report_excerpt" not in used
            and wants_report
        ):
            return "fetch_report"

        if incident_id and "get_why_flagged" not in used:
            if any(
                token in combined
                for token in ("why", "flag", "playbook", "explain", "critical", "severity")
            ):
                return "fetch_why_flagged"

        # Opportunistic Docs for general how-to asks (no incident needed).
        docs_queue = _ensure_docs_queue(shared)
        if (
            docs_queue
            and not incident_id
            and not wants_report
            and not wants_rank
            and not wants_incidents
        ):
            shared["_pending_docs_slug"] = docs_queue[0]
            return "fetch_docs"

        if _needs_more_evidence(shared):
            return _apply_agent_decision(shared)

        return "answer"


class _ToolNode(Node):
    tool_name: str = ""
    citation_source: str = ""

    def prep(self, shared: dict[str, Any]) -> dict[str, Any]:
        return shared

    def _kwargs(self, shared: dict[str, Any]) -> dict[str, Any]:
        return {"incident_id": shared.get("incident_id")}

    def exec(self, shared: dict[str, Any]) -> dict[str, Any] | None:
        ctx: ToolContext | None = shared.get("tool_context")
        if ctx is None:
            return {"error": "tool context missing"}
        try:
            return run_tool(self.tool_name, ctx, **self._kwargs(shared))
        except ToolError as exc:
            return {"error": str(exc)}

    def post(self, shared, prep_res, exec_res) -> str:  # noqa: ANN001
        results = shared.setdefault("tool_results", {})
        results[self.tool_name] = exec_res
        used = shared.setdefault("tools_used", [])
        if self.tool_name not in used:
            used.append(self.tool_name)
        shared["tool_loop_count"] = int(shared.get("tool_loop_count") or 0) + 1
        if isinstance(exec_res, dict) and "error" not in exec_res:
            citations = shared.setdefault("citations", [])
            ref = str(
                shared.get("incident_id")
                or exec_res.get("slug")
                or exec_res.get("filename")
                or self.tool_name
            )
            citations.append({"source": self.citation_source, "ref": ref})
            if self.tool_name == "get_incident_brief":
                shared["brief"] = exec_res
        return "decide"


class FetchIncident(_ToolNode):
    tool_name = "get_incident_brief"
    citation_source = "incident_brief"


class FetchWhyFlagged(_ToolNode):
    tool_name = "get_why_flagged"
    citation_source = "why_flagged"


class FetchReport(_ToolNode):
    tool_name = "get_report_excerpt"
    citation_source = "report_excerpt"

    def _kwargs(self, shared: dict[str, Any]) -> dict[str, Any]:
        path = _report_filename_from_shared(shared)
        if path:
            return {"path": path}
        return {"incident_id": shared.get("incident_id")}


class FetchRankEntities(_ToolNode):
    tool_name = "rank_entities_by_anomalies"
    citation_source = "entity_ranking"

    def _kwargs(self, shared: dict[str, Any]) -> dict[str, Any]:
        pending = (shared.get("_pending_tool_args") or {}).get(self.tool_name) or {}
        kwargs: dict[str, Any] = {}
        if pending.get("limit") is not None:
            kwargs["limit"] = pending.get("limit")
        return kwargs


class FetchIncidentsRanked(_ToolNode):
    tool_name = "list_incidents_ranked"
    citation_source = "incident_ranking"

    def _kwargs(self, shared: dict[str, Any]) -> dict[str, Any]:
        pending = (shared.get("_pending_tool_args") or {}).get(self.tool_name) or {}
        kwargs: dict[str, Any] = {}
        for key in ("sort", "limit", "entity_id"):
            if pending.get(key) is not None:
                kwargs[key] = pending.get(key)
        if "entity_id" not in kwargs:
            eid = _entity_id_from_shared(shared)
            if eid:
                kwargs["entity_id"] = eid
        return kwargs


class FetchEntityOverview(_ToolNode):
    tool_name = "get_entity_overview"
    citation_source = "entity_overview"

    def _kwargs(self, shared: dict[str, Any]) -> dict[str, Any]:
        pending = (shared.get("_pending_tool_args") or {}).get(self.tool_name) or {}
        eid = pending.get("entity_id") or _entity_id_from_shared(shared)
        return {"entity_id": eid}


class FetchDocs(_ToolNode):
    tool_name = "get_docs_section"
    citation_source = "docs_section"

    def _kwargs(self, shared: dict[str, Any]) -> dict[str, Any]:
        queue = _ensure_docs_queue(shared)
        slug = shared.pop("_pending_docs_slug", None)
        if not slug and queue:
            slug = queue[0]
        if not slug:
            slug = _docs_slug_from_shared(shared)
        if slug:
            shared["_active_docs_slug"] = str(slug).strip().strip("/")
        return {"slug": slug}

    def post(self, shared, prep_res, exec_res) -> str:  # noqa: ANN001
        active = str(shared.pop("_active_docs_slug", "") or "").strip().strip("/")
        queue = _pending_docs_queue(shared)
        if active and queue and queue[0] == active:
            queue = queue[1:]
        elif active:
            queue = [item for item in queue if item != active]
        shared["_pending_docs_slugs"] = queue

        fetched = shared.setdefault("_fetched_docs_slugs", [])
        if active and active not in fetched:
            fetched.append(active)

        results = shared.setdefault("tool_results", {})
        bucket = results.get(self.tool_name)
        if not isinstance(bucket, list):
            bucket = [] if bucket is None else [bucket]
        bucket.append(exec_res)
        results[self.tool_name] = bucket

        used = shared.setdefault("tools_used", [])
        if self.tool_name not in used:
            used.append(self.tool_name)
        shared["tool_loop_count"] = int(shared.get("tool_loop_count") or 0) + 1
        if isinstance(exec_res, dict) and "error" not in exec_res:
            citations = shared.setdefault("citations", [])
            ref = str(exec_res.get("slug") or active or self.tool_name)
            citations.append({"source": self.citation_source, "ref": ref})
        return "decide"


class Answer(Node):
    """Call Phase 95 provider with system prompt + store facts only."""

    def prep(self, shared: dict[str, Any]) -> dict[str, Any]:
        return shared

    def exec(self, shared: dict[str, Any]) -> str:
        provider: LlmProvider | None = shared.get("provider")
        if provider is None:
            raise CopilotProviderError("LLM provider not configured")

        facts = {
            "incident_id": shared.get("incident_id"),
            "analysis_id": shared.get("analysis_id"),
            "brief": shared.get("brief"),
            "tool_results": shared.get("tool_results") or {},
            "attachments": shared.get("attachments") or [],
        }
        context_json = json.dumps(facts, default=str)
        history = list(shared.get("messages") or [])
        llm_messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "system",
                "content": f"Structured evidence JSON:\n{context_json}",
            },
            *history,
        ]
        model = shared.get("model")
        timeout = shared.get("timeout")
        return provider.generate(
            llm_messages,
            model=model if isinstance(model, str) else None,
            timeout=float(timeout) if timeout is not None else None,
        )

    def post(self, shared, prep_res, exec_res) -> str:  # noqa: ANN001
        shared["reply"] = _to_plain_text(str(exec_res or ""))
        return "default"


def build_chat_flow() -> Flow:
    """Wire PackContext → Decide ⇄ tools → Answer."""
    pack = PackContext()
    decide = Decide()
    fetch_incident = FetchIncident()
    fetch_why = FetchWhyFlagged()
    fetch_report = FetchReport()
    fetch_docs = FetchDocs()
    fetch_rank = FetchRankEntities()
    fetch_incidents_ranked = FetchIncidentsRanked()
    fetch_entity = FetchEntityOverview()
    answer = Answer()

    pack.next(decide, "decide")
    decide.next(fetch_incident, "fetch_incident")
    decide.next(fetch_why, "fetch_why_flagged")
    decide.next(fetch_report, "fetch_report")
    decide.next(fetch_docs, "fetch_docs")
    decide.next(fetch_rank, "fetch_rank_entities")
    decide.next(fetch_incidents_ranked, "fetch_incidents_ranked")
    decide.next(fetch_entity, "fetch_entity_overview")
    decide.next(answer, "answer")
    fetch_incident.next(decide, "decide")
    fetch_why.next(decide, "decide")
    fetch_report.next(decide, "decide")
    fetch_docs.next(decide, "decide")
    fetch_rank.next(decide, "decide")
    fetch_incidents_ranked.next(decide, "decide")
    fetch_entity.next(decide, "decide")
    return Flow(start=pack)


def run_chat_turn(
    *,
    messages: list[dict[str, str]],
    attachments: list[dict[str, Any]] | None = None,
    incident_id: str | None = None,
    analysis_id: str | None = None,
    tool_context: ToolContext,
    provider: LlmProvider,
    env_settings: CopilotEnvSettings,
    max_attachment_chars: int = 4000,
) -> dict[str, Any]:
    """Execute one Pocket Flow chat turn; returns reply envelope fields."""
    resolved_model = getattr(provider, "default_model", None) or env_settings.model
    shared: dict[str, Any] = {
        "messages": messages,
        "attachments": attachments or [],
        "incident_id": incident_id,
        "analysis_id": analysis_id,
        "tool_context": tool_context,
        "provider": provider,
        "model": resolved_model,
        "timeout": env_settings.timeout_seconds,
        "max_attachment_chars": max_attachment_chars,
        "brief": None,
        "tool_results": {},
        "tools_used": [],
        "citations": [],
        "tool_loop_count": 0,
        "_pending_docs_slugs": [],
        "_fetched_docs_slugs": [],
        "_pending_tool_args": {},
        "reply": "",
    }
    flow = build_chat_flow()
    flow.run(shared)
    used_model = getattr(provider, "default_model", None) or resolved_model
    return {
        "reply": shared.get("reply") or "",
        "citations": list(shared.get("citations") or []),
        "tools_used": list(shared.get("tools_used") or []),
        "provider": env_settings.provider,
        "model": used_model,
        "brief": shared.get("brief"),
        "tool_results": shared.get("tool_results") or {},
    }
