"""Assistive AI copilot (v12) — Q/A only; not a detector.

Phase 95: provider adapter + ``.env`` settings.
Phase 96: Pocket Flow chat turn + allow-listed tools + ``POST /api/v1/copilot/chat``.
Phase 98: Pocket Flow Insight Workflow → optional ``*_ai_insight.md``.
"""

from __future__ import annotations

from src.copilot.flow import build_chat_flow, run_chat_turn
from src.copilot.insight_flow import (
    InsightFlowError,
    build_insight_flow,
    insight_filename,
    run_insight_workflow,
)
from src.copilot.provider import (
    CopilotProviderError,
    GeminiProvider,
    LlmProvider,
    OllamaProvider,
    OpenAICompatProvider,
    build_provider,
    pick_gemini_model,
    resolve_display_model,
)
from src.copilot.settings import (
    CopilotEnvSettings,
    is_auto_model,
    is_copilot_runtime_enabled,
    load_copilot_env_settings,
    load_dotenv_file,
)
from src.copilot.tools import ALLOWED_TOOLS, ToolContext, ToolError, run_tool

__all__ = [
    "ALLOWED_TOOLS",
    "CopilotEnvSettings",
    "CopilotProviderError",
    "GeminiProvider",
    "InsightFlowError",
    "LlmProvider",
    "OllamaProvider",
    "OpenAICompatProvider",
    "ToolContext",
    "ToolError",
    "build_chat_flow",
    "build_insight_flow",
    "build_provider",
    "insight_filename",
    "is_auto_model",
    "is_copilot_runtime_enabled",
    "load_copilot_env_settings",
    "load_dotenv_file",
    "pick_gemini_model",
    "resolve_display_model",
    "run_chat_turn",
    "run_insight_workflow",
    "run_tool",
]
