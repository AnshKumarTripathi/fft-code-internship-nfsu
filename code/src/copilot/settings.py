"""Copilot settings from ``.env`` (Phase 95+).

Secrets never belong in committed ``pipeline.yaml``. Provider keys and endpoints
are loaded from the environment (optionally seeded from ``code/.env``).

**Dual-gate rule:** runtime copilot is on only when *both*
``COPILOT_ENABLED=true`` (env) *and* ``copilot.enabled: true`` (YAML) are set.
Either alone leaves the feature off. Soft-fail paths (Phase 96+) must respect this.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_COPILOT_MODEL = "qwen2.5:14b"
DEFAULT_GEMINI_MODEL = "auto"
DEFAULT_TIMEOUT_SECONDS = 120.0

ALLOWED_PROVIDERS = frozenset({"ollama", "openai_compat", "gemini"})
AUTO_MODEL_TOKENS = frozenset({"", "auto", "*", "latest", "default"})

# ``src/copilot/settings.py`` → ``code/``
_CODE_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class CopilotEnvSettings:
    """Resolved copilot environment (no YAML). Secrets stay here, not in git."""

    enabled: bool
    provider: str
    model: str
    ollama_base_url: str
    openai_api_key: str | None
    openai_base_url: str
    gemini_api_key: str | None
    gemini_base_url: str
    timeout_seconds: float


def is_auto_model(model: str | None) -> bool:
    """True when the operator asked the provider to pick a model dynamically."""
    if model is None:
        return True
    return model.strip().lower() in AUTO_MODEL_TOKENS


def _truthy_env(raw: str | None) -> bool:
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_dotenv_file(path: Path | None = None) -> Path | None:
    """Load ``KEY=VALUE`` lines into ``os.environ`` if the key is unset.

    Does not override existing process environment. Returns the path loaded,
    or ``None`` if no file was found. Never logs secret values.
    """
    candidates: list[Path] = []
    if path is not None:
        candidates.append(Path(path))
    else:
        candidates.append(_CODE_ROOT / ".env")
        candidates.append(Path.cwd() / ".env")

    for candidate in candidates:
        if not candidate.is_file():
            continue
        _apply_dotenv(candidate)
        logger.debug("Loaded copilot dotenv from %s", candidate)
        return candidate
    return None


def _apply_dotenv(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].strip()
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


def load_copilot_env_settings(*, load_dotenv: bool = True) -> CopilotEnvSettings:
    """Read copilot settings from the process environment.

    When ``load_dotenv`` is true, attempts to seed unset keys from ``code/.env``.
    """
    if load_dotenv:
        load_dotenv_file()

    provider_raw = (os.environ.get("COPILOT_PROVIDER") or "ollama").strip().lower()
    if provider_raw not in ALLOWED_PROVIDERS:
        raise ValueError(
            f"COPILOT_PROVIDER must be one of {sorted(ALLOWED_PROVIDERS)}, "
            f"got {provider_raw!r}"
        )

    model_raw = os.environ.get("COPILOT_MODEL")
    if provider_raw == "gemini":
        # Empty / auto → pick from Gemini list-models at runtime.
        if model_raw is None or is_auto_model(model_raw):
            model = DEFAULT_GEMINI_MODEL
        else:
            model = model_raw.strip()
    else:
        model = (model_raw or DEFAULT_COPILOT_MODEL).strip()
        if not model:
            raise ValueError("COPILOT_MODEL must be a non-empty string")

    ollama_base = (
        os.environ.get("OLLAMA_BASE_URL") or DEFAULT_OLLAMA_BASE_URL
    ).strip().rstrip("/")
    if not ollama_base:
        raise ValueError("OLLAMA_BASE_URL must be a non-empty URL")

    openai_base = (
        os.environ.get("OPENAI_BASE_URL") or DEFAULT_OPENAI_BASE_URL
    ).strip().rstrip("/")
    if not openai_base:
        raise ValueError("OPENAI_BASE_URL must be a non-empty URL")

    gemini_base = (
        os.environ.get("GEMINI_BASE_URL") or DEFAULT_GEMINI_BASE_URL
    ).strip().rstrip("/")
    if not gemini_base:
        raise ValueError("GEMINI_BASE_URL must be a non-empty URL")

    api_key_raw = os.environ.get("OPENAI_API_KEY")
    api_key = api_key_raw.strip() if isinstance(api_key_raw, str) else None
    if api_key == "":
        api_key = None

    gemini_key_raw = os.environ.get("GEMINI_API_KEY") or os.environ.get(
        "GOOGLE_API_KEY"
    )
    gemini_key = gemini_key_raw.strip() if isinstance(gemini_key_raw, str) else None
    if gemini_key == "":
        gemini_key = None

    timeout_raw = os.environ.get("COPILOT_TIMEOUT_SECONDS")
    if timeout_raw is None or not str(timeout_raw).strip():
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS
    else:
        try:
            timeout_seconds = float(timeout_raw)
        except ValueError as exc:
            raise ValueError(
                "COPILOT_TIMEOUT_SECONDS must be a positive number"
            ) from exc
        if timeout_seconds <= 0:
            raise ValueError("COPILOT_TIMEOUT_SECONDS must be a positive number")

    return CopilotEnvSettings(
        enabled=_truthy_env(os.environ.get("COPILOT_ENABLED")),
        provider=provider_raw,
        model=model,
        ollama_base_url=ollama_base,
        openai_api_key=api_key,
        openai_base_url=openai_base,
        gemini_api_key=gemini_key,
        gemini_base_url=gemini_base,
        timeout_seconds=timeout_seconds,
    )


def is_copilot_runtime_enabled(
    *,
    yaml_enabled: bool,
    env_settings: CopilotEnvSettings | None = None,
) -> bool:
    """Dual-gate: YAML ``copilot.enabled`` AND env ``COPILOT_ENABLED`` must both be true."""
    settings = env_settings if env_settings is not None else load_copilot_env_settings()
    return bool(yaml_enabled) and bool(settings.enabled)
