"""Pluggable LLM providers for the assistive copilot (Phase 95+).

Wrappers Pocket Flow will call in Phase 96+. Extends the urllib style of
``src.reporting.narrative_llm`` without changing detector stages.

Providers: Ollama, OpenAI-compatible, Gemini (Google AI). Gemini can set
``COPILOT_MODEL=auto`` to pick a ``generateContent`` model from the API list.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol, Sequence

from src.copilot.settings import (
    CopilotEnvSettings,
    is_auto_model,
    load_copilot_env_settings,
)

logger = logging.getLogger(__name__)

ChatMessage = dict[str, str]  # role + content

_GEMINI_VERSION_RE = re.compile(
    r"gemini-(?:(\d+)(?:\.(\d+))?)?",
    re.IGNORECASE,
)

# Process-wide Gemini model cache (survives across chat requests in one uvicorn worker).
_cache_lock = threading.Lock()
_resolved_model_cache: dict[str, "_ModelCacheEntry"] = {}


@dataclass(frozen=True)
class _ModelCacheEntry:
    model: str
    listed_models: tuple[str, ...] | None = None


def _fingerprint_secret(secret: str | None) -> str:
    if not secret:
        return "none"
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return digest[:16]


def _gemini_cache_key(
    *,
    api_key: str | None,
    base_url: str,
    requested_model: str,
) -> str:
    return "|".join(
        [
            "gemini",
            base_url.rstrip("/"),
            _fingerprint_secret(api_key),
            (requested_model or "auto").strip().lower() or "auto",
        ]
    )


def get_cached_gemini_model(
    *,
    api_key: str | None,
    base_url: str,
    requested_model: str = "auto",
) -> str | None:
    """Return a previously successful Gemini model id, if cached."""
    key = _gemini_cache_key(
        api_key=api_key,
        base_url=base_url,
        requested_model=requested_model,
    )
    with _cache_lock:
        entry = _resolved_model_cache.get(key)
    return entry.model if entry else None


def get_cached_gemini_listed_models(
    *,
    api_key: str | None,
    base_url: str,
    requested_model: str = "auto",
) -> list[str] | None:
    key = _gemini_cache_key(
        api_key=api_key,
        base_url=base_url,
        requested_model=requested_model,
    )
    with _cache_lock:
        entry = _resolved_model_cache.get(key)
    if entry is None or entry.listed_models is None:
        return None
    return list(entry.listed_models)


def cache_gemini_model(
    *,
    api_key: str | None,
    base_url: str,
    requested_model: str,
    model: str,
    listed_models: Sequence[str] | None = None,
) -> None:
    """Remember a working Gemini model (and optional list-models snapshot)."""
    resolved = _strip_models_prefix(model)
    if not resolved or is_auto_model(resolved):
        return
    key = _gemini_cache_key(
        api_key=api_key,
        base_url=base_url,
        requested_model=requested_model,
    )
    listed_tuple: tuple[str, ...] | None = None
    if listed_models is not None:
        listed_tuple = tuple(_strip_models_prefix(item) for item in listed_models if item)
    with _cache_lock:
        previous = _resolved_model_cache.get(key)
        if listed_tuple is None and previous is not None:
            listed_tuple = previous.listed_models
        _resolved_model_cache[key] = _ModelCacheEntry(
            model=resolved,
            listed_models=listed_tuple,
        )


def clear_gemini_model_cache() -> None:
    """Test helper — drop process-wide Gemini model cache."""
    with _cache_lock:
        _resolved_model_cache.clear()


class CopilotProviderError(Exception):
    """Provider call failed; message must never include API key material."""


class CopilotHttpError(CopilotProviderError):
    """HTTP failure from an LLM endpoint (safe URL, no secrets)."""

    def __init__(self, status_code: int, url: str) -> None:
        self.status_code = int(status_code)
        self.url = url
        super().__init__(f"LLM HTTP {self.status_code} from {url}")


class CopilotTimeoutError(CopilotProviderError):
    """Request exceeded the configured timeout."""

    def __init__(self, message: str = "LLM request timed out") -> None:
        super().__init__(message)


class LlmProvider(Protocol):
    """Minimal generate interface for Pocket Flow Answer nodes."""

    def generate(
        self,
        messages_or_prompt: str | Sequence[ChatMessage],
        *,
        model: str | None = None,
        timeout: float | None = None,
    ) -> str:
        """Return assistant text for a prompt string or chat messages."""


def _normalize_messages(
    messages_or_prompt: str | Sequence[ChatMessage],
) -> list[ChatMessage]:
    if isinstance(messages_or_prompt, str):
        text = messages_or_prompt.strip()
        if not text:
            raise CopilotProviderError("prompt must be a non-empty string")
        return [{"role": "user", "content": text}]
    if not messages_or_prompt:
        raise CopilotProviderError("messages must be a non-empty sequence")
    normalized: list[ChatMessage] = []
    for item in messages_or_prompt:
        if not isinstance(item, dict):
            raise CopilotProviderError("each message must be a mapping with role/content")
        role = str(item.get("role") or "").strip()
        content = str(item.get("content") or "").strip()
        if not role or not content:
            raise CopilotProviderError("each message needs non-empty role and content")
        normalized.append({"role": role, "content": content})
    return normalized


def _post_json(
    url: str,
    payload: dict,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method="POST",
    )
    return _read_json_response(request, timeout=timeout)


def _get_json(
    url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> dict:
    request = urllib.request.Request(
        url,
        headers=headers or {},
        method="GET",
    )
    return _read_json_response(request, timeout=timeout)


def _read_json_response(request: urllib.request.Request, *, timeout: float) -> dict:
    safe_url = request.full_url.split("?", 1)[0]
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        # Do not attach response body — may echo request headers/keys from proxies.
        raise CopilotHttpError(exc.code, safe_url) from None
    except TimeoutError as exc:
        raise CopilotTimeoutError("LLM request timed out") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        reason_text = str(reason).lower()
        if "timed out" in reason_text or "timeout" in reason_text:
            raise CopilotTimeoutError("LLM request timed out") from None
        raise CopilotProviderError(f"LLM unreachable: {reason}") from None
    except OSError as exc:
        # socket.timeout / WinError path on some platforms
        if "timed out" in str(exc).lower() or "timeout" in str(exc).lower():
            raise CopilotTimeoutError("LLM request timed out") from None
        raise CopilotProviderError(f"LLM network error: {exc}") from None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CopilotProviderError("LLM returned non-JSON body") from exc
    if not isinstance(data, dict):
        raise CopilotProviderError("LLM JSON root must be an object")
    return data


def _strip_models_prefix(name: str) -> str:
    raw = (name or "").strip()
    if raw.startswith("models/"):
        return raw[len("models/") :]
    return raw


# Preferred chat models for COPILOT_MODEL=auto (usable aliases first).
# gemini-flash-latest is generation-free and usually callable; numbered
# 2.x ids often list successfully but 404 on generateContent for new keys.
_GEMINI_STABLE_PREF: tuple[str, ...] = (
    "gemini-flash-latest",
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
)

# Retry generateContent on these Google-side / availability codes.
_GEMINI_FALLBACK_HTTP = frozenset({404, 503, 429})
_GEMINI_FALLBACK_MAX = 6
# Per-attempt cap so a hung model leaves budget for fallbacks.
_GEMINI_PER_ATTEMPT_TIMEOUT = 45.0
_GEMINI_PER_ATTEMPT_MIN = 25.0


def _gemini_pref_score(low: str) -> int:
    """Higher is better. Match preferred stable ids; ignore lite/exp/preview variants."""
    if any(tok in low for tok in ("lite", "exp", "preview", "thinking", "image")):
        return 0
    best = 0
    for index, pref in enumerate(_GEMINI_STABLE_PREF):
        if low == pref or low.startswith(f"{pref}-"):
            best = max(best, 100 - index)
    return best


def _gemini_model_rank(model_id: str) -> tuple:
    """Higher tuple sorts first — callable aliases / Flash over brittle numbered ids."""
    low = _strip_models_prefix(model_id).lower()
    if "flash-lite" in low or "flashlite" in low:
        family = 2
    elif "flash" in low:
        family = 3
    elif "pro" in low:
        family = 1
    else:
        family = 0

    match = _GEMINI_VERSION_RE.search(low)
    major = int(match.group(1)) if match and match.group(1) else 0
    minor = int(match.group(2)) if match and match.group(2) else 0

    stable = 0 if any(tok in low for tok in ("exp", "preview", "thinking")) else 1
    # Prefer generation-free aliases and 2.x; keep 3.x as later fallback (503 risk).
    if "latest" in low and major == 0:
        gen_bucket = 4
    elif major == 2:
        gen_bucket = 3
    elif major == 1:
        gen_bucket = 2
    elif major >= 3:
        gen_bucket = 1
    else:
        gen_bucket = 0
    pref = _gemini_pref_score(low)
    return (pref, stable, family, gen_bucket, minor, low)


def _is_skipped_gemini_model(model_id: str) -> bool:
    low = _strip_models_prefix(model_id).lower()
    if "gemini" not in low:
        return True
    skip_tokens = (
        "embed",
        "aqa",
        "gecko",
        "imagen",
        "image",
        "tts",
        "live",
        "robotics",
        "computer-use",
        "veo",
    )
    return any(tok in low for tok in skip_tokens)


def rank_gemini_models(model_ids: Sequence[str]) -> list[str]:
    """Return chat-capable Gemini ids ordered best-first for auto + fallback."""
    ranked: list[tuple[tuple, str]] = []
    for raw in model_ids:
        name = _strip_models_prefix(str(raw))
        if not name or _is_skipped_gemini_model(name):
            continue
        ranked.append((_gemini_model_rank(name), name))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return [name for _, name in ranked]


def pick_gemini_model(model_ids: Sequence[str]) -> str:
    """Choose a chat-capable Gemini id (stable / callable Flash first when auto)."""
    ranked = rank_gemini_models(model_ids)
    if not ranked:
        raise CopilotProviderError(
            "No suitable Gemini generateContent models available for this API key"
        )
    return ranked[0]


class OllamaProvider:
    """Local Ollama via ``/api/chat`` (messages) or ``/api/generate`` (prompt string)."""

    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:11434",
        default_model: str = "qwen2.5:14b",
        default_timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.default_timeout = default_timeout

    def generate(
        self,
        messages_or_prompt: str | Sequence[ChatMessage],
        *,
        model: str | None = None,
        timeout: float | None = None,
    ) -> str:
        use_model = (model or self.default_model).strip()
        use_timeout = float(self.default_timeout if timeout is None else timeout)
        if use_timeout <= 0:
            raise CopilotProviderError("timeout must be positive")

        if isinstance(messages_or_prompt, str):
            prompt = messages_or_prompt.strip()
            if not prompt:
                raise CopilotProviderError("prompt must be a non-empty string")
            data = _post_json(
                f"{self.base_url}/api/generate",
                {
                    "model": use_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0, "seed": 42},
                },
                timeout=use_timeout,
            )
            text = data.get("response")
        else:
            messages = _normalize_messages(messages_or_prompt)
            data = _post_json(
                f"{self.base_url}/api/chat",
                {
                    "model": use_model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": 0, "seed": 42},
                },
                timeout=use_timeout,
            )
            message = data.get("message") or {}
            text = message.get("content") if isinstance(message, dict) else None

        if not text or not str(text).strip():
            raise CopilotProviderError("Ollama returned an empty response")
        return str(text).strip()


class OpenAICompatProvider:
    """OpenAI-compatible ``/chat/completions`` (cloud or local gateway)."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        default_model: str = "gpt-4o-mini",
        default_timeout: float = 60.0,
    ) -> None:
        key = api_key.strip() if isinstance(api_key, str) else ""
        if not key:
            raise CopilotProviderError(
                "OPENAI_API_KEY is required when COPILOT_PROVIDER=openai_compat"
            )
        self._api_key = key
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.default_timeout = default_timeout

    def generate(
        self,
        messages_or_prompt: str | Sequence[ChatMessage],
        *,
        model: str | None = None,
        timeout: float | None = None,
    ) -> str:
        use_model = (model or self.default_model).strip()
        use_timeout = float(self.default_timeout if timeout is None else timeout)
        if use_timeout <= 0:
            raise CopilotProviderError("timeout must be positive")

        messages = _normalize_messages(messages_or_prompt)
        url = f"{self.base_url}/chat/completions"
        data = _post_json(
            url,
            {
                "model": use_model,
                "messages": messages,
                "temperature": 0,
            },
            timeout=use_timeout,
            headers={"Authorization": f"Bearer {self._api_key}"},
        )
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise CopilotProviderError("OpenAI-compat response missing choices")
        first = choices[0]
        if not isinstance(first, dict):
            raise CopilotProviderError("OpenAI-compat choice must be an object")
        message = first.get("message") or {}
        if not isinstance(message, dict):
            raise CopilotProviderError("OpenAI-compat message must be an object")
        text = message.get("content")
        if not text or not str(text).strip():
            raise CopilotProviderError("OpenAI-compat returned an empty response")
        return str(text).strip()


class GeminiProvider:
    """Google AI Gemini via ``generateContent`` (+ auto-pick and HTTP fallback)."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        default_model: str = "auto",
        default_timeout: float = 60.0,
        resolve_model: bool = True,
    ) -> None:
        key = api_key.strip() if isinstance(api_key, str) else ""
        if not key:
            raise CopilotProviderError(
                "GEMINI_API_KEY is required when COPILOT_PROVIDER=gemini"
            )
        self._api_key = key
        self.base_url = base_url.rstrip("/")
        self.default_timeout = default_timeout
        self._requested_model = (default_model or "auto").strip() or "auto"
        self._listed_models: list[str] | None = None

        cached_listed = get_cached_gemini_listed_models(
            api_key=self._api_key,
            base_url=self.base_url,
            requested_model=self._requested_model,
        )
        if cached_listed:
            self._listed_models = cached_listed

        cached_model = get_cached_gemini_model(
            api_key=self._api_key,
            base_url=self.base_url,
            requested_model=self._requested_model,
        )
        if resolve_model and is_auto_model(self._requested_model) and cached_model:
            self.default_model = cached_model
            logger.debug("Gemini using cached model: %s", self.default_model)
        elif resolve_model and is_auto_model(self._requested_model):
            self.default_model = self.resolve_model(timeout=default_timeout)
            logger.info("Gemini auto-selected model: %s", self.default_model)
            self._remember_success(self.default_model)
        else:
            self.default_model = _strip_models_prefix(self._requested_model)

    def _remember_success(self, model: str) -> None:
        cache_gemini_model(
            api_key=self._api_key,
            base_url=self.base_url,
            requested_model=self._requested_model,
            model=model,
            listed_models=self._listed_models,
        )

    def resolve_model(self, *, timeout: float | None = None) -> str:
        """List Gemini models and pick a generateContent-capable chat model."""
        ranked = self.ranked_models(timeout=timeout)
        if not ranked:
            raise CopilotProviderError(
                "No suitable Gemini generateContent models available for this API key"
            )
        return ranked[0]

    def ranked_models(self, *, timeout: float | None = None) -> list[str]:
        """Cached list-models ranking for primary pick + fallbacks."""
        use_timeout = float(self.default_timeout if timeout is None else timeout)
        if self._listed_models is None:
            cached = get_cached_gemini_listed_models(
                api_key=self._api_key,
                base_url=self.base_url,
                requested_model=self._requested_model,
            )
            if cached:
                self._listed_models = cached
            else:
                self._listed_models = self.list_generate_content_models(
                    timeout=use_timeout
                )
                ranked_now = rank_gemini_models(self._listed_models)
                known = getattr(self, "default_model", "")
                model_for_cache = (
                    known
                    if known and not is_auto_model(known)
                    else (ranked_now[0] if ranked_now else "")
                )
                if model_for_cache:
                    cache_gemini_model(
                        api_key=self._api_key,
                        base_url=self.base_url,
                        requested_model=self._requested_model,
                        model=model_for_cache,
                        listed_models=self._listed_models,
                    )
        return rank_gemini_models(self._listed_models)

    def list_generate_content_models(self, *, timeout: float) -> list[str]:
        """Return model ids that advertise ``generateContent`` support."""
        names: list[str] = []
        page_token: str | None = None
        for _ in range(20):  # hard stop against runaway pagination
            query: dict[str, str] = {
                "key": self._api_key,
                "pageSize": "100",
            }
            if page_token:
                query["pageToken"] = page_token
            url = f"{self.base_url}/models?{urllib.parse.urlencode(query)}"
            data = _get_json(url, timeout=timeout)
            for item in data.get("models") or []:
                if not isinstance(item, dict):
                    continue
                methods = item.get("supportedGenerationMethods") or []
                if "generateContent" not in methods:
                    continue
                name = item.get("name")
                if isinstance(name, str) and name.strip():
                    names.append(_strip_models_prefix(name))
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            page_token = str(next_token)
        return names

    def _candidate_models(
        self,
        primary: str,
        *,
        timeout: float,
    ) -> list[str]:
        """Primary first, then ranked alternates (capped) for 404/503 fallback."""
        ordered: list[str] = []
        primary = _strip_models_prefix(primary)
        if primary and not is_auto_model(primary):
            ordered.append(primary)

        listed = self._listed_models
        if listed is None:
            listed = get_cached_gemini_listed_models(
                api_key=self._api_key,
                base_url=self.base_url,
                requested_model=self._requested_model,
            )
            if listed:
                self._listed_models = listed

        if listed is not None:
            for name in rank_gemini_models(listed):
                if name not in ordered:
                    ordered.append(name)
        else:
            for pref in _GEMINI_STABLE_PREF:
                if pref not in ordered:
                    ordered.append(pref)
            # First connection (no process cache): fetch catalogue for fallbacks.
            has_cached_model = get_cached_gemini_model(
                api_key=self._api_key,
                base_url=self.base_url,
                requested_model=self._requested_model,
            )
            if not has_cached_model:
                try:
                    for name in self.ranked_models(timeout=timeout):
                        if name not in ordered:
                            ordered.append(name)
                except CopilotProviderError:
                    pass

        if not ordered and primary:
            ordered.append(primary)
        return ordered[:_GEMINI_FALLBACK_MAX]

    def generate(
        self,
        messages_or_prompt: str | Sequence[ChatMessage],
        *,
        model: str | None = None,
        timeout: float | None = None,
    ) -> str:
        use_model = _strip_models_prefix(model or self.default_model)
        use_timeout = float(self.default_timeout if timeout is None else timeout)
        if use_timeout <= 0:
            raise CopilotProviderError("timeout must be positive")
        if is_auto_model(use_model):
            cached = get_cached_gemini_model(
                api_key=self._api_key,
                base_url=self.base_url,
                requested_model=self._requested_model,
            )
            if cached:
                use_model = cached
            else:
                use_model = self.resolve_model(timeout=use_timeout)
            self.default_model = use_model

        messages = _normalize_messages(messages_or_prompt)
        system_parts: list[str] = []
        contents: list[dict] = []
        for item in messages:
            role = item["role"]
            text = item["content"]
            if role == "system":
                system_parts.append(text)
                continue
            gemini_role = "model" if role == "assistant" else "user"
            contents.append(
                {"role": gemini_role, "parts": [{"text": text}]}
            )
        if not contents:
            raise CopilotProviderError("Gemini requires at least one user message")

        payload: dict = {
            "contents": contents,
            "generationConfig": {"temperature": 0},
        }
        if system_parts:
            payload["systemInstruction"] = {
                "parts": [{"text": "\n\n".join(system_parts)}]
            }

        candidates = self._candidate_models(use_model, timeout=use_timeout)
        # Leave room for 2+ attempts when the overall budget is large enough.
        if len(candidates) > 1:
            per_attempt = min(
                _GEMINI_PER_ATTEMPT_TIMEOUT,
                max(_GEMINI_PER_ATTEMPT_MIN, use_timeout / 2.0),
            )
        else:
            per_attempt = min(_GEMINI_PER_ATTEMPT_TIMEOUT, use_timeout)
        per_attempt = min(per_attempt, use_timeout)

        last_error: Exception | None = None
        for index, candidate in enumerate(candidates):
            query = urllib.parse.urlencode({"key": self._api_key})
            url = f"{self.base_url}/models/{candidate}:generateContent?{query}"
            try:
                data = _post_json(url, payload, timeout=per_attempt)
            except CopilotHttpError as exc:
                last_error = exc
                if (
                    exc.status_code in _GEMINI_FALLBACK_HTTP
                    and index < len(candidates) - 1
                ):
                    logger.warning(
                        "Gemini model %s returned HTTP %s — trying fallback",
                        candidate,
                        exc.status_code,
                    )
                    continue
                raise
            except CopilotTimeoutError as exc:
                last_error = exc
                if index < len(candidates) - 1:
                    logger.warning(
                        "Gemini model %s timed out after %.0fs — trying fallback",
                        candidate,
                        per_attempt,
                    )
                    continue
                raise
            except CopilotProviderError as exc:
                last_error = exc
                raise

            text = _extract_gemini_text(data)
            if not text:
                last_error = CopilotProviderError("Gemini returned an empty response")
                if index < len(candidates) - 1:
                    logger.warning(
                        "Gemini model %s returned empty text — trying fallback",
                        candidate,
                    )
                    continue
                raise last_error

            if candidate != use_model:
                logger.info("Gemini fallback succeeded with model %s", candidate)
            self.default_model = candidate
            self._remember_success(candidate)
            return text

        if last_error is not None:
            raise last_error
        raise CopilotProviderError("Gemini generate failed with no candidate models")


def _extract_gemini_text(data: dict) -> str:
    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return ""
    first = candidates[0]
    if not isinstance(first, dict):
        return ""
    content = first.get("content") or {}
    if not isinstance(content, dict):
        return ""
    parts = content.get("parts") or []
    if not isinstance(parts, list):
        return ""
    chunks: list[str] = []
    for part in parts:
        if isinstance(part, dict) and part.get("text"):
            chunks.append(str(part["text"]))
    return "\n".join(chunks).strip()


def resolve_display_model(settings: CopilotEnvSettings) -> str:
    """Model string for status UI — resolves Gemini ``auto`` when possible."""
    if settings.provider != "gemini" or not is_auto_model(settings.model):
        return settings.model
    if not settings.gemini_api_key:
        return settings.model
    cached = get_cached_gemini_model(
        api_key=settings.gemini_api_key,
        base_url=settings.gemini_base_url,
        requested_model=settings.model,
    )
    if cached:
        return cached
    try:
        provider = GeminiProvider(
            api_key=settings.gemini_api_key,
            base_url=settings.gemini_base_url,
            default_model="auto",
            default_timeout=min(15.0, settings.timeout_seconds),
            resolve_model=True,
        )
        return provider.default_model
    except CopilotProviderError as exc:
        logger.debug("Gemini model auto-resolve deferred: %s", exc)
        return settings.model


def build_provider(
    settings: CopilotEnvSettings | None = None,
) -> LlmProvider:
    """Construct the configured provider from env settings."""
    resolved = settings if settings is not None else load_copilot_env_settings()
    if resolved.provider == "ollama":
        return OllamaProvider(
            base_url=resolved.ollama_base_url,
            default_model=resolved.model,
            default_timeout=resolved.timeout_seconds,
        )
    if resolved.provider == "openai_compat":
        if not resolved.openai_api_key:
            raise CopilotProviderError(
                "OPENAI_API_KEY is required when COPILOT_PROVIDER=openai_compat"
            )
        return OpenAICompatProvider(
            api_key=resolved.openai_api_key,
            base_url=resolved.openai_base_url,
            default_model=resolved.model,
            default_timeout=resolved.timeout_seconds,
        )
    if resolved.provider == "gemini":
        if not resolved.gemini_api_key:
            raise CopilotProviderError(
                "GEMINI_API_KEY is required when COPILOT_PROVIDER=gemini"
            )
        return GeminiProvider(
            api_key=resolved.gemini_api_key,
            base_url=resolved.gemini_base_url,
            default_model=resolved.model,
            default_timeout=resolved.timeout_seconds,
            resolve_model=True,
        )
    raise CopilotProviderError(f"Unknown COPILOT_PROVIDER: {resolved.provider!r}")
