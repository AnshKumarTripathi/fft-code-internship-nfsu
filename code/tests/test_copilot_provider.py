"""Unit tests for Phase 95 copilot provider + .env settings (mocked HTTP)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.config import ConfigError, copilot_settings
from src.copilot.provider import (
    CopilotProviderError,
    GeminiProvider,
    OllamaProvider,
    OpenAICompatProvider,
    build_provider,
    clear_gemini_model_cache,
    pick_gemini_model,
)
from src.copilot.settings import (
    CopilotEnvSettings,
    is_copilot_runtime_enabled,
    load_copilot_env_settings,
    load_dotenv_file,
)


@pytest.fixture(autouse=True)
def _clear_gemini_cache() -> None:
    clear_gemini_model_cache()
    yield
    clear_gemini_model_cache()


def _fake_urlopen(payload: dict) -> MagicMock:
    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps(payload).encode("utf-8")
    fake_response.__enter__.return_value = fake_response
    fake_response.__exit__.return_value = False
    return fake_response


def test_load_dotenv_file_does_not_override_existing_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    monkeypatch.setenv("COPILOT_MODEL", "already-set")
    env_path = tmp_path / ".env"
    env_path.write_text(
        "COPILOT_MODEL=from-file\nCOPILOT_ENABLED=true\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("COPILOT_ENABLED", raising=False)
    loaded = load_dotenv_file(env_path)
    assert loaded == env_path
    assert os.environ.get("COPILOT_MODEL") == "already-set"
    assert os.environ.get("COPILOT_ENABLED") == "true"


def test_load_copilot_env_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "COPILOT_ENABLED",
        "COPILOT_PROVIDER",
        "COPILOT_MODEL",
        "OLLAMA_BASE_URL",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_BASE_URL",
        "COPILOT_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(key, raising=False)
    settings = load_copilot_env_settings(load_dotenv=False)
    assert settings.enabled is False
    assert settings.provider == "ollama"
    assert settings.model == "qwen2.5:14b"
    assert settings.ollama_base_url == "http://127.0.0.1:11434"
    assert settings.openai_api_key is None
    assert settings.gemini_api_key is None
    assert settings.timeout_seconds == 120.0


def test_dual_gate_requires_yaml_and_env() -> None:
    env_on = CopilotEnvSettings(
        enabled=True,
        provider="ollama",
        model="m",
        ollama_base_url="http://127.0.0.1:11434",
        openai_api_key=None,
        openai_base_url="https://api.openai.com/v1",
        gemini_api_key=None,
        gemini_base_url="https://generativelanguage.googleapis.com/v1beta",
        timeout_seconds=30.0,
    )
    env_off = CopilotEnvSettings(
        enabled=False,
        provider="ollama",
        model="m",
        ollama_base_url="http://127.0.0.1:11434",
        openai_api_key=None,
        openai_base_url="https://api.openai.com/v1",
        gemini_api_key=None,
        gemini_base_url="https://generativelanguage.googleapis.com/v1beta",
        timeout_seconds=30.0,
    )
    assert is_copilot_runtime_enabled(yaml_enabled=True, env_settings=env_on) is True
    assert is_copilot_runtime_enabled(yaml_enabled=False, env_settings=env_on) is False
    assert is_copilot_runtime_enabled(yaml_enabled=True, env_settings=env_off) is False


def test_ollama_generate_prompt_mocked() -> None:
    provider = OllamaProvider(base_url="http://127.0.0.1:11434", default_model="m")
    fake = _fake_urlopen({"response": "  hello from ollama  "})
    with patch("urllib.request.urlopen", return_value=fake) as mock_open:
        text = provider.generate("Explain this incident.", model="m", timeout=5)
    assert text == "hello from ollama"
    request = mock_open.call_args[0][0]
    assert request.full_url.endswith("/api/generate")
    payload = json.loads(request.data.decode("utf-8"))
    assert payload["prompt"] == "Explain this incident."
    assert payload["options"]["temperature"] == 0


def test_ollama_generate_messages_uses_chat() -> None:
    provider = OllamaProvider(default_model="m")
    fake = _fake_urlopen({"message": {"role": "assistant", "content": "chat ok"}})
    with patch("urllib.request.urlopen", return_value=fake) as mock_open:
        text = provider.generate(
            [{"role": "user", "content": "hi"}],
            timeout=5,
        )
    assert text == "chat ok"
    assert mock_open.call_args[0][0].full_url.endswith("/api/chat")


def test_openai_compat_sends_bearer_and_never_leaks_key_on_http_error() -> None:
    secret = "sk-test-secret-should-not-appear"
    provider = OpenAICompatProvider(
        api_key=secret,
        base_url="https://example.test/v1",
        default_model="gpt-test",
    )
    http_error = __import__("urllib.error").error.HTTPError(
        url="https://example.test/v1/chat/completions",
        code=401,
        msg="Unauthorized",
        hdrs=None,
        fp=None,
    )
    with patch("urllib.request.urlopen", side_effect=http_error):
        with pytest.raises(CopilotProviderError, match="LLM HTTP 401") as caught:
            provider.generate("hello", timeout=5)
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)


def test_openai_compat_success_mocked() -> None:
    provider = OpenAICompatProvider(
        api_key="sk-lab",
        base_url="https://example.test/v1",
        default_model="gpt-test",
    )
    fake = _fake_urlopen(
        {
            "choices": [
                {"message": {"role": "assistant", "content": "compat reply"}}
            ]
        }
    )
    with patch("urllib.request.urlopen", return_value=fake) as mock_open:
        text = provider.generate(
            [{"role": "user", "content": "summarize"}],
            timeout=5,
        )
    assert text == "compat reply"
    request = mock_open.call_args[0][0]
    assert request.full_url.endswith("/chat/completions")
    auth = request.get_header("Authorization") or request.headers.get("Authorization")
    assert auth == "Bearer sk-lab"


def test_openai_compat_missing_key_on_construct() -> None:
    with pytest.raises(CopilotProviderError, match="OPENAI_API_KEY is required"):
        OpenAICompatProvider(api_key="  ")


def test_build_provider_openai_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COPILOT_PROVIDER", "openai_compat")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    settings = load_copilot_env_settings(load_dotenv=False)
    with pytest.raises(CopilotProviderError, match="OPENAI_API_KEY is required"):
        build_provider(settings)


def test_build_provider_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COPILOT_PROVIDER", "ollama")
    monkeypatch.setenv("COPILOT_MODEL", "lab-model")
    settings = load_copilot_env_settings(load_dotenv=False)
    provider = build_provider(settings)
    assert isinstance(provider, OllamaProvider)
    assert provider.default_model == "lab-model"


def test_gemini_env_defaults_to_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COPILOT_PROVIDER", "gemini")
    monkeypatch.delenv("COPILOT_MODEL", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    settings = load_copilot_env_settings(load_dotenv=False)
    assert settings.provider == "gemini"
    assert settings.model == "auto"
    assert settings.gemini_api_key == "test-gemini-key"


def test_pick_gemini_model_prefers_stable_flash() -> None:
    chosen = pick_gemini_model(
        [
            "models/embedding-001",
            "models/gemini-3.8-flash",
            "models/gemini-1.5-pro",
            "models/gemini-1.5-flash",
            "models/gemini-2.0-flash",
            "models/gemini-2.0-flash-exp",
            "models/gemini-2.0-flash-lite",
            "models/gemini-2.5-flash",
            "models/gemini-flash-latest",
        ]
    )
    assert chosen == "gemini-flash-latest"


def test_pick_gemini_model_avoids_bleeding_edge_when_stable_exists() -> None:
    chosen = pick_gemini_model(
        [
            "models/gemini-3.8-flash",
            "models/gemini-2.0-flash",
        ]
    )
    assert chosen == "gemini-2.0-flash"


def test_gemini_generate_mocked_auto_resolve() -> None:
    list_payload = {
        "models": [
            {
                "name": "models/gemini-1.5-flash",
                "supportedGenerationMethods": ["generateContent"],
            },
            {
                "name": "models/gemini-2.0-flash",
                "supportedGenerationMethods": ["generateContent"],
            },
            {
                "name": "models/text-embedding-004",
                "supportedGenerationMethods": ["embedContent"],
            },
        ]
    }
    gen_payload = {
        "candidates": [
            {"content": {"parts": [{"text": "  gemini reply  "}]}}
        ]
    }
    list_resp = _fake_urlopen(list_payload)
    gen_resp = _fake_urlopen(gen_payload)
    with patch(
        "urllib.request.urlopen",
        side_effect=[list_resp, gen_resp],
    ) as mock_open:
        provider = GeminiProvider(
            api_key="secret-gemini",
            default_model="auto",
            resolve_model=True,
            default_timeout=5,
        )
        assert provider.default_model == "gemini-2.0-flash"
        text = provider.generate(
            [
                {"role": "system", "content": "Be brief."},
                {"role": "user", "content": "Explain the incident."},
            ],
            timeout=5,
        )
    assert text == "gemini reply"
    assert "secret-gemini" not in str(mock_open.call_args_list)
    # Second call is generateContent — key only in query string, not error text.
    gen_req = mock_open.call_args_list[1][0][0]
    assert ":generateContent" in gen_req.full_url
    assert "gemini-2.0-flash" in gen_req.full_url
    payload = json.loads(gen_req.data.decode("utf-8"))
    assert payload["generationConfig"]["temperature"] == 0
    assert payload["systemInstruction"]["parts"][0]["text"] == "Be brief."


def test_gemini_reuses_cached_model_across_providers() -> None:
    list_payload = {
        "models": [
            {
                "name": "models/gemini-flash-latest",
                "supportedGenerationMethods": ["generateContent"],
            },
            {
                "name": "models/gemini-2.0-flash",
                "supportedGenerationMethods": ["generateContent"],
            },
        ]
    }
    gen_payload = {
        "candidates": [{"content": {"parts": [{"text": "first"}]}}]
    }
    gen_payload_2 = {
        "candidates": [{"content": {"parts": [{"text": "second"}]}}]
    }
    with patch(
        "urllib.request.urlopen",
        side_effect=[
            _fake_urlopen(list_payload),
            _fake_urlopen(gen_payload),
            _fake_urlopen(gen_payload_2),
        ],
    ) as mock_open:
        first = GeminiProvider(
            api_key="secret-gemini",
            default_model="auto",
            resolve_model=True,
            default_timeout=5,
        )
        assert first.default_model == "gemini-flash-latest"
        assert first.generate("hi", timeout=5) == "first"

        second = GeminiProvider(
            api_key="secret-gemini",
            default_model="auto",
            resolve_model=True,
            default_timeout=5,
        )
        assert second.default_model == "gemini-flash-latest"
        assert second.generate("hi again", timeout=5) == "second"

    urls = [call[0][0].full_url for call in mock_open.call_args_list]
    list_calls = [url for url in urls if "/models?" in url or url.rstrip("/").endswith("/models")]
    # Only the first provider should list models; the second uses the process cache.
    assert len(list_calls) == 1
    assert sum(1 for url in urls if ":generateContent" in url) == 2


def test_gemini_generate_falls_back_on_404() -> None:
    import urllib.error

    list_payload = {
        "models": [
            {
                "name": "models/gemini-2.5-flash",
                "supportedGenerationMethods": ["generateContent"],
            },
            {
                "name": "models/gemini-flash-latest",
                "supportedGenerationMethods": ["generateContent"],
            },
        ]
    }
    list_resp = _fake_urlopen(list_payload)
    http_404 = urllib.error.HTTPError(
        url="https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
        code=404,
        msg="Not Found",
        hdrs=None,
        fp=None,
    )
    gen_ok = _fake_urlopen(
        {"candidates": [{"content": {"parts": [{"text": "fallback ok"}]}}]}
    )
    provider = GeminiProvider(
        api_key="secret-gemini",
        default_model="gemini-2.5-flash",
        resolve_model=False,
        default_timeout=5,
    )
    with patch(
        "urllib.request.urlopen",
        side_effect=[list_resp, http_404, gen_ok],
    ) as mock_open:
        text = provider.generate("What is this project about?", timeout=5)
    assert text == "fallback ok"
    assert provider.default_model == "gemini-flash-latest"
    urls = [call[0][0].full_url for call in mock_open.call_args_list]
    assert any("gemini-2.5-flash:generateContent" in u for u in urls)
    assert any("gemini-flash-latest:generateContent" in u for u in urls)


def test_gemini_generate_falls_back_on_timeout() -> None:
    list_payload = {
        "models": [
            {
                "name": "models/gemini-2.5-flash",
                "supportedGenerationMethods": ["generateContent"],
            },
            {
                "name": "models/gemini-flash-latest",
                "supportedGenerationMethods": ["generateContent"],
            },
        ]
    }
    list_resp = _fake_urlopen(list_payload)
    gen_ok = _fake_urlopen(
        {"candidates": [{"content": {"parts": [{"text": "after timeout"}]}}]}
    )
    provider = GeminiProvider(
        api_key="secret-gemini",
        default_model="gemini-2.5-flash",
        resolve_model=False,
        default_timeout=90,
    )
    with patch(
        "urllib.request.urlopen",
        side_effect=[list_resp, TimeoutError("slow"), gen_ok],
    ) as mock_open:
        text = provider.generate("hello", timeout=90)
    assert text == "after timeout"
    assert provider.default_model == "gemini-flash-latest"
    assert any(
        "gemini-flash-latest:generateContent" in call[0][0].full_url
        for call in mock_open.call_args_list
        if call[0]
    )


def test_build_provider_gemini_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COPILOT_PROVIDER", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    settings = load_copilot_env_settings(load_dotenv=False)
    with pytest.raises(CopilotProviderError, match="GEMINI_API_KEY is required"):
        build_provider(settings)


def test_copilot_settings_defaults() -> None:
    settings = copilot_settings({})
    assert settings["enabled"] is False
    assert settings["max_attachment_chars"] == 4000
    assert settings["ai_insight"]["enabled"] is False


def test_copilot_settings_rejects_bad_enabled() -> None:
    with pytest.raises(ConfigError, match="copilot.enabled"):
        copilot_settings({"copilot": {"enabled": "yes"}})
