"""
Tests for dynamic model routing in llm_utils.py.

Covers:
- openrouter/ prefix routes to OpenRouter (ChatOpenAI with OpenRouter base_url)
- Unknown prefix falls back to OpenRouter with a warning log
- Missing API key raises ValueError with a helpful message
"""

import logging
import pytest
from unittest.mock import patch


# ─── Prefix routing tests ────────────────────────────────────────────────────


def test_get_llm_openrouter_prefix():
    """Model ID starting with openrouter/ should route to OpenRouter (ChatOpenAI)."""
    from ezio.llm_utils import resolve_model_config
    from langchain_openai import ChatOpenAI

    config = resolve_model_config("openrouter/deepseek/deepseek-chat")
    assert config is not None, "Expected a config dict for openrouter/ prefix"
    assert config["class"] is ChatOpenAI
    ctor = config.get("constructor_params", {})
    # The actual model name should strip the openrouter/ prefix
    assert "deepseek/deepseek-chat" in ctor.get("model_name", "")
    # Should point to OpenRouter base URL
    assert "openrouter" in (ctor.get("base_url", "") or "").lower()


def test_get_llm_groq_prefix():
    """Model ID starting with groq/ should route to Groq (ChatOpenAI at Groq URL)."""
    from ezio.llm_utils import resolve_model_config
    from langchain_openai import ChatOpenAI

    config = resolve_model_config("groq/llama-3.3-70b-versatile")
    assert config is not None
    assert config["class"] is ChatOpenAI
    ctor = config.get("constructor_params", {})
    assert "groq.com" in (ctor.get("base_url", "") or "").lower()


def test_get_llm_gpt_prefix():
    """Model ID starting with gpt- routes to OpenAI (ChatOpenAI)."""
    from ezio.llm_utils import resolve_model_config
    from langchain_openai import ChatOpenAI

    config = resolve_model_config("gpt-4o-mini")
    assert config is not None
    assert config["class"] is ChatOpenAI
    ctor = config.get("constructor_params", {})
    assert "gpt-4o-mini" in (ctor.get("model_name", "") or "")


def test_get_llm_claude_prefix():
    """Model ID starting with claude- routes to Anthropic (ChatAnthropic)."""
    from ezio.llm_utils import resolve_model_config
    from langchain_anthropic import ChatAnthropic

    config = resolve_model_config("claude-3-5-sonnet-20241022")
    assert config is not None
    assert config["class"] is ChatAnthropic


def test_get_llm_gemini_prefix():
    """Model ID starting with gemini- routes to Google (ChatGoogleGenerativeAI)."""
    from ezio.llm_utils import resolve_model_config
    from langchain_google_genai import ChatGoogleGenerativeAI

    config = resolve_model_config("gemini-1.5-flash")
    assert config is not None
    assert config["class"] is ChatGoogleGenerativeAI


def test_get_llm_ollama_prefix():
    """Model ID starting with ollama/ routes to Ollama (ChatOllama)."""
    from ezio.llm_utils import resolve_model_config
    from langchain_ollama import ChatOllama

    config = resolve_model_config("ollama/llama3.2:latest")
    assert config is not None
    assert config["class"] is ChatOllama
    ctor = config.get("constructor_params", {})
    assert "llama3.2:latest" in (ctor.get("model", "") or "")


def test_get_llm_unknown_prefix_fallback(caplog):
    """Unknown prefix falls back to OpenRouter and logs a warning."""
    from ezio.llm_utils import resolve_model_config
    from langchain_openai import ChatOpenAI

    with caplog.at_level(logging.WARNING):
        config = resolve_model_config("totally-unknown-provider/some-model")

    assert config is not None
    assert config["class"] is ChatOpenAI
    ctor = config.get("constructor_params", {})
    assert "openrouter" in (ctor.get("base_url", "") or "").lower()
    # Should have logged a warning about unknown prefix
    assert any("Unknown model prefix" in r.message for r in caplog.records)


# ─── Missing key tests ────────────────────────────────────────────────────────


def test_get_llm_no_key_raises_valueerror_openrouter():
    """_make_openrouter_llm raises ValueError when no OPENROUTER_API_KEY is set."""
    from ezio.llm_utils import _make_openrouter_llm

    with patch("ezio.llm_utils.OPENROUTER_API_KEY", None):
        with pytest.raises(ValueError, match="No API key configured for OpenRouter"):
            _make_openrouter_llm("deepseek/deepseek-chat", api_keys={})


def test_get_llm_no_key_raises_valueerror_groq():
    """_make_groq_llm raises ValueError when no GROQ_API_KEY is set."""
    from ezio.llm_utils import _make_groq_llm

    with patch("ezio.llm_utils.GROQ_API_KEY", None):
        with pytest.raises(ValueError, match="No API key configured for Groq"):
            _make_groq_llm("llama-3.3-70b-versatile", api_keys={})


def test_get_llm_no_key_raises_valueerror_openai():
    """_make_openai_llm raises ValueError when no OPENAI_API_KEY is set."""
    from ezio.llm_utils import _make_openai_llm

    with patch("ezio.llm_utils.OPENAI_API_KEY", None):
        with pytest.raises(ValueError, match="No API key configured for OpenAI"):
            _make_openai_llm("gpt-4o", api_keys={})


def test_get_llm_no_key_raises_valueerror_anthropic():
    """_make_anthropic_llm raises ValueError when no ANTHROPIC_API_KEY is set."""
    from ezio.llm_utils import _make_anthropic_llm

    with patch("ezio.llm_utils.ANTHROPIC_API_KEY", None):
        with pytest.raises(ValueError, match="No API key configured for Anthropic"):
            _make_anthropic_llm("claude-3-5-sonnet-20241022", api_keys={})


def test_user_key_overrides_missing_server_key():
    """A user-provided API key satisfies the key check even when server key is absent."""
    from ezio.llm_utils import _make_openrouter_llm

    with patch("ezio.llm_utils.OPENROUTER_API_KEY", None):
        # Should NOT raise — user key is provided in api_keys
        with patch("langchain_openai.ChatOpenAI.__init__", return_value=None):
            _make_openrouter_llm(
                "deepseek/deepseek-chat",
                api_keys={"OPENROUTER_API_KEY": "sk-user-override-key"},
            )
            # If no ValueError was raised, the test passes
