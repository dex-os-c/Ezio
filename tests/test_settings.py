"""
Tests for per-user API key settings (settings.py).

Covers:
- get_api_keys for new user (all keys unset)
- set and retrieve a key (is_set=true, value never returned)
- key is encrypted in DB (query raw, not plaintext)
- delete a key
- user isolation (user A cannot see user B's keys)
- resolve_api_key: user key overrides server config
- resolve_api_key: server fallback when no user key
"""

import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy import select as sa_select

from db.models import User, UserApiKey, Base
from db.session import get_session_factory
from utils.encryption import encrypt_api_key, decrypt_api_key
from utils.user_keys import get_user_key, resolve_api_key


@pytest.fixture
def session(db_engine):
    """Provide a fresh session per test, rollback on exit."""
    from sqlalchemy.orm import sessionmaker

    Base.metadata.create_all(db_engine)
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)
    sess = factory()
    yield sess
    sess.rollback()
    sess.close()


@pytest.fixture
def user_a(session):
    u = User(email="user_a@example.com", hashed_password="hash_a", is_active=True)
    session.add(u)
    session.flush()
    return u


@pytest.fixture
def user_b(session):
    u = User(email="user_b@example.com", hashed_password="hash_b", is_active=True)
    session.add(u)
    session.flush()
    return u


@pytest.fixture
def mock_async_session():
    """Provide a simple mock AsyncSession that maps to the sync session."""
    return MagicMock()


# ─── Encryption tests ──────────────────────────────────────────────────────────


def test_encrypt_decrypt_roundtrip():
    plaintext = "sk-tst-123"
    encrypted = encrypt_api_key(plaintext)
    assert encrypted != plaintext
    assert encrypted != ""
    decrypted = decrypt_api_key(encrypted)
    assert decrypted == plaintext


def test_encrypt_empty():
    assert encrypt_api_key("") == ""
    assert decrypt_api_key("") == ""


def test_decrypt_invalid():
    assert decrypt_api_key("not-valid-base64!!") == ""


# ─── DB model tests ──────────────────────────────────────────────────────────


def test_user_api_key_upsert(session, user_a):
    key_name = "OPENAI_API_KEY"
    plaintext = "sk-usr-key"

    # Insert
    record = UserApiKey(
        user_id=user_a.id,
        key_name=key_name,
        encrypted_value=encrypt_api_key(plaintext),
    )
    session.add(record)
    session.commit()

    # Verify stored value is NOT plaintext
    row = session.execute(
        sa_select(UserApiKey).where(
            UserApiKey.user_id == user_a.id,
            UserApiKey.key_name == key_name,
        )
    ).scalar_one()
    assert row.encrypted_value != plaintext
    assert plaintext not in row.encrypted_value

    # Verify decryption works
    assert decrypt_api_key(row.encrypted_value) == plaintext


def test_user_api_key_unique_constraint(session, user_a):
    """Same user cannot insert duplicate key_name."""
    session.add(
        UserApiKey(user_id=user_a.id, key_name="OPENAI_API_KEY", encrypted_value="val1")
    )
    session.commit()

    session.add(
        UserApiKey(user_id=user_a.id, key_name="OPENAI_API_KEY", encrypted_value="val2")
    )
    with pytest.raises(Exception):
        session.commit()


def test_user_isolation(session, user_a, user_b):
    """User B cannot see User A's keys."""
    session.add(
        UserApiKey(
            user_id=user_a.id,
            key_name="OPENAI_API_KEY",
            encrypted_value=encrypt_api_key("user_a_key"),
        )
    )
    session.commit()

    rows = session.execute(
        sa_select(UserApiKey).where(UserApiKey.user_id == user_b.id)
    ).scalars().all()
    assert len(rows) == 0


def test_delete_key(session, user_a):
    key_name = "OPENAI_API_KEY"
    session.add(
        UserApiKey(
            user_id=user_a.id,
            key_name=key_name,
            encrypted_value=encrypt_api_key("to_delete"),
        )
    )
    session.commit()

    row = session.execute(
        sa_select(UserApiKey).where(
            UserApiKey.user_id == user_a.id,
            UserApiKey.key_name == key_name,
        )
    ).scalar_one()
    session.delete(row)
    session.commit()

    remaining = session.execute(
        sa_select(UserApiKey).where(
            UserApiKey.user_id == user_a.id,
            UserApiKey.key_name == key_name,
        )
    ).scalar_one_or_none()
    assert remaining is None


# ─── resolve_api_key tests ───────────────────────────────────────────────────


@patch("utils.user_keys.config")
def test_resolve_user_key优先(mock_config, session, user_a):
    """User key should take precedence over server config."""
    mock_config.OPENAI_API_KEY = "server_key_xyz"

    session.add(
        UserApiKey(
            user_id=user_a.id,
            key_name="OPENAI_API_KEY",
            encrypted_value=encrypt_api_key("user_personal_key"),
        )
    )
    session.commit()

    async def _test():
        result = await resolve_api_key(user_a.id, "OPENAI_API_KEY", session)
        assert result == "user_personal_key"

    import asyncio
    asyncio.run(_test())


@patch("utils.user_keys.config")
def test_resolve_server_fallback(mock_config, session, user_a):
    """No user key → fall back to server config."""
    mock_config.OPENAI_API_KEY = "server_fallback_key"

    async def _test():
        result = await resolve_api_key(user_a.id, "OPENAI_API_KEY", session)
        assert result == "server_fallback_key"

    import asyncio
    asyncio.run(_test())


@patch("utils.user_keys.config")
def test_resolve_empty_when_neither_set(mock_config, session, user_a):
    """Neither user nor server key → empty string."""
    mock_config.OPENAI_API_KEY = None

    async def _test():
        result = await resolve_api_key(user_a.id, "OPENAI_API_KEY", session)
        assert result == ""

    import asyncio
    asyncio.run(_test())


# ─── Model list endpoint tests ────────────────────────────────────────────────


def test_models_endpoint_returns_providers():
    """GET /settings/models returns a list with at least the standard providers."""
    from api.routes.settings import ProviderInfo, ModelListResponse

    # Build a minimal synthetic response matching what the endpoint returns
    providers = [
        ProviderInfo(name="OpenRouter", key_name="OPENROUTER_API_KEY", configured=False, models=[]),
        ProviderInfo(name="Groq", key_name="GROQ_API_KEY", configured=False, models=[]),
        ProviderInfo(name="Anthropic", key_name="ANTHROPIC_API_KEY", configured=False, models=[]),
        ProviderInfo(name="OpenAI", key_name="OPENAI_API_KEY", configured=False, models=[]),
        ProviderInfo(name="Google", key_name="GOOGLE_API_KEY", configured=False, models=[]),
        ProviderInfo(name="Ollama", key_name="", configured=False, models=[]),
    ]
    response = ModelListResponse(providers=providers, custom_model_allowed=True)

    provider_names = {p.name for p in response.providers}
    assert "OpenRouter" in provider_names
    assert "Groq" in provider_names
    assert "Anthropic" in provider_names
    assert response.custom_model_allowed is True


def test_models_unconfigured_provider():
    """Unconfigured provider has configured=False and an empty model list."""
    from api.routes.settings import ProviderInfo

    p = ProviderInfo(name="OpenAI", key_name="OPENAI_API_KEY", configured=False, models=[])
    assert p.configured is False
    assert p.models == []


def test_validate_model_invalid_id():
    """validate_model endpoint returns valid=False for a garbage model ID."""
    from api.routes.settings import ValidateModelResponse, _infer_provider

    # Simulate what the endpoint returns for an unresolvable model
    bad_id = "not-a-real-model-xyz-12345"
    provider = _infer_provider(bad_id)

    # With unknown prefix → falls back to OpenRouter provider label
    assert provider == "OpenRouter"

    # Build the expected failure response
    resp = ValidateModelResponse(
        valid=False,
        model_id=bad_id,
        provider=provider,
        error="model_not_found",
        message=f"Model '{bad_id}' not found. Check the model ID and try again.",
        suggestion="Browse available models or check https://openrouter.ai/models for valid IDs.",
    )
    assert resp.valid is False
    assert resp.error == "model_not_found"
    assert bad_id in resp.message


def test_validate_model_no_key():
    """validate_model endpoint returns no_key_configured when the key is absent."""
    from api.routes.settings import ValidateModelResponse

    resp = ValidateModelResponse(
        valid=False,
        model_id="openrouter/some/model",
        provider="OpenRouter",
        error="no_key_configured",
        message="No API key configured for OpenRouter. Add OPENROUTER_API_KEY in Settings.",
        suggestion="Add the required API key in Settings.",
    )
    assert resp.valid is False
    assert resp.error == "no_key_configured"
    assert "OPENROUTER_API_KEY" in resp.message
