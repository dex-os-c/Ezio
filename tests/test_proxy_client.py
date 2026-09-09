"""
tests/test_proxy_client.py — Unit tests for sources/proxy_client.py.

Phase 1.6 (corrected per architect review) — tests the single-transport
selection logic in ``clearnet_fetch``:

    transport:  "direct" | "api" | "proxy"

Plus the .onion guard (must fire first, unconditionally), the silent
fallback to direct on any failure, the single-credential design (only
SCRAPINGANT_API_KEY exists), the Proxy Mode username built per docs
("scrapingant&browser=false&proxy_type=..."), the single proxy host
(proxy.scrapingant.com:8080), and the mutually-exclusive behavior of
EZIO_USE_PROXIES vs EZIO_USE_PROXY (proxy wins if both).

Per https://docs.scrapingant.com/proxy-mode:
    "Proxy Mode is a light front-end for the scraping API and has all
    the same functionality and performance as sending requests to the
    API endpoint."

No real network connections. All aiohttp calls are mocked.
No real env vars. All env mutations use monkeypatch.

Run with:
    pytest tests/test_proxy_client.py -v
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from urllib.parse import unquote

import pytest

from sources.proxy_client import (
    MAX_RESPONSE_BYTES,
    SCRAPINGANT_PROXY_HOST,
    SCRAPINGANT_PROXY_HTTPS_PORT,
    SCRAPINGANT_PROXY_PORT,
    _build_proxy_username,
    _get_proxy_url,
    clearnet_fetch,
    is_api_transport_enabled,
    is_proxy_transport_enabled,
    select_transport,
)


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


class _MockResponse:
    """Lightweight fake aiohttp response.

    Supports:
        - ``.status``  (int)
        - ``.headers`` (dict-like; ``.get()`` is the only method used)
        - ``.read()``  (async; returns bytes)
        - ``async with`` context manager protocol
    """

    def __init__(self, *, status: int, headers: dict, body: bytes):
        self.status = status
        self.headers = headers
        self._body = body

    async def read(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None


class _RaisingCM:
    """Async context manager that raises the given exception on enter."""

    def __init__(self, exc):
        self.exc = exc

    async def __aenter__(self):
        raise self.exc

    async def __aexit__(self, exc_type, exc, tb):
        return None


class _MockSession:
    """Fake aiohttp.ClientSession that dispatches pre-queued responses.

    Records every .get() and .request() call (with their kwargs) so
    tests can assert on what the chokepoint actually sent over the wire.
    """

    def __init__(self, *, get_queue=None, request_queue=None):
        self.get_queue = list(get_queue or [])
        self.request_queue = list(request_queue or [])
        self.get_calls: list[tuple] = []
        self.request_calls: list[tuple] = []

    def _dispatch(self, queue, resp_or_exc):
        if isinstance(resp_or_exc, BaseException):
            return _RaisingCM(resp_or_exc)
        return resp_or_exc

    def get(self, *args, **kwargs):
        self.get_calls.append((args, kwargs))
        if not self.get_queue:
            raise AssertionError(
                f"MockSession.get called with no response configured (url={args[0] if args else '?'})"
            )
        return self._dispatch(self.get_queue, self.get_queue.pop(0))

    def request(self, *args, **kwargs):
        self.request_calls.append((args, kwargs))
        if not self.request_queue:
            raise AssertionError(
                "MockSession.request called with no response configured "
                f"(method={args[0] if args else '?'} url={args[1] if len(args) > 1 else '?'})"
            )
        return self._dispatch(self.request_queue, self.request_queue.pop(0))


def _scrub_proxy_env(monkeypatch):
    """Remove every proxy-related env var so each test starts from a known state."""
    for k in (
        "SCRAPINGANT_API_KEY",
        "SCRAPINGANT_PROXY_USERNAME",
        "SCRAPINGANT_PROXY_PASSWORD",
        "EZIO_USE_PROXIES",
        "EZIO_USE_PROXY",
        "SCRAPINGANT_PROXY_TYPE",
    ):
        monkeypatch.delenv(k, raising=False)


# ---------------------------------------------------------------------------
# Module-level guarantees
# ---------------------------------------------------------------------------


def test_module_never_imports_scraper():
    """sources/proxy_client.py must NOT import anything from scraper/ —
    this preserves the sources/scraper firewall.

    Verified by AST parse of the source file: any ``import scraper`` or
    ``from scraper.*`` would be flagged.
    """
    proxy_client_path = (
        Path(__file__).resolve().parent.parent / "sources" / "proxy_client.py"
    )
    source = proxy_client_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    bad_imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "scraper" or mod.startswith("scraper."):
                bad_imports.append(f"from {mod} import ...")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name == "scraper" or name.startswith("scraper."):
                    bad_imports.append(f"import {name}")

    assert not bad_imports, (
        "sources/proxy_client.py violates the sources/scraper firewall: "
        + ", ".join(bad_imports)
    )


def test_module_does_not_export_old_proxy_mode_surface():
    """Per https://docs.scrapingant.com/proxy-mode §Integration details,
    the Proxy Mode username is the literal constant "scrapingant" plus
    runtime parameters. There is NO per-customer username credential.

    This test guards against future regressions: if anyone re-introduces
    a SCRAPINGANT_PROXY_USERNAME constant or a _get_proxy_username()
    function, the test will fail.
    """
    import sources.proxy_client as mod

    forbidden = [
        "SCRAPINGANT_PROXY_TYPE",
        "_get_proxy_type",
        "SCRAPINGANT_PROXY_HOST_RESIDENTIAL",  # single host, not two
        "SCRAPINGANT_PROXY_HOST_DATACENTER",   # single host, not two
        "is_residential_proxy_enabled",     # replaced by is_proxy_transport_enabled
        "is_scraping_api_enabled",          # replaced by is_api_transport_enabled
    ]
    for name in forbidden:
        assert not hasattr(mod, name), (
            f"sources/proxy_client.py exports forbidden old Proxy Mode name {name!r}."
        )


def test_module_exports_expected_public_surface():
    """Public surface is small and intentional: the chokepoint, the two
    transport selectors, the single transport chooser, and constants for
    introspection. Internal helpers are present (sanity) but not in the
    public API.
    """
    import sources.proxy_client as mod

    public = {
        "clearnet_fetch",                 # the chokepoint
        "select_transport",               # the single-transport chooser
        "is_api_transport_enabled",       # REST API transport predicate
        "is_proxy_transport_enabled",     # Proxy Mode transport predicate
        "MAX_RESPONSE_BYTES",
        "SCRAPINGANT_BASE_URL",
        "SCRAPINGANT_PROXY_HOST",
        "SCRAPINGANT_PROXY_PORT",
        "SCRAPINGANT_PROXY_HTTPS_PORT",
    }
    for name in public:
        assert hasattr(mod, name), f"missing public symbol: {name}"

    # Internal helpers exist for testability.
    assert hasattr(mod, "_fetch_via_scrapingant")
    assert hasattr(mod, "_fetch_via_proxy_mode")
    assert hasattr(mod, "_fetch_direct")
    assert hasattr(mod, "_get_api_key")
    assert hasattr(mod, "_get_proxy_credentials")
    assert hasattr(mod, "_build_proxy_username")
    assert hasattr(mod, "_get_proxy_url")
    assert not hasattr(mod, "__all__"), (
        "module should not declare __all__ — let public symbols be implicit"
    )


def test_max_response_bytes_matches_scraper_cap():
    """MAX_RESPONSE_BYTES must match scraper/scrape.py's MAX_DOWNLOAD_BYTES.
    If scrape.py changes its cap, this test fails — a deliberate tripwire
    that forces a synchronized update in both locations."""
    scrape_path = (
        Path(__file__).resolve().parent.parent / "scraper" / "scrape.py"
    )
    source = scrape_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "MAX_DOWNLOAD_BYTES"
        ):
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, int):
                assert value.value == MAX_RESPONSE_BYTES, (
                    f"MAX_DOWNLOAD_BYTES in scraper/scrape.py = {value.value}, "
                    f"but sources/proxy_client.MAX_RESPONSE_BYTES = {MAX_RESPONSE_BYTES}. "
                    "These must match — update both in the same commit."
                )
                return
    pytest.fail(
        "Could not locate MAX_DOWNLOAD_BYTES = <int> assignment in scraper/scrape.py"
    )


# ---------------------------------------------------------------------------
# .onion guard — must be unconditional, first check, regardless of transport
# ---------------------------------------------------------------------------


def test_onion_url_refused_with_api_transport(monkeypatch):
    """is_api_transport_enabled() is True, but the .onion guard still fires
    first. No network call is made — neither API nor direct."""
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    session = _MockSession()  # No queues — any .get/.request raises AssertionError

    with pytest.raises(ValueError, match=r"refuses \.onion URLs"):
        asyncio.run(
            clearnet_fetch(
                "http://abcdef.onion/some/path",
                expect="text",
                fallback_session=session,
            )
        )

    assert session.get_calls == []
    assert session.request_calls == []


def test_onion_url_refused_with_proxy_transport(monkeypatch):
    """is_proxy_transport_enabled() is True, but the .onion guard still
    fires first. No network call is made — neither proxy nor direct."""
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")

    session = _MockSession()

    with pytest.raises(ValueError, match=r"refuses \.onion URLs"):
        asyncio.run(
            clearnet_fetch(
                "http://xyzabc.onion/article",
                expect="html",
                fallback_session=session,
            )
        )

    assert session.get_calls == []
    assert session.request_calls == []


def test_onion_url_refused_with_no_transport(monkeypatch):
    """No transport env vars set, but the .onion guard still fires first.
    This proves the guard is checked BEFORE any transport is even evaluated."""
    _scrub_proxy_env(monkeypatch)

    session = _MockSession()

    with pytest.raises(ValueError, match=r"refuses \.onion URLs"):
        asyncio.run(
            clearnet_fetch(
                "http://abcdef.onion",
                expect="html",
                fallback_session=session,
            )
        )

    assert session.get_calls == []
    assert session.request_calls == []


def test_onion_url_refused_with_both_transports_set(monkeypatch):
    """Both transport env vars set (which means Proxy Mode wins), but the
    .onion guard still fires first."""
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")

    session = _MockSession()

    with pytest.raises(ValueError, match=r"refuses \.onion URLs"):
        asyncio.run(
            clearnet_fetch(
                "http://abcdef.onion",
                expect="html",
                fallback_session=session,
            )
        )

    assert session.get_calls == []
    assert session.request_calls == []


# ---------------------------------------------------------------------------
# Transport predicates — is_api_transport_enabled + is_proxy_transport_enabled
# ---------------------------------------------------------------------------


def test_api_transport_disabled_no_key(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    assert is_api_transport_enabled() is False


def test_api_transport_disabled_key_set_flag_false(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key-123")
    assert is_api_transport_enabled() is False


def test_api_transport_disabled_flag_set_no_key(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")
    assert is_api_transport_enabled() is False


def test_api_transport_enabled_key_and_flag_set(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")
    assert is_api_transport_enabled() is True


def test_api_transport_flag_case_insensitive(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    for value in ("true", "TRUE", "True", "tRuE"):
        monkeypatch.setenv("EZIO_USE_PROXIES", value)
        assert is_api_transport_enabled() is True, f"failed for value {value!r}"


def test_api_transport_disabled_key_blank(monkeypatch):
    """A blank/whitespace-only API key is treated as no key."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "   ")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")
    assert is_api_transport_enabled() is False


def test_proxy_transport_disabled_no_credentials(monkeypatch):
    """No API key — Proxy Mode transport is unavailable regardless of flag."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("EZIO_USE_PROXY", "true")
    assert is_proxy_transport_enabled() is False


def test_proxy_transport_disabled_no_flag(monkeypatch):
    """Key set but flag unset — Proxy Mode transport is unavailable."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    assert is_proxy_transport_enabled() is False


def test_proxy_transport_enabled_credentials_and_flag_set(monkeypatch):
    """Key + flag set — Proxy Mode transport is available.
    No per-customer username required (per docs)."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")
    assert is_proxy_transport_enabled() is True


def test_proxy_transport_flag_case_insensitive(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    for value in ("true", "TRUE", "True", "tRuE"):
        monkeypatch.setenv("EZIO_USE_PROXY", value)
        assert is_proxy_transport_enabled() is True, f"failed for value {value!r}"


def test_proxy_transport_requires_both_credentials(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("EZIO_USE_PROXY", "true")
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    assert is_proxy_transport_enabled() is False

    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("EZIO_USE_PROXY", "true")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    assert is_proxy_transport_enabled() is False


def test_api_key_alone_does_not_activate_proxy_transport(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "api-key-only")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")
    assert is_proxy_transport_enabled() is False
    assert select_transport() == "direct"


# ---------------------------------------------------------------------------
# select_transport() — mutually exclusive, proxy wins on conflict
# ---------------------------------------------------------------------------


def test_select_transport_default_is_direct(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    assert select_transport() == "direct"


def test_select_transport_only_api(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")
    assert select_transport() == "api"


def test_select_transport_only_proxy(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")
    assert select_transport() == "proxy"


def test_select_transport_both_set_proxy_wins(monkeypatch):
    """Per docs, Proxy Mode is "the same functionality" as the API —
    chaining them would double-charge. Proxy wins, with a one-shot info log."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")

    import sources.proxy_client as mod
    monkeypatch.setattr(mod, "_BOTH_GATES_WARNED", False)

    assert select_transport() == "proxy"


def test_select_transport_api_disabled_no_key(monkeypatch):
    """No key — both predicates are False, default to direct."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")
    assert select_transport() == "direct"


# ---------------------------------------------------------------------------
# Proxy Mode username string — built per docs at call time
# ---------------------------------------------------------------------------


def test_build_proxy_username_uses_dashboard_username(monkeypatch):
    """Default proxy type produces scrapingant&browser=false&proxy_type=residential."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "katriel.moses8poQrr")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    assert _build_proxy_username() == "katriel.moses8poQrr"
    assert "scrapingant&" not in _build_proxy_username()


def test_build_proxy_username_returns_empty_without_credentials(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    assert _build_proxy_username() == ""


# ---------------------------------------------------------------------------
# _get_proxy_url() — single host, URL-encoded userinfo
# ---------------------------------------------------------------------------


def test_get_proxy_url_uses_residential_host_and_credentials(monkeypatch):
    """Single documented host (proxy.scrapingant.com:8080) regardless of pool type."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "api-key-must-not-be-used")
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser123")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass456")
    url = _get_proxy_url()
    assert url is not None
    assert f"@{SCRAPINGANT_PROXY_HOST}:{SCRAPINGANT_PROXY_PORT}" in url
    assert url.startswith("http://")
    # Username in URL is URL-encoded; decoding it should yield the docs form.
    after_scheme = url[len("http://"):]
    userinfo, _, hostport = after_scheme.partition("@")
    user_decoded = unquote(userinfo.split(":", 1)[0])
    pass_decoded = unquote(userinfo.split(":", 1)[1])
    assert user_decoded == "testuser123"
    assert pass_decoded == "testpass456"
    assert hostport == f"{SCRAPINGANT_PROXY_HOST}:{SCRAPINGANT_PROXY_PORT}"
    assert SCRAPINGANT_PROXY_HOST == "residential.scrapingant.com"
    assert SCRAPINGANT_PROXY_PORT == 8080
    assert SCRAPINGANT_PROXY_HTTPS_PORT == 443
    assert "proxy.scrapingant.com" not in url
    assert "scrapingant&" not in url
    assert "api-key-must-not-be-used" not in url


def test_get_proxy_url_single_host_datacenter(monkeypatch):
    """Pool type does NOT change the host — it's a username parameter."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    url = _get_proxy_url()
    assert url is not None
    assert f"@{SCRAPINGANT_PROXY_HOST}:{SCRAPINGANT_PROXY_PORT}" in url
    after_scheme = url[len("http://"):]
    userinfo, _, hostport = after_scheme.partition("@")
    user_decoded = unquote(userinfo.split(":", 1)[0])
    assert user_decoded == "testuser"
    assert hostport == f"{SCRAPINGANT_PROXY_HOST}:{SCRAPINGANT_PROXY_PORT}"
    assert SCRAPINGANT_PROXY_HOST == "residential.scrapingant.com"
    assert "scrapingant&" not in url


def test_get_proxy_url_returns_none_when_credentials_missing(monkeypatch):
    """Without SCRAPINGANT_API_KEY, _get_proxy_url() returns None."""
    _scrub_proxy_env(monkeypatch)
    assert _get_proxy_url() is None
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    assert _get_proxy_url() is None
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    assert _get_proxy_url() is None


def test_get_proxy_url_handles_special_chars_in_credentials(monkeypatch):
    """API keys with URL-special characters get percent-encoded."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "user&with=special@chars")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "pass&with=special@chars")
    url = _get_proxy_url()
    assert url is not None
    # The raw `&`, `=`, `@` in the key must NOT appear unescaped in the
    # userinfo portion (they would break URL parsing).
    after_scheme = url[len("http://"):]
    userinfo, _, _hostport = after_scheme.partition("@")
    # userinfo should be percent-encoded: every `&` and `=` outside the
    # initial password field would be ambiguous.
    assert "user&with" not in userinfo
    assert "pass&with" not in userinfo
    assert "%26" in userinfo


# ---------------------------------------------------------------------------
# Dispatch — direct (no transport env vars)
# ---------------------------------------------------------------------------


def test_dispatch_no_transport_direct_only(monkeypatch):
    """No transport env vars set — the chokepoint goes direct.
    This is byte-for-byte the v1.5.0 behavior and the regression baseline."""
    _scrub_proxy_env(monkeypatch)

    body = b"v1.5.0 direct fetch body"
    session = _MockSession(
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "text/plain"}, body=body,
        )]
    )
    status, _ctype, returned_body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )

    assert status == 200
    assert returned_body == body
    assert session.get_calls == [], "ScrapingAnt should not have been called"
    assert len(session.request_calls) == 1, "Direct fetch should have been called exactly once"


# ---------------------------------------------------------------------------
# Dispatch — REST API transport (legacy EZIO_USE_PROXIES)
# ---------------------------------------------------------------------------


def test_dispatch_api_transport_success(monkeypatch):
    """REST API transport enabled → first attempt hits ScrapingAnt API."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    api_body = b"<rss>api response</rss>"
    session = _MockSession(
        get_queue=[_MockResponse(
            status=200,
            headers={
                "content-type": "application/json",
                "ant-page-status-code": "200",
                "ant-original-header-content-type": "application/rss+xml",
            },
            body=api_body,
        )]
    )
    status, ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/feed.xml", expect="xml", fallback_session=session)
    )

    assert status == 200
    assert ctype == "application/rss+xml"
    assert body == api_body
    assert len(session.get_calls) == 1, "ScrapingAnt API should have been called"
    assert session.request_calls == [], "Direct fetch should not have been called"


def test_dispatch_api_transport_5xx_falls_back_to_direct(monkeypatch):
    """If the ScrapingAnt API returns 5xx, fall through to direct."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    direct_body = b"direct fallback body"
    session = _MockSession(
        get_queue=[_MockResponse(status=500, headers={}, body=b"server error")],
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "text/plain"}, body=direct_body,
        )],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )

    assert status == 200
    assert body == direct_body
    assert len(session.get_calls) == 1
    assert len(session.request_calls) == 1


def test_dispatch_api_transport_target_5xx_falls_back(monkeypatch):
    """ant-page-status-code >= 500 means the TARGET failed, not the API.
    Fall through to direct."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    session = _MockSession(
        get_queue=[_MockResponse(
            status=200,
            headers={"ant-page-status-code": "503"},
            body=b"target down",
        )],
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "text/plain"}, body=b"direct-ok",
        )],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert status == 200
    assert body == b"direct-ok"


def test_dispatch_api_transport_target_4xx_passes_through(monkeypatch):
    """4xx is the target's answer, not a proxy error — return it."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    session = _MockSession(
        get_queue=[_MockResponse(
            status=200,
            headers={"ant-page-status-code": "404"},
            body=b"not found",
        )],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/missing", fallback_session=session)
    )
    assert status == 404
    assert body == b"not found"
    assert session.request_calls == [], "Direct should not have been called for 4xx"


def test_dispatch_api_transport_timeout_falls_back(monkeypatch):
    """asyncio.TimeoutError on the API call → fall through to direct."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    session = _MockSession(
        get_queue=[asyncio.TimeoutError()],
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "text/plain"}, body=b"direct-ok",
        )],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert status == 200
    assert body == b"direct-ok"


def test_dispatch_api_transport_invalid_key_falls_back(monkeypatch):
    """A 403 from the API (invalid key) → fall through to direct."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "bad-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    session = _MockSession(
        get_queue=[_MockResponse(status=403, headers={}, body=b"forbidden")],
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "text/plain"}, body=b"direct-ok",
        )],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert status == 200
    assert body == b"direct-ok"


def test_dispatch_api_transport_unparseable_target_status_treated_as_200(monkeypatch):
    """ant-page-status-code missing or unparseable → default to 200 (body is success)."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    session = _MockSession(
        get_queue=[_MockResponse(
            status=200,
            headers={"content-type": "text/html"},
            body=b"<html>ok</html>",
        )],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert status == 200
    assert body == b"<html>ok</html>"


# ---------------------------------------------------------------------------
# Dispatch — Proxy Mode transport (EZIO_USE_PROXY)
# ---------------------------------------------------------------------------


def test_dispatch_proxy_transport_success(monkeypatch):
    """Proxy Mode transport enabled → first attempt goes through proxy."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")

    proxy_body = b"<rss>proxy response</rss>"
    session = _MockSession(
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "application/rss+xml"}, body=proxy_body,
        )]
    )
    status, ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/feed.xml", expect="xml", fallback_session=session)
    )

    assert status == 200
    assert ctype == "application/rss+xml"
    assert body == proxy_body
    # The proxy URL is passed via aiohttp's proxy= kwarg, not as the URL.
    # So .request was called (not .get), and the proxy kwarg is set.
    assert len(session.request_calls) == 1
    kwargs = session.request_calls[0][1]
    assert "proxy" in kwargs
    proxy_url = kwargs["proxy"]
    assert SCRAPINGANT_PROXY_HOST in proxy_url


def test_dispatch_proxy_transport_5xx_falls_back_to_direct(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")

    session = _MockSession(
        request_queue=[
            _MockResponse(status=502, headers={}, body=b"bad gateway"),
            _MockResponse(
                status=200, headers={"content-type": "text/plain"}, body=b"direct-ok",
            ),
        ],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert status == 200
    assert body == b"direct-ok"


def test_dispatch_proxy_transport_4xx_passes_through(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")

    session = _MockSession(
        request_queue=[_MockResponse(
            status=404, headers={"content-type": "text/plain"}, body=b"missing",
        )],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/missing", fallback_session=session)
    )
    assert status == 404
    assert body == b"missing"


def test_dispatch_proxy_transport_timeout_falls_back(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")

    session = _MockSession(
        request_queue=[
            asyncio.TimeoutError(),
            _MockResponse(
                status=200, headers={"content-type": "text/plain"}, body=b"direct-ok",
            ),
        ],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert status == 200
    assert body == b"direct-ok"


def test_dispatch_proxy_transport_missing_key_silently_skipped(monkeypatch):
    """If key is unset, Proxy Mode can't activate (no creds) → silent skip → direct."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("EZIO_USE_PROXY", "true")
    # No SCRAPINGANT_API_KEY

    session = _MockSession(
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "text/plain"}, body=b"direct-ok",
        )],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert status == 200
    assert body == b"direct-ok"


# ---------------------------------------------------------------------------
# Mutual exclusion — both transports set, proxy wins, no chaining
# ---------------------------------------------------------------------------


def test_dispatch_both_transports_set_proxy_wins_no_chaining(monkeypatch):
    """When both transport env vars are set, the chokepoint MUST NOT chain.
    Proxy Mode is tried first; on failure it falls through to direct,
    NOT to the REST API."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")

    import sources.proxy_client as mod
    monkeypatch.setattr(mod, "_BOTH_GATES_WARNED", False)

    # Proxy returns 5xx → falls through to direct. Must NOT try the API.
    direct_body = b"direct after proxy failure"
    session = _MockSession(
        request_queue=[
            _MockResponse(status=502, headers={}, body=b"proxy failed"),
            _MockResponse(
                status=200, headers={"content-type": "text/plain"}, body=direct_body,
            ),
        ],
    )
    status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert status == 200
    assert body == direct_body
    assert len(session.get_calls) == 0, (
        "REST API should NOT have been called when both transports are set "
        "and Proxy Mode fails — that would be chaining."
    )
    assert len(session.request_calls) == 2, (
        "Expected exactly 2 .request() calls: one for proxy attempt, one for direct fallback."
    )


# ---------------------------------------------------------------------------
# browser=false enforcement (Phase 1 verified correct, must not regress)
# ---------------------------------------------------------------------------


def test_browser_param_always_false_on_api_transport(monkeypatch):
    """browser=false is hardcoded on the REST API call. No way for a caller
    to override — preserves raw text/XML bytes."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    session = _MockSession(
        get_queue=[_MockResponse(
            status=200,
            headers={"ant-page-status-code": "200", "content-type": "text/html"},
            body=b"<html>ok</html>",
        )]
    )
    asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )

    assert len(session.get_calls) == 1
    call_kwargs = session.get_calls[0][1]
    assert "params" in call_kwargs
    params = call_kwargs["params"]
    assert params.get("browser") == "false", (
        f"browser must always be 'false' on the REST API; got params={params}"
    )


def test_proxy_username_does_not_append_web_scraping_api_parameters(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")

    username = _build_proxy_username()
    assert username == "testuser"
    assert "browser=false" not in username
    assert "proxy_type=" not in username


# ---------------------------------------------------------------------------
# Ant- header prefixing (Phase 1 verified correct, must not regress)
# ---------------------------------------------------------------------------


def test_ant_header_prefixing_on_api_path(monkeypatch):
    """Caller headers are prefixed with ``Ant-`` on the REST API path."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    session = _MockSession(
        get_queue=[_MockResponse(
            status=200,
            headers={"ant-page-status-code": "200", "content-type": "text/html"},
            body=b"<html>ok</html>",
        )]
    )
    asyncio.run(
        clearnet_fetch(
            "https://example.com/",
            headers={"User-Agent": "test-agent", "X-Custom": "v"},
            fallback_session=session,
        )
    )

    call_kwargs = session.get_calls[0][1]
    headers = call_kwargs.get("headers", {})
    assert headers.get("Ant-User-Agent") == "test-agent"
    assert headers.get("Ant-X-Custom") == "v"


# ---------------------------------------------------------------------------
# Caller params appended to target URL on API path
# ---------------------------------------------------------------------------


def test_caller_params_appended_to_target_url(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    session = _MockSession(
        get_queue=[_MockResponse(
            status=200,
            headers={"ant-page-status-code": "200", "content-type": "text/html"},
            body=b"<html>ok</html>",
        )]
    )
    asyncio.run(
        clearnet_fetch(
            "https://example.com/",
            params={"q": "search"},
            fallback_session=session,
        )
    )

    params = session.get_calls[0][1]["params"]
    target_url = params.get("url", "")
    assert "q=search" in target_url


def test_caller_params_separator_when_url_already_has_query(monkeypatch):
    """If the caller URL already has a query string, params are appended with &."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    session = _MockSession(
        get_queue=[_MockResponse(
            status=200,
            headers={"ant-page-status-code": "200", "content-type": "text/html"},
            body=b"<html>ok</html>",
        )]
    )
    asyncio.run(
        clearnet_fetch(
            "https://example.com/?existing=1",
            params={"q": "search"},
            fallback_session=session,
        )
    )

    params = session.get_calls[0][1]["params"]
    target_url = params.get("url", "")
    assert "existing=1&q=search" in target_url or "existing=1" in target_url and "q=search" in target_url


# ---------------------------------------------------------------------------
# Response size capping (verified correct)
# ---------------------------------------------------------------------------


def test_response_size_capped_api_path(monkeypatch):
    """API path returns body capped at MAX_RESPONSE_BYTES."""
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "test-key")
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")

    huge_body = b"X" * (MAX_RESPONSE_BYTES + 1000)
    session = _MockSession(
        get_queue=[_MockResponse(
            status=200,
            headers={"ant-page-status-code": "200", "content-type": "text/html"},
            body=huge_body,
        )]
    )
    _status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert len(body) <= MAX_RESPONSE_BYTES


def test_response_size_capped_proxy_path(monkeypatch):
    _scrub_proxy_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "testuser")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "testpass")
    monkeypatch.setenv("EZIO_USE_PROXY", "true")

    huge_body = b"X" * (MAX_RESPONSE_BYTES + 1000)
    session = _MockSession(
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "text/html"}, body=huge_body,
        )]
    )
    _status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert len(body) <= MAX_RESPONSE_BYTES


def test_response_size_capped_direct_path(monkeypatch):
    _scrub_proxy_env(monkeypatch)

    huge_body = b"X" * (MAX_RESPONSE_BYTES + 1000)
    session = _MockSession(
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "text/html"}, body=huge_body,
        )]
    )
    _status, _ctype, body = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert len(body) <= MAX_RESPONSE_BYTES


# ---------------------------------------------------------------------------
# Direct fetch (verified correct)
# ---------------------------------------------------------------------------


def test_direct_fetch_matches_existing_behavior(monkeypatch):
    """Direct fetch (no transport env vars) returns the caller's response directly."""
    _scrub_proxy_env(monkeypatch)

    body = b"direct response body"
    session = _MockSession(
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "text/plain"}, body=body,
        )]
    )
    status, ctype, returned = asyncio.run(
        clearnet_fetch("https://example.com/", fallback_session=session)
    )
    assert status == 200
    assert ctype == "text/plain"
    assert returned == body


def test_direct_fetch_method_and_headers_forwarded(monkeypatch):
    """Direct fetch forwards the caller's method and headers verbatim."""
    _scrub_proxy_env(monkeypatch)

    session = _MockSession(
        request_queue=[_MockResponse(
            status=200, headers={"content-type": "text/plain"}, body=b"ok",
        )]
    )
    asyncio.run(
        clearnet_fetch(
            "https://example.com/",
            method="POST",
            headers={"X-Custom": "v"},
            fallback_session=session,
        )
    )
    args, kwargs = session.request_calls[0]
    assert args[0] == "POST"
    assert kwargs["headers"]["X-Custom"] == "v"
