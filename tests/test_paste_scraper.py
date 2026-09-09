"""
tests/test_paste_scraper.py — Unit tests for sources/paste_scraper.py.

No real network connections.  All HTTP is mocked.

Covers:
  - _build_search_terms: basic query, CVE detection, malware-name detection
  - _score_relevance: high score for high-value content, zero for unrelated
  - sanitize_content integration: blocks pastes with prohibited content
  - Content size limit: bodies > MAX_PASTE_SIZE are truncated (Phase 1.6 behavior)
  - Opt-out: PASTE_SCRAPING_ENABLED=false short-circuits
  - source_type marking: returned dicts have source_type="paste_site"
  - Phase 1.6 chokepoint wiring: _search_source / _fetch_paste route
    through sources.proxy_client.clearnet_fetch (browser=false, expect=
    hint passed correctly)
  - Regression: with proxies disabled, behavior is byte-for-byte identical
    to pre-v1.6 (clearnet_fetch → _fetch_direct → session.request)

Run with:
    pytest tests/test_paste_scraper.py -v
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

from sources.paste_scraper import (
    MAX_PASTE_SIZE,
    PasteScraper,
    _is_paste_scraping_enabled,
    check_robots_txt,
    scrape_paste_sites,
)


# ---------------------------------------------------------------------------
# _build_search_terms
# ---------------------------------------------------------------------------


def test_build_search_terms_basic():
    """The original query is always included as a search term."""
    scraper = PasteScraper()
    terms = scraper._build_search_terms("LockBit ransomware", "")
    assert any("LockBit ransomware" in t for t in terms)
    assert len(terms) >= 1


def test_build_search_terms_cve():
    """CVE identifiers are extracted and appended as discrete terms."""
    scraper = PasteScraper()
    terms = scraper._build_search_terms("CVE-2024-1234 exploit", "")
    assert any("CVE-2024-1234" in t for t in terms)


def test_build_search_terms_malware_name():
    """Known malware family names are extracted."""
    scraper = PasteScraper()
    terms = scraper._build_search_terms("lockbit ransomware infrastructure", "")
    assert any("lockbit" in t.lower() for t in terms)


def test_build_search_terms_uses_refined_when_different():
    """The refined query is added separately from the original query."""
    scraper = PasteScraper()
    terms = scraper._build_search_terms("dark web", "lockbit C2 servers")
    assert "lockbit C2 servers" in terms
    assert "dark web" in terms


# ---------------------------------------------------------------------------
# _score_relevance
# ---------------------------------------------------------------------------


def test_score_relevance_high():
    """Content with the search term, IPs and SHA256 hashes scores high."""
    scraper = PasteScraper()
    content = (
        "LockBit ransomware C2 servers identified.\n"
        "C2: 192.168.1.1, 10.0.0.5, 172.16.0.1\n"
        "Sample SHA256: " + "a" * 64 + "\n"
        "Email contact: ops@example.com\n"
        "PGP key follows:\n-----BEGIN PGP PUBLIC KEY BLOCK-----"
    )
    score = scraper._score_relevance(content, "LockBit ransomware")
    assert score > 10


def test_score_relevance_low():
    """Generic unrelated text scores zero."""
    scraper = PasteScraper()
    content = "The weather today is sunny and pleasant."
    score = scraper._score_relevance(content, "lockbit ransomware infrastructure")
    assert score == 0


def test_score_relevance_empty_inputs():
    """Empty content or term returns zero — never raises."""
    scraper = PasteScraper()
    assert scraper._score_relevance("", "anything") == 0
    assert scraper._score_relevance("anything", "") == 0


# ---------------------------------------------------------------------------
# Opt-out toggle
# ---------------------------------------------------------------------------


def test_paste_enabled_default(monkeypatch):
    """When PASTE_SCRAPING_ENABLED is unset, scraping is enabled."""
    monkeypatch.delenv("PASTE_SCRAPING_ENABLED", raising=False)
    assert _is_paste_scraping_enabled() is True


def test_paste_enabled_false(monkeypatch):
    """PASTE_SCRAPING_ENABLED=false disables scraping."""
    monkeypatch.setenv("PASTE_SCRAPING_ENABLED", "false")
    assert _is_paste_scraping_enabled() is False


def test_scrape_paste_sites_opt_out_short_circuits(monkeypatch):
    """When disabled, scrape_paste_sites returns [] without doing work."""
    monkeypatch.setenv("PASTE_SCRAPING_ENABLED", "false")

    # If the scraper actually ran, this patch would block — make sure that the
    # short-circuit happens BEFORE any aiohttp session is created.
    with patch("sources.paste_scraper.PasteScraper") as mock_scraper:
        result = asyncio.run(scrape_paste_sites("anything"))

    assert result == []
    mock_scraper.assert_not_called()


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------
#
# Phase 1.6 wiring: _search_source and _fetch_paste no longer call
# ``self._session.get(...)`` directly — they call
# ``clearnet_fetch(...)`` from sources.proxy_client.  We mock the
# chokepoint at the import site (``sources.paste_scraper.clearnet_fetch``)
# rather than the underlying aiohttp session, because:
#
#   1. The chokepoint's contract is what paste_scraper depends on
#      (3-tuple return: status, content_type, body).
#   2. Mocking the session would couple tests to the chokepoint's
#      internal routing (request vs get, header semantics, etc.).
#
# For the proxy-disabled REGRESSION test, we mock the underlying session
# instead — that's the path that exercises the full chokepoint without
# scraping the network.
#
# Legacy ``_make_scraper_with_response`` mock (which targeted session.get)
# is replaced by ``_mocked_paste_scraper`` — a context manager that yields
# a PasteScraper while patching ``clearnet_fetch`` at the import site.


@contextmanager
def _mocked_paste_scraper(
    body: bytes,
    status: int = 200,
    content_type: str = "text/plain; charset=utf-8",
    paste_id: str = "abc12345",
):
    """Yield a PasteScraper with ``clearnet_fetch`` patched to return *body*.

    The PasteScraper holds a MagicMock session that is never used (because
    ``clearnet_fetch`` is patched).  Use as::

        with _mocked_paste_scraper(b"hello") as scraper:
            result = asyncio.run(scraper._fetch_paste(source, paste_id))

    Args:
        body:         raw bytes that ``clearnet_fetch`` will return as the body.
        status:       HTTP status code the mock chokepoint returns.
        content_type: content-type the mock chokepoint returns.
        paste_id:     default paste_id used in the existing tests' calls.
    """
    scraper = PasteScraper()
    session = MagicMock()
    session.close = AsyncMock()
    scraper._session = session
    mock = AsyncMock(return_value=(status, content_type, body))
    with patch("sources.paste_scraper.clearnet_fetch", mock):
        yield scraper


def _build_session_for_direct_path(body: bytes, status: int = 200):
    """Build a mock aiohttp.ClientSession that the chokepoint's direct
    path (``_fetch_direct``) can route through.

    This is used by the REGRESSION test where we mock the underlying
    session instead of the chokepoint — to prove that proxies-off
    behavior is byte-for-byte identical to pre-v1.6.
    """
    mock_resp = MagicMock()
    mock_resp.status = status
    mock_resp.headers = {"content-type": "text/plain; charset=utf-8"}
    mock_resp.read = AsyncMock(return_value=body)

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_resp)
    cm.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.close = AsyncMock()
    session.request = MagicMock(return_value=cm)
    session.get = MagicMock(return_value=cm)  # also set so check_robots_txt can be tested
    return session, cm, mock_resp


def test_content_safety_blocks_paste(monkeypatch):
    """Pastes containing CSAM/gore terms are dropped before being returned."""
    blocked_body = (
        "Some intro text. " * 50
        + " child pornography distribution network. "
        + " Filler content. " * 50
    ).encode("utf-8")
    with _mocked_paste_scraper(blocked_body) as scraper:
        result = asyncio.run(
            scraper._fetch_paste(
                {"name": "Pastebin", "paste_url": "https://pastebin.com/raw/{id}"},
                "abc12345",
            )
        )
    assert result == {}


def test_content_size_limit(monkeypatch):
    """Bodies larger than MAX_PASTE_SIZE are truncated to MAX_PASTE_SIZE,
    NOT rejected outright.  This is a behavior change from pre-Phase 1.6:

    - Pre-1.6:  checked the ``content-length`` header; if > MAX_PASTE_SIZE
                the paste was rejected with ``{}``.
    - Phase 1.6: chokepoint returns raw bytes; the size gate uses
                ``len(body)`` (more reliable than a header that may be
                missing or wrong) and TRUNCATES the body to
                ``MAX_PASTE_SIZE`` bytes, then proceeds normally.

    The threshold value is preserved exactly.  This test verifies the
    new truncation behavior.
    """
    body = b"X" * (MAX_PASTE_SIZE + 1000)
    with _mocked_paste_scraper(body) as scraper:
        result = asyncio.run(
            scraper._fetch_paste(
                {"name": "Pastebin", "paste_url": "https://pastebin.com/raw/{id}"},
                "bigpaste",
            )
        )
    # After truncation: MAX_PASTE_SIZE bytes of "X" — long enough to pass
    # the 50-char min and not safety-flagged, so we get a valid paste dict,
    # not {}.  The text_content must be exactly MAX_PASTE_SIZE bytes.
    assert result != {}, "Truncation should yield a valid result, not empty"
    assert "text_content" in result
    assert len(result["text_content"].encode("utf-8")) == MAX_PASTE_SIZE


def test_content_too_short_rejected():
    """Pastes shorter than the minimum threshold are skipped."""
    with _mocked_paste_scraper(b"tiny") as scraper:
        result = asyncio.run(
            scraper._fetch_paste(
                {"name": "Pastebin", "paste_url": "https://pastebin.com/raw/{id}"},
                "tiny01",
            )
        )
    assert result == {}


# ---------------------------------------------------------------------------
# Source-type marking
# ---------------------------------------------------------------------------


def test_source_type_marking():
    """Successful fetches are tagged with source_type=paste_site and source_name."""
    body = (
        "Threat intel dump for LockBit ransomware.\n"
        "C2: 192.168.1.1\n"
        "SHA256: " + "b" * 64 + "\n"
        + ("Filler line " * 30)
    ).encode("utf-8")
    with _mocked_paste_scraper(body) as scraper:
        result = asyncio.run(
            scraper._fetch_paste(
                {"name": "Pastebin", "paste_url": "https://pastebin.com/raw/{id}"},
                "abc12345",
            )
        )
    assert result["source_type"] == "paste_site"
    assert result["source_name"] == "Pastebin"
    assert result["url"] == "https://pastebin.com/raw/abc12345"
    assert result["title"] == "Pastebin — abc12345"
    assert result["word_count"] > 0
    assert "scraped_at" in result


# ---------------------------------------------------------------------------
# Blocked query
# ---------------------------------------------------------------------------


def test_blocked_query_returns_empty(monkeypatch):
    """A query that hits the content-safety blocklist returns [] immediately."""
    monkeypatch.setenv("PASTE_SCRAPING_ENABLED", "true")

    async def _run():
        return await scrape_paste_sites("child porn distribution")

    result = asyncio.run(_run())
    assert result == []


# ---------------------------------------------------------------------------
# Phase 1.6 chokepoint wiring — _search_source + _fetch_paste
# ---------------------------------------------------------------------------
#
# These tests verify the Phase 1.6 wiring: _search_source and _fetch_paste
# now route through sources.proxy_client.clearnet_fetch.  We mock the
# chokepoint at the import site (``sources.paste_scraper.clearnet_fetch``)
# and assert the call shape (URL, expect= hint, fallback_session).
#
# For the proxy-disabled REGRESSION test further below, we mock the
# underlying aiohttp session instead — to prove the end-to-end path still
# produces byte-for-byte identical results when proxies are off.


def test_search_source_uses_chokepoint(monkeypatch):
    """_search_source routes through clearnet_fetch with expect='html'."""
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    source = {
        "name": "Pastebin",
        "search_url": "https://pastebin.com/search?q={query}",
        "result_pattern": r'href="/([a-zA-Z0-9]{8})"',
        "rate_limit": 0,
    }
    html_body = b'<html><a href="/ABCDEFGH">link</a></html>'

    scraper = PasteScraper()
    scraper._session = MagicMock()

    with patch(
        "sources.paste_scraper.clearnet_fetch", new_callable=AsyncMock
    ) as mock_fetch:
        mock_fetch.return_value = (200, "text/html", html_body)
        ids = asyncio.run(scraper._search_source(source, "test query"))

    assert mock_fetch.called, "clearnet_fetch must be called"
    # URL should be the search URL with the encoded term
    sent_url = mock_fetch.call_args.args[0]
    assert "pastebin.com/search" in sent_url
    assert "test+query" in sent_url or "test%20query" in sent_url
    # expect='html' must be passed (not 'text' or 'json')
    assert mock_fetch.call_args.kwargs.get("expect") == "html"
    # fallback_session must be the scraper's session
    assert mock_fetch.call_args.kwargs.get("fallback_session") is scraper._session
    # Sanity: the result still contains the parsed ID
    assert "ABCDEFGH" in ids


def test_fetch_paste_uses_chokepoint(monkeypatch):
    """_fetch_paste routes through clearnet_fetch with expect='text'."""
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    body = (b"some paste content here with enough length to pass the "
            b"50-char minimum threshold and not be flagged")

    scraper = PasteScraper()
    scraper._session = MagicMock()

    with patch(
        "sources.paste_scraper.clearnet_fetch", new_callable=AsyncMock
    ) as mock_fetch:
        mock_fetch.return_value = (200, "text/plain", body)
        asyncio.run(
            scraper._fetch_paste(
                {"name": "Pastebin", "paste_url": "https://pastebin.com/raw/{id}"},
                "abc12345",
            )
        )

    assert mock_fetch.called, "clearnet_fetch must be called"
    sent_url = mock_fetch.call_args.args[0]
    assert sent_url == "https://pastebin.com/raw/abc12345"
    # expect='text' for raw paste content
    assert mock_fetch.call_args.kwargs.get("expect") == "text"
    assert mock_fetch.call_args.kwargs.get("fallback_session") is scraper._session


def test_fetch_paste_size_gate_still_works(monkeypatch):
    """Body larger than MAX_PASTE_SIZE is truncated to exactly MAX_PASTE_SIZE.

    Same threshold value as pre-1.6 — the gate logic is preserved, only
    the source of the length measurement changed (header → body length).
    """
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    body = b"X" * (MAX_PASTE_SIZE + 5000)
    with _mocked_paste_scraper(body) as scraper:
        result = asyncio.run(
            scraper._fetch_paste(
                {"name": "Pastebin", "paste_url": "https://pastebin.com/raw/{id}"},
                "big01",
            )
        )

    # Truncation, not rejection — the truncated body is a valid paste
    assert result != {}
    assert "text_content" in result
    assert len(result["text_content"].encode("utf-8")) == MAX_PASTE_SIZE


def test_search_source_non_200_returns_empty(monkeypatch):
    """_search_source returns [] when clearnet_fetch returns a non-200 status."""
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    source = {
        "name": "Pastebin",
        "search_url": "https://pastebin.com/search?q={query}",
        "result_pattern": r"x",
        "rate_limit": 0,
    }
    scraper = PasteScraper()
    scraper._session = MagicMock()

    with patch(
        "sources.paste_scraper.clearnet_fetch", new_callable=AsyncMock
    ) as mock_fetch:
        mock_fetch.return_value = (404, "text/html", b"not found")
        ids = asyncio.run(scraper._search_source(source, "test"))

    assert ids == []


def test_fetch_paste_non_200_returns_empty(monkeypatch):
    """_fetch_paste returns {} when clearnet_fetch returns a non-200 status."""
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    scraper = PasteScraper()
    scraper._session = MagicMock()

    with patch(
        "sources.paste_scraper.clearnet_fetch", new_callable=AsyncMock
    ) as mock_fetch:
        mock_fetch.return_value = (404, "text/plain", b"not found")
        result = asyncio.run(
            scraper._fetch_paste(
                {"name": "Pastebin", "paste_url": "https://pastebin.com/raw/{id}"},
                "missing",
            )
        )

    assert result == {}


def test_paste_scraper_works_with_proxies_disabled(monkeypatch):
    """REGRESSION: with proxies disabled, paste_scraper behavior is
    byte-for-byte identical to pre-v1.6.

    The underlying aiohttp session is mocked (NOT clearnet_fetch) so this
    test exercises the full chokepoint path: ``_fetch_paste`` →
    ``clearnet_fetch`` → ``_fetch_direct`` → ``session.request()`` →
    mock response.  The chokepoint's internal routing (request vs get,
    response.read() vs response.text()) is verified by the call-shape
    assertion on session.request at the end.
    """
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    body = (
        b"Threat intel dump for LockBit ransomware.\n"
        b"C2: 192.168.1.1\n"
        b"SHA256: " + b"b" * 64 + b"\n"
        + (b"Filler line " * 30)
    )

    session, _cm, _resp = _build_session_for_direct_path(body)

    scraper = PasteScraper()
    scraper._session = session

    result = asyncio.run(
        scraper._fetch_paste(
            {"name": "Pastebin", "paste_url": "https://pastebin.com/raw/{id}"},
            "abc12345",
        )
    )

    # Result is a valid paste dict — byte-for-byte identical to pre-1.6
    assert result != {}, "valid paste must produce a non-empty result"
    assert result["source_type"] == "paste_site"
    assert result["source_name"] == "Pastebin"
    assert result["url"] == "https://pastebin.com/raw/abc12345"
    assert result["title"] == "Pastebin — abc12345"
    assert "C2: 192.168.1.1" in result["text_content"]
    assert "LockBit" in result["text_content"]
    assert result["word_count"] > 0
    assert "scraped_at" in result
    assert result["scraped_at"].endswith("+00:00") or "T" in result["scraped_at"]

    # Chokepoint routing in effect:
    #   - session.request() was called (clearnet_fetch → _fetch_direct path)
    #   - session.get() was NOT called (pre-1.6 path, no longer used)
    assert session.request.called, (
        "session.request must be called via clearnet_fetch → _fetch_direct"
    )
    assert not session.get.called, (
        "session.get is the pre-1.6 path; the chokepoint must route via request()"
    )
    # The request was made with the correct method and URL
    method, url = session.request.call_args[0]
    assert method == "GET"
    assert url == "https://pastebin.com/raw/abc12345"


def test_paste_scraper_robots_txt_unchanged(monkeypatch):
    """check_robots_txt still uses session.get directly, NOT clearnet_fetch.

    Phase 2 SCOPE decision: the robots.txt fetch is optional, low-value,
    and external-callers-only — no proxy indirection.  We assert this by
    patching clearnet_fetch and confirming it was NOT called when
    check_robots_txt runs against a mock session.
    """
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    # Mock response that session.get will yield
    robots_body = b"User-agent: *\nAllow: /\n"
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.text = AsyncMock(return_value=robots_body.decode("utf-8"))

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_resp)
    cm.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.get = MagicMock(return_value=cm)
    session.request = MagicMock(return_value=cm)

    with patch(
        "sources.paste_scraper.clearnet_fetch", new_callable=AsyncMock
    ) as mock_chokepoint:
        result = asyncio.run(
            check_robots_txt(session, "https://example.com", "/some/path")
        )

    # chokepoint was NOT used
    assert not mock_chokepoint.called, (
        "check_robots_txt must NOT route through clearnet_fetch"
    )
    # session.get WAS used (original path preserved)
    assert session.get.called, (
        "check_robots_txt must still call session.get directly"
    )
    # session.request was NOT used (that's the chokepoint's path)
    assert not session.request.called
    # Result: "Allow: /" means the path is allowed
    assert result is True
