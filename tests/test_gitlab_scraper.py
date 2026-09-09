"""
tests/test_gitlab_scraper.py — Unit tests for sources/gitlab_scraper.py.

No real network connections.  All HTTP is mocked.

Covers:
  - _build_search_queries: basic + tool-specific modifier variants
  - _is_noise_repo: positive (awesome-list) and negative (security framework)
  - _score_relevance: high score for IOC-rich content, low for generic text
  - Content safety: files flagged by sanitize_content are dropped
  - Size limit: files larger than MAX_FILE_SIZE are truncated
  - Opt-out: GITLAB_SCRAPING_ENABLED=false short-circuits
  - source_type marking: returned dicts have source_type="gitlab"
  - Rate-limit delay selection (authenticated vs unauthenticated)
  - Snippet fallback: uses item["data"] when file API returns non-200

Run with:
    pytest tests/test_gitlab_scraper.py -v
"""

from __future__ import annotations

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sources.gitlab_scraper import (
    MAX_FILE_SIZE,
    SEARCH_RATE_LIMIT_DELAY,
    GitLabScraper,
    _is_gitlab_scraping_enabled,
    scrape_gitlab,
)


# ---------------------------------------------------------------------------
# _build_search_queries
# ---------------------------------------------------------------------------


def test_build_search_queries_basic():
    """The original query is always included as the first search term."""
    scraper = GitLabScraper()
    queries = scraper._build_search_queries("cobalt strike malware", "")
    assert any("cobalt strike malware" in q for q in queries)
    assert len(queries) >= 1


def test_build_search_queries_tool_modifier():
    """Known tool names ('cobalt strike') append a second query with a modifier."""
    scraper = GitLabScraper()
    queries = scraper._build_search_queries("cobalt strike c2", "")
    assert len(queries) == 2
    assert "malleable" in queries[1]


# ---------------------------------------------------------------------------
# _is_noise_repo
# ---------------------------------------------------------------------------


def test_is_noise_repo_positive():
    """An 'awesome-*' repo is treated as noise."""
    scraper = GitLabScraper()
    assert scraper._is_noise_repo("awesome-hacking") is True


def test_is_noise_repo_negative():
    """A legitimate offensive-security framework is not flagged as noise."""
    scraper = GitLabScraper()
    assert scraper._is_noise_repo("cobalt-strike-c2-framework") is False


# ---------------------------------------------------------------------------
# _score_relevance
# ---------------------------------------------------------------------------


def test_score_relevance_high():
    """Content with a high-value filename, SHA256, and malware keywords scores high."""
    scraper = GitLabScraper()
    content = (
        "Malware analysis notes for the dropper.\n"
        "SHA256: " + "a" * 64 + "\n"
        "C2 server: 192.168.1.10\n"
        "References cobalt strike beacon and mimikatz credential dumping.\n"
        "CVE-2024-1234 used for lateral movement.\n"
    )
    score = scraper._score_relevance(content, "malware.py", "attacker/tools")
    assert score > 10


def test_score_relevance_low():
    """Generic README text without IOCs or security keywords scores low."""
    scraper = GitLabScraper()
    content = (
        "This project is a calendar app for tracking birthdays. "
        "Install with pip and run the example notebook to see how it works."
    )
    score = scraper._score_relevance(content, "calendar.py", "user/calendar")
    assert score < 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _make_mock_response(payload, status: int = 200, headers: dict | None = None):
    """Build a fake aiohttp response context manager returning JSON payload."""
    resp = MagicMock()
    resp.status = status
    resp.headers = headers or {}
    resp.json = AsyncMock(return_value=payload)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


# ---------------------------------------------------------------------------
# Content safety
# ---------------------------------------------------------------------------


def test_content_safety_blocks_file():
    """A file whose content trips sanitize_content returns {}."""
    scraper = GitLabScraper()

    blocked_body = "Filler. " * 50 + " child pornography ring " + " filler. " * 50
    session = MagicMock()
    session.get = MagicMock(
        return_value=_make_mock_response({"content": _b64(blocked_body)})
    )
    scraper._session = session

    item = {
        "project_id": 12345,
        "path": "src/file.py",
        "ref": "main",
        "filename": "file.py",
        "data": "",
    }
    scraper._search_delay = 0.0
    scraper._project_delay = 0.0
    result = asyncio.run(scraper._fetch_code_file(item))
    assert result == {}


# ---------------------------------------------------------------------------
# Size limit
# ---------------------------------------------------------------------------


def test_size_limit_enforced():
    """Files larger than MAX_FILE_SIZE are truncated to MAX_FILE_SIZE chars."""
    scraper = GitLabScraper()
    scraper._search_delay = 0.0
    scraper._project_delay = 0.0

    big_body = "A" * (MAX_FILE_SIZE + 5000)
    session = MagicMock()
    session.get = MagicMock(
        return_value=_make_mock_response({"content": _b64(big_body)})
    )
    scraper._session = session

    item = {
        "project_id": 12345,
        "path": "big.py",
        "ref": "main",
        "filename": "big.py",
        "data": "",
    }
    result = asyncio.run(scraper._fetch_code_file(item))
    assert result, "expected a result dict, got empty"
    assert len(result["text_content"]) == MAX_FILE_SIZE


# ---------------------------------------------------------------------------
# Opt-out toggle
# ---------------------------------------------------------------------------


def test_gitlab_enabled_default(monkeypatch):
    """When GITLAB_SCRAPING_ENABLED is unset, scraping is enabled."""
    monkeypatch.delenv("GITLAB_SCRAPING_ENABLED", raising=False)
    assert _is_gitlab_scraping_enabled() is True


def test_disabled_by_env(monkeypatch):
    """GITLAB_SCRAPING_ENABLED=false short-circuits scrape_gitlab()."""
    monkeypatch.setenv("GITLAB_SCRAPING_ENABLED", "false")

    with patch("sources.gitlab_scraper.GitLabScraper") as mock_cls:
        result = asyncio.run(scrape_gitlab("anything"))

    assert result == []
    mock_cls.assert_not_called()


# ---------------------------------------------------------------------------
# Source-type marking
# ---------------------------------------------------------------------------


def test_source_type_marking():
    """Successful fetches are tagged with source_type='gitlab'."""
    scraper = GitLabScraper()
    scraper._search_delay = 0.0
    scraper._project_delay = 0.0

    body = (
        "Threat intel write-up.\n"
        "SHA256: " + "b" * 64 + "\n"
        "C2 IP: 10.0.0.1\n" + ("Filler line " * 30)
    )
    session = MagicMock()
    session.get = MagicMock(
        return_value=_make_mock_response({"content": _b64(body)})
    )
    scraper._session = session

    item = {
        "project_id": 99999,
        "path": "notes.md",
        "ref": "main",
        "filename": "notes.md",
        "data": "",
    }
    result = asyncio.run(scraper._fetch_code_file(item))
    assert result["source_type"] == "gitlab"
    assert result["source_name"] == "GitLab"
    assert result["gitlab_repo"] == "99999"
    assert result["gitlab_filename"] == "notes.md"
    assert "gitlab.com" in result["url"]
    assert "scraped_at" in result
    assert result["word_count"] > 0


# ---------------------------------------------------------------------------
# Rate-limit delay selection
# ---------------------------------------------------------------------------


def test_search_delay_is_identical_with_and_without_a_token(monkeypatch):
    """
    GitLab.com caps /search at 10 req/min PER IP ADDRESS, and a PRIVATE-TOKEN
    does not lift it.  This is the documented counter-example to the "key
    present == go faster" pattern NVD established, so the search delay must
    NOT branch on the token.  An earlier version used 4.0 s unauthenticated and
    1.0 s authenticated — 15/min and 60/min, both over the real limit.
    """
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    unauth = GitLabScraper()._search_delay
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-dummy_token_for_test")
    auth = GitLabScraper()._search_delay

    assert unauth == auth == SEARCH_RATE_LIMIT_DELAY
    assert auth >= 6.0      # 10 req/min per IP


# ---------------------------------------------------------------------------
# Snippet fallback
# ---------------------------------------------------------------------------


def test_snippet_fallback_used_when_file_api_fails():
    """When the file API returns non-200, the item['data'] snippet is used."""
    scraper = GitLabScraper()
    scraper._search_delay = 0.0
    scraper._project_delay = 0.0

    # Return 404 from the files API
    fail_resp = MagicMock()
    fail_resp.status = 404
    fail_resp.headers = {}
    fail_resp.json = AsyncMock(return_value={})
    fail_cm = MagicMock()
    fail_cm.__aenter__ = AsyncMock(return_value=fail_resp)
    fail_cm.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.get = MagicMock(return_value=fail_cm)
    scraper._session = session

    snippet = "Malware dropper config. C2: 10.0.0.1. " * 5
    item = {
        "project_id": 55555,
        "path": "dropper.py",
        "ref": "main",
        "filename": "dropper.py",
        "data": snippet,
    }
    result = asyncio.run(scraper._fetch_code_file(item))
    assert result, "expected fallback result from snippet"
    assert result["source_type"] == "gitlab"
    assert snippet[:30] in result["text_content"]


# ---------------------------------------------------------------------------
# Token auth header
# ---------------------------------------------------------------------------


def test_token_uses_private_token_header(monkeypatch):
    """When GITLAB_TOKEN is set, headers contain PRIVATE-TOKEN (not Bearer)."""
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test123")
    scraper = GitLabScraper()
    assert "PRIVATE-TOKEN" in scraper._headers
    assert scraper._headers["PRIVATE-TOKEN"] == "glpat-test123"
    assert "Authorization" not in scraper._headers


def test_no_token_omits_auth_header(monkeypatch):
    """When no GITLAB_TOKEN is set, no auth header is present."""
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    scraper = GitLabScraper()
    assert "PRIVATE-TOKEN" not in scraper._headers
    assert "Authorization" not in scraper._headers


# ---------------------------------------------------------------------------
# Blocked query
# ---------------------------------------------------------------------------


def test_blocked_query_returns_empty(monkeypatch):
    """A query that hits the content-safety blocklist returns []."""
    monkeypatch.setenv("GITLAB_SCRAPING_ENABLED", "true")

    async def _run():
        return await scrape_gitlab("child porn distribution")

    result = asyncio.run(_run())
    assert result == []
