"""
tests/test_github_scraper.py — Unit tests for sources/github_scraper.py.

No real network connections.  All HTTP is mocked.

Covers:
  - _build_search_queries: basic + tool-specific modifier variants
  - _is_noise_repo: positive (awesome-list) and negative (security framework)
  - _score_relevance: high score for IOC-rich content, low for generic text
  - Content safety: pastes/files flagged by sanitize_content are dropped
  - Size limit: files larger than MAX_FILE_SIZE are truncated
  - Opt-out: GITHUB_SCRAPING_ENABLED=false short-circuits
  - source_type marking: returned dicts have source_type="github"
  - Rate-limit delay selection (authenticated vs unauthenticated)

Run with:
    pytest tests/test_github_scraper.py -v
"""

from __future__ import annotations

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sources.github_scraper import (
    CODE_SEARCH_RATE_LIMIT_DELAY,
    MAX_FILE_SIZE,
    SEARCH_RATE_LIMIT_DELAY_AUTH,
    SEARCH_RATE_LIMIT_DELAY_UNAUTH,
    GitHubScraper,
    _is_github_scraping_enabled,
    scrape_github,
)


# ---------------------------------------------------------------------------
# _build_search_queries
# ---------------------------------------------------------------------------


def test_build_search_queries_basic():
    """The original query is always included as the first search term."""
    scraper = GitHubScraper()
    queries = scraper._build_search_queries("cobalt strike malware", "")
    assert any("cobalt strike malware" in q for q in queries)
    assert len(queries) >= 1


def test_build_search_queries_tool_modifier():
    """Known tool names ('cobalt strike') append a second query with a modifier."""
    scraper = GitHubScraper()
    queries = scraper._build_search_queries("cobalt strike c2", "")
    assert len(queries) == 2
    assert "malleable" in queries[1]


# ---------------------------------------------------------------------------
# _is_noise_repo
# ---------------------------------------------------------------------------


def test_is_noise_repo_positive():
    """An 'awesome-*' repo is treated as noise."""
    scraper = GitHubScraper()
    assert scraper._is_noise_repo("awesome-hacking") is True


def test_is_noise_repo_negative():
    """A legitimate offensive-security framework is not flagged as noise."""
    scraper = GitHubScraper()
    assert scraper._is_noise_repo("cobalt-strike-c2-framework") is False


# ---------------------------------------------------------------------------
# _score_relevance
# ---------------------------------------------------------------------------


def test_score_relevance_high():
    """Content with a high-value filename, SHA256, and malware keywords scores high."""
    scraper = GitHubScraper()
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
    scraper = GitHubScraper()
    content = (
        "This project is a calendar app for tracking birthdays. "
        "Install with pip and run the example notebook to see how it works."
    )
    score = scraper._score_relevance(content, "calendar.py", "user/calendar")
    assert score < 5


# ---------------------------------------------------------------------------
# Content safety
# ---------------------------------------------------------------------------


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _make_mock_response(payload, status: int = 200):
    """Build a fake aiohttp response context manager returning JSON payload."""
    resp = MagicMock()
    resp.status = status
    resp.headers = {}
    resp.json = AsyncMock(return_value=payload)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def test_content_safety_blocks_file():
    """A file whose content trips sanitize_content returns {}."""
    scraper = GitHubScraper()

    blocked_body = "Filler. " * 50 + " child pornography ring " + " filler. " * 50
    session = MagicMock()
    session.get = MagicMock(
        return_value=_make_mock_response({"content": _b64(blocked_body)})
    )
    scraper._session = session

    item = {
        "git_url": "https://api.github.com/repos/x/y/git/blobs/abc",
        "html_url": "https://github.com/x/y/blob/main/file.py",
        "name": "file.py",
        "repository": {"full_name": "x/y", "name": "y", "stargazers_count": 0},
    }
    # _fetch_code_file sleeps ~rate_limit_delay/2 between calls; shrink it so the
    # test is fast.
    scraper._search_delay = 0.0
    scraper._code_search_delay = 0.0
    scraper._blob_fetch_delay = 0.0
    result = asyncio.run(scraper._fetch_code_file(item))
    assert result == {}


# ---------------------------------------------------------------------------
# Size limit
# ---------------------------------------------------------------------------


def test_size_limit_enforced():
    """Files larger than MAX_FILE_SIZE are truncated to MAX_FILE_SIZE chars."""
    scraper = GitHubScraper()
    scraper._search_delay = 0.0
    scraper._code_search_delay = 0.0
    scraper._blob_fetch_delay = 0.0

    big_body = "A" * (MAX_FILE_SIZE + 5000)
    session = MagicMock()
    session.get = MagicMock(
        return_value=_make_mock_response({"content": _b64(big_body)})
    )
    scraper._session = session

    item = {
        "git_url": "https://api.github.com/repos/x/y/git/blobs/abc",
        "html_url": "https://github.com/x/y/blob/main/big.py",
        "name": "big.py",
        "repository": {"full_name": "x/y", "name": "y", "stargazers_count": 0},
    }
    result = asyncio.run(scraper._fetch_code_file(item))
    assert result, "expected a result dict, got empty"
    assert len(result["text_content"]) == MAX_FILE_SIZE


# ---------------------------------------------------------------------------
# Opt-out toggle
# ---------------------------------------------------------------------------


def test_github_enabled_default(monkeypatch):
    """When GITHUB_SCRAPING_ENABLED is unset, scraping is enabled."""
    monkeypatch.delenv("GITHUB_SCRAPING_ENABLED", raising=False)
    assert _is_github_scraping_enabled() is True


def test_disabled_by_env(monkeypatch):
    """GITHUB_SCRAPING_ENABLED=false short-circuits scrape_github()."""
    monkeypatch.setenv("GITHUB_SCRAPING_ENABLED", "false")

    with patch("sources.github_scraper.GitHubScraper") as mock_cls:
        result = asyncio.run(scrape_github("anything"))

    assert result == []
    mock_cls.assert_not_called()


# ---------------------------------------------------------------------------
# Source-type marking
# ---------------------------------------------------------------------------


def test_source_type_marking():
    """Successful fetches are tagged with source_type='github'."""
    scraper = GitHubScraper()
    scraper._search_delay = 0.0
    scraper._code_search_delay = 0.0
    scraper._blob_fetch_delay = 0.0

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
        "git_url": "https://api.github.com/repos/x/y/git/blobs/abc",
        "html_url": "https://github.com/x/y/blob/main/notes.md",
        "name": "notes.md",
        "repository": {"full_name": "x/y", "name": "y", "stargazers_count": 42},
    }
    result = asyncio.run(scraper._fetch_code_file(item))
    assert result["source_type"] == "github"
    assert result["source_name"] == "GitHub"
    assert result["github_repo"] == "x/y"
    assert result["github_filename"] == "notes.md"
    assert result["url"] == "https://github.com/x/y/blob/main/notes.md"
    assert "scraped_at" in result
    assert result["word_count"] > 0


# ---------------------------------------------------------------------------
# Rate-limit delay selection
# ---------------------------------------------------------------------------


def test_no_token_uses_unauth_delay(monkeypatch):
    """No GITHUB_TOKEN → the search delay equals the unauthenticated baseline."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    scraper = GitHubScraper()
    assert scraper._search_delay == SEARCH_RATE_LIMIT_DELAY_UNAUTH


def test_token_uses_auth_delay(monkeypatch):
    """GITHUB_TOKEN set → the search delay equals the authenticated baseline."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_dummy_token_for_test")
    scraper = GitHubScraper()
    assert scraper._search_delay == SEARCH_RATE_LIMIT_DELAY_AUTH


def test_code_search_delay_ignores_the_token(monkeypatch):
    """
    /search/code is 10 req/min even authenticated — it does not share the
    30/min tier the other search endpoints get, so a token must not shorten it.
    """
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    unauth = GitHubScraper()._code_search_delay
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_dummy_token_for_test")
    auth = GitHubScraper()._code_search_delay

    assert unauth == auth == CODE_SEARCH_RATE_LIMIT_DELAY
    assert auth >= 6.0      # 10 req/min


# ---------------------------------------------------------------------------
# Blocked query
# ---------------------------------------------------------------------------


def test_blocked_query_returns_empty(monkeypatch):
    """A query that hits the content-safety blocklist returns []."""
    monkeypatch.setenv("GITHUB_SCRAPING_ENABLED", "true")

    async def _run():
        return await scrape_github("child porn distribution")

    result = asyncio.run(_run())
    assert result == []
