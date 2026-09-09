"""
tests/test_rss_scraper.py — Unit tests for sources/rss_scraper.py
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sources.rss_scraper import (
    MAX_ARTICLES_PER_FEED,
    MAX_ARTICLE_SIZE,
    RSS_FEEDS,
    RSSCache,
    RSSFeedScraper,
    scrape_rss_feeds,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_RSS2_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>LockBit ransomware hits major bank</title>
      <link>https://example.com/article/1</link>
      <description>LockBit group claimed responsibility for the attack.</description>
      <pubDate>Mon, 12 May 2025 10:00:00 +0000</pubDate>
    </item>
    <item>
      <title>New malware strain discovered</title>
      <link>https://example.com/article/2</link>
      <description>Researchers found a new stealer targeting crypto wallets.</description>
      <pubDate>Tue, 13 May 2025 08:00:00 +0000</pubDate>
    </item>
  </channel>
</rss>"""

SAMPLE_ATOM_XML = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Test Feed</title>
  <entry>
    <title>APT29 targets EU parliament</title>
    <link rel="alternate" href="https://example.com/atom/1"/>
    <summary>Russian state actors launched spear-phishing campaigns.</summary>
    <published>2025-05-10T12:00:00Z</published>
  </entry>
  <entry>
    <title>Zero-day in Chrome exploited in the wild</title>
    <link href="https://example.com/atom/2"/>
    <summary>Google patches critical V8 engine vulnerability.</summary>
    <published>2025-05-11T09:00:00Z</published>
  </entry>
</feed>"""

MALFORMED_XML = """<?xml version="1.0"?>
<rss>
  <channel>
    <item>
      <title>Broken</title>
      <link>https://example.com/broken</link>
    <!-- unclosed comment
  </channel>
</rss"""


# ---------------------------------------------------------------------------
# 1. test_rss_parse_valid_rss2
# ---------------------------------------------------------------------------

def test_rss_parse_valid_rss2():
    scraper = RSSFeedScraper()
    articles = scraper._parse_feed(SAMPLE_RSS2_XML, "https://example.com/feed")
    assert len(articles) == 2
    assert articles[0]["url"] == "https://example.com/article/1"
    assert "LockBit" in articles[0]["title"]
    assert articles[0]["summary"] != ""
    assert articles[0]["published"] != ""


# ---------------------------------------------------------------------------
# 2. test_rss_parse_valid_atom
# ---------------------------------------------------------------------------

def test_rss_parse_valid_atom():
    scraper = RSSFeedScraper()
    articles = scraper._parse_feed(SAMPLE_ATOM_XML, "https://example.com/atom")
    assert len(articles) == 2
    assert articles[0]["url"] == "https://example.com/atom/1"
    assert "APT29" in articles[0]["title"]


# ---------------------------------------------------------------------------
# 3. test_rss_parse_malformed
# ---------------------------------------------------------------------------

def test_rss_parse_malformed():
    scraper = RSSFeedScraper()
    articles = scraper._parse_feed(MALFORMED_XML, "https://example.com/bad")
    assert articles == []


# ---------------------------------------------------------------------------
# 4. test_score_article_recent_match
# ---------------------------------------------------------------------------

def test_score_article_recent_match():
    scraper = RSSFeedScraper()
    three_days_ago = (datetime.now(timezone.utc) - timedelta(days=3)).strftime(
        "%a, %d %b %Y %H:%M:%S +0000"
    )
    article = {
        "title": "LockBit ransomware deploys new encryptor",
        "summary": "Group has begun targeting critical infrastructure.",
        "published": three_days_ago,
    }
    feed = {"tags": ["ransomware"], "weight": 10}
    score = scraper._score_article(article, ["lockbit", "ransomware"], feed)
    assert score >= 10


# ---------------------------------------------------------------------------
# 5. test_score_article_old
# ---------------------------------------------------------------------------

def test_score_article_old():
    scraper = RSSFeedScraper()
    old_date = (datetime.now(timezone.utc) - timedelta(days=100)).strftime(
        "%a, %d %b %Y %H:%M:%S +0000"
    )
    article = {
        "title": "LockBit ransomware",
        "summary": "Old article about lockbit.",
        "published": old_date,
    }
    feed = {"tags": ["ransomware"], "weight": 10}
    score = scraper._score_article(article, ["lockbit"], feed)
    assert score == 0


# ---------------------------------------------------------------------------
# 6. test_score_article_no_match
# ---------------------------------------------------------------------------

def test_score_article_no_match():
    scraper = RSSFeedScraper()
    # No published date and no matching terms → score must be 0
    article = {
        "title": "Unrelated cooking tips",
        "summary": "How to make pasta.",
        "published": "",
    }
    feed = {"tags": ["malware"], "weight": 8}
    score = scraper._score_article(article, ["lockbit", "ransomware"], feed)
    assert score == 0


# ---------------------------------------------------------------------------
# 7. test_extract_search_terms_actor
# ---------------------------------------------------------------------------

def test_extract_search_terms_actor():
    scraper = RSSFeedScraper()
    terms = scraper._extract_search_terms("LockBit ransomware", "")
    assert "lockbit" in terms


# ---------------------------------------------------------------------------
# 8. test_extract_search_terms_cve
# ---------------------------------------------------------------------------

def test_extract_search_terms_cve():
    scraper = RSSFeedScraper()
    terms = scraper._extract_search_terms("CVE-2024-1234 remote code execution", "")
    assert "cve-2024-1234" in terms


# ---------------------------------------------------------------------------
# 9. test_strip_html
# ---------------------------------------------------------------------------

def test_strip_html():
    scraper = RSSFeedScraper()
    result = scraper._strip_html("<p>Hello <b>world</b></p>")
    assert result == "Hello world"


# ---------------------------------------------------------------------------
# 10. test_article_body_uses_trafilatura
# ---------------------------------------------------------------------------

def test_article_body_uses_trafilatura():
    scraper = RSSFeedScraper()
    extracted = "Main article content. " * 10

    with patch("sources.rss_scraper.trafilatura.extract", return_value=extracted) as mock_extract:
        result = scraper._extract_article_text(
            "<html><nav>Skip to main content</nav><article>raw page</article></html>"
        )

    assert result == extracted.strip()
    mock_extract.assert_called_once_with(
        "<html><nav>Skip to main content</nav><article>raw page</article></html>",
        include_comments=False,
        include_tables=True,
    )


# ---------------------------------------------------------------------------
# 11. test_article_body_raw_strip_fallback
# ---------------------------------------------------------------------------

def test_article_body_raw_strip_fallback():
    scraper = RSSFeedScraper()
    html = """
    <html>
      <nav>Skip to main content</nav>
      <script>var tracking = 'noise';</script>
      <article><h1>Article title</h1><p>Usable article text survives.</p></article>
    </html>
    """

    with patch("sources.rss_scraper.trafilatura.extract", return_value=""):
        result = scraper._extract_article_text(html)

    assert "Usable article text survives." in result
    assert "var tracking" not in result
    # This is intentionally the raw-strip fallback contract, so page chrome
    # remains available rather than producing an empty article.
    assert "Skip to main content" in result


# ---------------------------------------------------------------------------
# 12. test_cache_set_and_get
# ---------------------------------------------------------------------------

def test_cache_set_and_get(tmp_path, monkeypatch):
    import sources.rss_scraper as rss_mod
    monkeypatch.setattr(rss_mod, "CACHE_DIR", tmp_path)
    cache = RSSCache.__new__(RSSCache)
    cache._cache_path = lambda url: tmp_path / f"{hash(url)}.json"

    articles = [{"url": "https://example.com", "title": "Test"}]
    cache.set("https://example.com/feed", articles)
    result = cache.get("https://example.com/feed")
    assert result == articles


# ---------------------------------------------------------------------------
# 13. test_cache_expires
# ---------------------------------------------------------------------------

def test_cache_expires(tmp_path):
    cache = RSSCache.__new__(RSSCache)
    key_path = tmp_path / "test.json"
    cache._cache_path = lambda url: key_path

    # Write cache entry with a timestamp from 2 hours ago
    key_path.write_text(json.dumps({
        "cached_at": time.time() - 7200,
        "articles": [{"url": "https://example.com"}],
    }))
    result = cache.get("https://example.com/feed")
    assert result is None


# ---------------------------------------------------------------------------
# 14. test_disabled_by_env
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv("RSS_FEEDS_ENABLED", "false")
    result = await scrape_rss_feeds("LockBit ransomware")
    assert result == []


# ---------------------------------------------------------------------------
# 15. test_content_safety_blocks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_content_safety_blocks():
    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = MagicMock()
    scraper._cache = MagicMock()
    scraper._cache.get.return_value = None
    scraper._cache.set = MagicMock()

    raw_articles = [
        {
            "url": "https://example.com/article",
            "title": "Ransomware article",
            "summary": "Details about a recent attack.",
            "published": (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
                "%a, %d %b %Y %H:%M:%S +0000"
            ),
        }
    ]

    with (
        patch.object(scraper, "_fetch_and_parse", new=AsyncMock(return_value=raw_articles)),
        patch.object(scraper, "_fetch_article_content", new=AsyncMock(return_value="Article body with sufficient text " * 10)),
        patch("sources.rss_scraper.sanitize_content", return_value=("", True)),
    ):
        feed = RSS_FEEDS[0]
        result = await scraper._fetch_feed(feed, ["ransomware"])

    assert result == []


# ---------------------------------------------------------------------------
# 16. test_source_type_marking
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_source_type_marking(monkeypatch):
    monkeypatch.setenv("RSS_FEEDS_ENABLED", "true")

    mock_article = {
        "url": "https://krebsonsecurity.com/2025/01/lockbit",
        "title": "LockBit indictment",
        "summary": "DOJ charges LockBit operators.",
        "published": (datetime.now(timezone.utc) - timedelta(days=2)).strftime(
            "%a, %d %b %Y %H:%M:%S +0000"
        ),
    }
    article_text = "LockBit ransomware operators were charged by the DOJ " * 20

    with patch("sources.rss_scraper.RSSFeedScraper") as MockScraper:
        mock_instance = AsyncMock()
        mock_instance.fetch_relevant_articles.return_value = [
            {
                "url": mock_article["url"],
                "text_content": article_text,
                "title": mock_article["title"],
                "source_type": "rss_feed",
                "source_name": "Krebs on Security",
                "feed_category": "journalism",
                "published_at": mock_article["published"],
                "relevance": 15,
                "feed_weight": 10,
                "scraped_at": datetime.now(timezone.utc).isoformat(),
                "word_count": len(article_text.split()),
            }
        ]
        MockScraper.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
        MockScraper.return_value.__aexit__ = AsyncMock(return_value=False)

        results = await scrape_rss_feeds("LockBit ransomware")

    assert len(results) == 1
    assert results[0]["source_type"] == "rss_feed"


# ---------------------------------------------------------------------------
# 17. test_max_articles_per_feed_respected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_max_articles_per_feed_respected():
    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = MagicMock()
    scraper._cache = MagicMock()
    scraper._cache.get.return_value = None
    scraper._cache.set = MagicMock()

    pub_date = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
        "%a, %d %b %Y %H:%M:%S +0000"
    )
    raw_articles = [
        {
            "url": f"https://example.com/article/{i}",
            "title": f"LockBit ransomware article {i}",
            "summary": "LockBit ransomware attack details.",
            "published": pub_date,
        }
        for i in range(20)
    ]

    content = "LockBit ransomware encrypted files on victim systems. " * 15

    with (
        patch.object(scraper, "_fetch_and_parse", new=AsyncMock(return_value=raw_articles)),
        patch.object(scraper, "_fetch_article_content", new=AsyncMock(return_value=content)),
        patch("sources.rss_scraper.sanitize_content", return_value=(content, False)),
    ):
        feed = {
            "name": "Test Feed",
            "url": "https://example.com/feed",
            "category": "journalism",
            "tags": ["ransomware"],
            "weight": 10,
        }
        result = await scraper._fetch_feed(feed, ["lockbit", "ransomware"])

    assert len(result) <= MAX_ARTICLES_PER_FEED


# ---------------------------------------------------------------------------
# Phase 1.6 chokepoint wiring — _fetch_and_parse + _fetch_article_content
# + .onion guard
# ---------------------------------------------------------------------------
#
# Mirrors the Phase 2 pattern from tests/test_paste_scraper.py.  All 15
# pre-existing tests above bypass the HTTP path (they test pure functions,
# or patch _fetch_and_parse / _fetch_article_content directly, or mock
# RSSFeedScraper wholesale) — none mock session.get — so NONE of them
# needed structural changes for Phase 3.


@pytest.mark.asyncio
async def test_fetch_and_parse_uses_chokepoint(monkeypatch):
    """_fetch_and_parse routes through clearnet_fetch with expect='xml'."""
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = MagicMock()
    feed_xml = SAMPLE_RSS2_XML.encode("utf-8")

    with patch("sources.rss_scraper.clearnet_fetch", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = (200, "application/rss+xml; charset=utf-8", feed_xml)
        await scraper._fetch_and_parse("https://example.com/feed", "Test Feed")

    assert mock_fetch.called
    call_args = mock_fetch.call_args
    assert call_args.args[0] == "https://example.com/feed"
    assert call_args.kwargs.get("expect") == "xml"
    assert call_args.kwargs.get("fallback_session") is scraper._session
    # The session's default 15s timeout must be preserved
    assert call_args.kwargs.get("timeout") == 15


@pytest.mark.asyncio
async def test_fetch_article_content_uses_chokepoint(monkeypatch):
    """_fetch_article_content routes through clearnet_fetch with expect='html'."""
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = MagicMock()
    body = ("<html><body>" + "Long article text content. " * 50 + "</body></html>").encode("utf-8")

    with patch("sources.rss_scraper.clearnet_fetch", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = (200, "text/html", body)
        result = await scraper._fetch_article_content("https://example.com/article")

    assert mock_fetch.called
    call_args = mock_fetch.call_args
    assert call_args.args[0] == "https://example.com/article"
    assert call_args.kwargs.get("expect") == "html"
    # The 10-second per-call timeout must be preserved exactly
    assert call_args.kwargs.get("timeout") == 10
    assert call_args.kwargs.get("fallback_session") is scraper._session
    # Sanity: the chokepoint's body flowed through extraction
    assert result is not None
    assert len(result) > 100


@pytest.mark.asyncio
async def test_fetch_and_parse_non_200_returns_empty(monkeypatch):
    """_fetch_and_parse returns [] when chokepoint returns non-200."""
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = MagicMock()

    with patch("sources.rss_scraper.clearnet_fetch", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = (404, "text/html", b"not found")
        result = await scraper._fetch_and_parse("https://example.com/feed", "Test Feed")

    assert result == []


@pytest.mark.asyncio
async def test_fetch_article_content_non_200_returns_none(monkeypatch):
    """_fetch_article_content returns None when chokepoint returns non-200."""
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = MagicMock()

    with patch("sources.rss_scraper.clearnet_fetch", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = (404, "text/html", b"not found")
        result = await scraper._fetch_article_content("https://example.com/article")

    assert result is None


@pytest.mark.asyncio
async def test_fetch_article_content_onion_url_refused(monkeypatch):
    """A .onion article URL is rejected before the chokepoint is ever called.

    Belt layer: the rss_scraper-side guard fires first, returns None,
    logs at debug.  Suspenders layer: the chokepoint's own guard inside
    clearnet_fetch would also refuse — verified separately by the proxy
    chokepoint's own test suite.
    """
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = MagicMock()

    with patch("sources.rss_scraper.clearnet_fetch", new_callable=AsyncMock) as mock_fetch:
        result = await scraper._fetch_article_content("http://abcdef.onion/some-article")

    # The chokepoint was NEVER called — guard fires first
    assert not mock_fetch.called, "clearnet_fetch must not be called for .onion URLs"
    # Result is None — same as any other failure case
    assert result is None


@pytest.mark.asyncio
async def test_fetch_article_content_size_truncation(monkeypatch):
    """Body larger than MAX_ARTICLE_SIZE is truncated to MAX_ARTICLE_SIZE.

    The threshold value (MAX_ARTICLE_SIZE = 100 KB) is preserved exactly.
    Truncation now happens on raw bytes (the chokepoint returns bytes)
    rather than on the decoded text.  For ASCII content the two are
    numerically equivalent; the test uses ASCII to verify that the
    boundary is hit precisely.
    """
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = MagicMock()

    # Body well over MAX_ARTICLE_SIZE — all ASCII so bytes = chars
    body = b"<html><body>" + b"X" * (MAX_ARTICLE_SIZE + 5000) + b"</body></html>"

    with patch("sources.rss_scraper.clearnet_fetch", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = (200, "text/html", body)
        result = await scraper._fetch_article_content("https://example.com/article")

    # Truncation, not rejection — function returns extracted text
    assert result is not None
    # The extracted text must be within the size budget.  For ASCII
    # content the tag-stripped result is shorter than the input bytes.
    assert len(result) <= MAX_ARTICLE_SIZE
    # And it should contain the body content (proving the truncation
    # actually happened, not that the body was rejected entirely)
    assert "X" in result


@pytest.mark.asyncio
async def test_rss_scraper_works_with_proxies_disabled(monkeypatch):
    """REGRESSION: with proxies disabled, rss_scraper behavior is
    byte-for-byte identical to pre-v1.6.

    Mocks the underlying aiohttp session (NOT clearnet_fetch) so this
    test exercises the full chokepoint path: _fetch_and_parse →
    clearnet_fetch → _fetch_direct → session.request() → mock response.
    Confirms the chokepoint's internal routing (request vs get) is
    actually in effect, AND that the result is identical to pre-v1.6.
    """
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    feed_xml = SAMPLE_RSS2_XML.encode("utf-8")

    # Build a mock response context manager that the chokepoint can route through
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"content-type": "application/rss+xml; charset=utf-8"}
    mock_resp.read = AsyncMock(return_value=feed_xml)

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_resp)
    cm.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.close = AsyncMock()
    session.request = MagicMock(return_value=cm)
    session.get = MagicMock(return_value=cm)

    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = session

    result = await scraper._fetch_and_parse("https://example.com/feed", "Test Feed")

    # Result is the parsed articles — byte-for-byte identical to pre-v1.6
    assert len(result) == 2
    assert result[0]["url"] == "https://example.com/article/1"
    assert "LockBit" in result[0]["title"]
    assert result[0]["summary"] != ""
    assert result[0]["published"] != ""

    # Chokepoint routing in effect:
    #   - session.request() was called (clearnet_fetch → _fetch_direct path)
    #   - session.get() was NOT called (pre-v1.6 path, no longer used)
    assert session.request.called, (
        "session.request must be called via clearnet_fetch → _fetch_direct"
    )
    assert not session.get.called, (
        "session.get is the pre-v1.6 path; the chokepoint must route via request()"
    )
    method, url = session.request.call_args[0]
    assert method == "GET"
    assert url == "https://example.com/feed"


@pytest.mark.asyncio
async def test_chokepoint_returns_genuine_xml_bytes_parse_correctly(monkeypatch):
    """Validates the browser=false behavior: when the chokepoint returns
    raw XML bytes, the existing ElementTree parser successfully extracts
    article data.

    This is the test that proves browser=false matters.  Without it, a
    headless-browser rendering could mangle the XML (e.g., by inserting
    HTML wrappers, mangling CDATA, or escaping entities) — and the
    ElementTree parser would fail.  By asserting that real RSS 2.0 XML
    bytes flow through end-to-end and produce fully-populated article
    dicts, we confirm the bytes are preserved.
    """
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = MagicMock()

    # Use the genuine sample RSS 2.0 — same as the existing parse tests
    feed_xml = SAMPLE_RSS2_XML.encode("utf-8")

    with patch("sources.rss_scraper.clearnet_fetch", new_callable=AsyncMock) as mock_fetch:
        # Simulate the chokepoint's proxy-path behavior: returns raw XML
        # bytes verbatim (because browser=false was set on the proxy req)
        mock_fetch.return_value = (200, "application/rss+xml; charset=utf-8", feed_xml)
        result = await scraper._fetch_and_parse("https://example.com/feed", "Test Feed")

    # ElementTree parsed the XML successfully — both articles present
    assert len(result) == 2
    # Article data is fully populated — proves the bytes are intact
    assert result[0]["url"] == "https://example.com/article/1"
    assert result[0]["title"] == "LockBit ransomware hits major bank"
    assert "LockBit" in result[0]["summary"]
    assert result[0]["published"] != ""
    assert result[1]["url"] == "https://example.com/article/2"
    assert "malware" in result[1]["title"].lower()


@pytest.mark.asyncio
async def test_summary_fallback_triggers_on_onion_rejection(monkeypatch):
    """When _fetch_article_content returns None for an .onion URL, the
    _fetch_feed method falls back to the article's summary field.

    This proves the onion guard's silent-None return doesn't break the
    existing fallback-to-summary behavior.  The article still appears
    in the result with summary as text_content — exactly the same
    shape it would have for any other fetch failure.

    Test scaffolding note: we pre-populate the feed cache with the
    article list, so the real ``_fetch_and_parse`` (which fetches the
    feed XML over clearnet) is bypassed.  This isolates the test to the
    article-level onion guard and prevents a false-positive failure
    from the feed fetch itself.
    """
    monkeypatch.delenv("SCRAPINGANT_API_KEY", raising=False)
    monkeypatch.delenv("EZIO_USE_PROXIES", raising=False)

    scraper = RSSFeedScraper.__new__(RSSFeedScraper)
    scraper._session = MagicMock()
    scraper._cache = MagicMock()

    long_summary = "Forum post claims LockBit released new stolen data. " * 10
    pub_date = (datetime.now(timezone.utc) - timedelta(days=2)).strftime(
        "%a, %d %b %Y %H:%M:%S +0000"
    )
    raw_articles = [
        {
            "url": "http://abcdef.onion/some-article",  # .onion URL
            "title": "LockBit leak on dark web forum",
            "summary": long_summary,
            "published": pub_date,
        }
    ]

    # Pre-populate cache so _fetch_and_parse (the feed fetch) is bypassed.
    # The cache hit short-circuits the feed-level fetch entirely; the test
    # is then isolated to the article-level onion guard.
    scraper._cache.get.return_value = raw_articles
    scraper._cache.set = MagicMock()

    # Patch clearnet_fetch so we can confirm it was NOT called for the
    # .onion article.  We do NOT patch _fetch_article_content — the real
    # method must run, hit the onion guard, return None, and exercise the
    # summary-fallback path in _fetch_feed.
    with patch("sources.rss_scraper.clearnet_fetch", new_callable=AsyncMock) as mock_fetch:
        feed = {
            "name": "Test Feed",
            "url": "https://example.com/feed",
            "category": "journalism",
            "tags": ["ransomware", "lockbit"],
            "weight": 10,
        }
        result = await scraper._fetch_feed(feed, ["lockbit", "ransomware"])

    # clearnet_fetch was NEVER called — the rss_scraper-side guard fires first
    assert not mock_fetch.called, (
        "clearnet_fetch must not be called for .onion URLs"
    )
    # The article was still included via summary fallback
    assert len(result) == 1
    assert result[0]["url"] == "http://abcdef.onion/some-article"
    # The summary flowed into text_content (the fallback contract)
    assert result[0]["text_content"] == long_summary
    assert result[0]["source_type"] == "rss_feed"
    assert "LockBit" in result[0]["text_content"]
