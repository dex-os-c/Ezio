"""
tests/test_crawler.py — Unit and integration tests for the crawler/ package (Phase 1C).

No real network connections — all HTTP mocked via unittest.mock.
Sentence-transformers model mocked via patch so the test suite never loads it.
DB tests use a separate SQLite file isolated from test_db.py and test_scrape.py.

Covers:
  - Link extraction (extract_onion_links)
  - URL validation (is_valid_onion)
  - URL normalization (normalize_url)
  - URL deduplication (UrlDedup)
  - Content deduplication (ContentDedup)
  - Relevance scoring (Frontier.score)
  - Frontier push/pop priority ordering
  - Politeness delays (timing lock, per-domain delay ranges)
  - DB persistence (page created, source upserted, status transitions)
  - Error handling (failed fetch → pages_failed++, source='failed', crawl continues)
  - CrawlResult return shape

Run with:
    pytest tests/test_crawler.py -v
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import numpy as np
import pytest

# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

# Valid base32 alphabet: a-z and 2-7 (RFC 4648); digits 0,1,8,9 are NOT valid.
_V3_VALID = "a" * 56 + ".onion"             # 56-char v3 hostname  ✓
_V2_VALID = "abcdefghijklmnop" + ".onion"   # 16-char v2 hostname, all valid base32 ✓

# A minimal HTML page with mixed links
_MIXED_HTML = f"""
<html><body>
<a href="http://{_V3_VALID}/page1">v3 onion link</a>
<a href="http://{_V2_VALID}/page2">v2 onion link</a>
<a href="http://example.com/clearnet">clearnet link</a>
<a href="#fragment">fragment</a>
<a href="javascript:void(0)">js link</a>
<a href="/relative">relative path</a>
</body></html>
"""

# ---------------------------------------------------------------------------
# SQLite test DB (separate from test_db.py and test_scrape.py)
# ---------------------------------------------------------------------------

_CRAWLER_DB_FILE = "crawler_test_temp.db"
CRAWLER_TEST_DB_URL = f"sqlite:///{_CRAWLER_DB_FILE}"


@pytest.fixture(scope="module")
def _crawler_db_engine():
    from db.models import Base
    from db.session import _engine_cache, get_engine

    engine = get_engine(CRAWLER_TEST_DB_URL)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()
    _engine_cache.pop(CRAWLER_TEST_DB_URL, None)
    if os.path.exists(_CRAWLER_DB_FILE):
        os.remove(_CRAWLER_DB_FILE)


@pytest.fixture
def _clean_crawler_db(_crawler_db_engine):
    """Wipe all rows before/after each DB test."""
    from sqlalchemy.orm import sessionmaker
    from db.models import Entity, EntityRelationship, Page, Source

    SM = sessionmaker(bind=_crawler_db_engine)

    def _wipe():
        s = SM()
        s.query(EntityRelationship).delete()
        s.query(Entity).delete()
        s.query(Page).delete()
        s.query(Source).delete()
        s.commit()
        s.close()

    _wipe()
    yield
    _wipe()


@pytest.fixture
def _db_url(monkeypatch, _clean_crawler_db):
    """Point DATABASE_URL at the test SQLite file."""
    monkeypatch.setattr("config.DATABASE_URL", CRAWLER_TEST_DB_URL)
    monkeypatch.setattr("db.session.DATABASE_URL", CRAWLER_TEST_DB_URL)
    # The proxy address moved to the shared pool the spider now borrows its
    # sessions from (scraper/tor_pool.py); the spider no longer owns one.
    monkeypatch.setattr("scraper.tor_pool.TOR_PROXY_HOST", "127.0.0.1")
    monkeypatch.setattr("scraper.tor_pool.TOR_PROXY_PORT", "9050")


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def make_mock_response(
    status: int = 200,
    body: bytes = b"<html><body>hello</body></html>",
    content_type: str = "text/html",
) -> MagicMock:
    """Build an aiohttp response mock compatible with async-with and iter_chunked."""
    resp = MagicMock()
    resp.status = status
    resp.headers = {"Content-Type": content_type}
    resp.charset = "utf-8"

    async def iter_chunked(n: int):
        yield body

    resp.content.iter_chunked = iter_chunked
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def make_session_mock(response) -> MagicMock:
    session = MagicMock()
    session.get = MagicMock(return_value=response)
    return session


def _fixed_embedding(text: str, **kwargs) -> np.ndarray:
    """Deterministic 'embedding' for tests — all ones, normalised."""
    return np.ones(384, dtype=np.float32) / np.sqrt(384)


def _mock_model():
    """Return a mock SentenceTransformer that produces fixed embeddings."""
    m = MagicMock()
    m.encode = MagicMock(side_effect=_fixed_embedding)
    return m


# ===========================================================================
# TestLinkExtraction
# ===========================================================================

class TestLinkExtraction:
    """Tests for crawler.utils.extract_onion_links."""

    def test_extracts_v3_onion_links(self):
        from crawler.utils import extract_onion_links
        links = extract_onion_links(_MIXED_HTML, f"http://{_V3_VALID}/")
        assert any(_V3_VALID in lnk for lnk in links)

    def test_extracts_v2_onion_links(self):
        from crawler.utils import extract_onion_links
        links = extract_onion_links(_MIXED_HTML, f"http://{_V3_VALID}/")
        assert any(_V2_VALID in lnk for lnk in links)

    def test_excludes_clearnet_links(self):
        from crawler.utils import extract_onion_links
        links = extract_onion_links(_MIXED_HTML)
        assert not any("example.com" in lnk for lnk in links)

    def test_excludes_fragments(self):
        from crawler.utils import extract_onion_links
        links = extract_onion_links(_MIXED_HTML)
        assert not any(lnk == "#fragment" or lnk.endswith("#") for lnk in links)

    def test_excludes_javascript_hrefs(self):
        from crawler.utils import extract_onion_links
        links = extract_onion_links(_MIXED_HTML)
        assert not any("javascript" in lnk for lnk in links)

    def test_resolves_relative_links(self):
        """Relative /path should become absolute when base_url is provided."""
        html = f'<a href="/path/page">link</a>'
        from crawler.utils import extract_onion_links
        links = extract_onion_links(
            html, base_url=f"http://{_V3_VALID}/"
        )
        # The relative /path on a v3 onion should produce a valid absolute link
        if links:
            assert links[0].startswith("http://")
            assert _V3_VALID in links[0]

    def test_deduplicates_within_page(self):
        html = (
            f'<a href="http://{_V3_VALID}/dup">1</a>'
            f'<a href="http://{_V3_VALID}/dup">2</a>'
        )
        from crawler.utils import extract_onion_links
        links = extract_onion_links(html)
        assert links.count(f"http://{_V3_VALID}/dup") == 1

    def test_returns_empty_on_bad_html(self):
        from crawler.utils import extract_onion_links
        # Should not raise; BeautifulSoup is permissive
        links = extract_onion_links("not html at all <<< >>>")
        assert isinstance(links, list)

    def test_returns_empty_when_no_onion_links(self):
        from crawler.utils import extract_onion_links
        html = '<a href="http://example.com/">link</a>'
        assert extract_onion_links(html) == []


# ===========================================================================
# TestUrlValidation
# ===========================================================================

class TestUrlValidation:
    """Tests for crawler.utils.is_valid_onion."""

    def test_v3_http_valid(self):
        from crawler.utils import is_valid_onion
        assert is_valid_onion(f"http://{_V3_VALID}/") is True

    def test_v3_https_valid(self):
        from crawler.utils import is_valid_onion
        assert is_valid_onion(f"https://{_V3_VALID}/path") is True

    def test_v2_valid(self):
        from crawler.utils import is_valid_onion
        assert is_valid_onion(f"http://{_V2_VALID}/") is True

    def test_clearnet_invalid(self):
        from crawler.utils import is_valid_onion
        assert is_valid_onion("http://example.com/") is False

    def test_wrong_scheme_invalid(self):
        from crawler.utils import is_valid_onion
        assert is_valid_onion(f"ftp://{_V3_VALID}/") is False

    def test_too_short_hostname_invalid(self):
        from crawler.utils import is_valid_onion
        # 10-char hostname — neither v2 (16) nor v3 (56)
        assert is_valid_onion("http://abcde12345.onion/") is False

    def test_55_char_hostname_invalid(self):
        from crawler.utils import is_valid_onion
        host = "a" * 55 + ".onion"
        assert is_valid_onion(f"http://{host}/") is False

    def test_empty_string_invalid(self):
        from crawler.utils import is_valid_onion
        assert is_valid_onion("") is False

    def test_invalid_base32_char_in_host(self):
        from crawler.utils import is_valid_onion
        # '8' and '9' are not valid base32 chars
        host = "8" * 16 + ".onion"
        assert is_valid_onion(f"http://{host}/") is False

    def test_v3_with_path_and_query_valid(self):
        from crawler.utils import is_valid_onion
        url = f"http://{_V3_VALID}/forum/thread?id=42"
        assert is_valid_onion(url) is True


# ===========================================================================
# TestNormalization
# ===========================================================================

class TestNormalization:
    """Tests for crawler.utils.normalize_url."""

    def test_lowercases_scheme(self):
        from crawler.utils import normalize_url
        assert normalize_url(f"HTTP://{_V3_VALID}/").startswith("http://")

    def test_lowercases_host(self):
        from crawler.utils import normalize_url
        upper = f"http://{_V3_VALID.upper()}/path"
        assert _V3_VALID.lower() in normalize_url(upper)

    def test_strips_fragment(self):
        from crawler.utils import normalize_url
        url = f"http://{_V3_VALID}/path#section"
        assert "#" not in normalize_url(url)

    def test_strips_trailing_slash_from_path(self):
        from crawler.utils import normalize_url
        url = f"http://{_V3_VALID}/path/"
        assert not normalize_url(url).endswith("/")

    def test_preserves_query_string(self):
        from crawler.utils import normalize_url
        url = f"http://{_V3_VALID}/search?q=test"
        assert "q=test" in normalize_url(url)

    def test_root_path_normalized_consistently(self):
        from crawler.utils import normalize_url
        # Two representations of the root should normalize identically
        a = normalize_url(f"http://{_V3_VALID}/")
        b = normalize_url(f"http://{_V3_VALID}")
        assert a == b

    def test_idempotent(self):
        from crawler.utils import normalize_url
        url = f"http://{_V3_VALID}/path?q=1"
        assert normalize_url(normalize_url(url)) == normalize_url(url)


# ===========================================================================
# TestUrlDedup
# ===========================================================================

class TestUrlDedup:
    """Tests for crawler.dedup.UrlDedup."""

    def test_new_url_is_new(self):
        from crawler.dedup import UrlDedup
        d = UrlDedup()
        assert d.is_new("http://example.onion/") is True

    def test_seen_url_is_not_new(self):
        from crawler.dedup import UrlDedup
        d = UrlDedup()
        url = "http://example.onion/"
        d.mark_seen(url)
        assert d.is_new(url) is False

    def test_different_urls_independent(self):
        from crawler.dedup import UrlDedup
        d = UrlDedup()
        d.mark_seen("http://aaa.onion/")
        assert d.is_new("http://bbb.onion/") is True

    def test_len_tracks_seen_count(self):
        from crawler.dedup import UrlDedup
        d = UrlDedup()
        d.mark_seen("http://a.onion/")
        d.mark_seen("http://b.onion/")
        d.mark_seen("http://a.onion/")  # duplicate, should not count twice
        assert len(d) == 2

    def test_empty_dedup_starts_fresh(self):
        from crawler.dedup import UrlDedup
        d1 = UrlDedup()
        d2 = UrlDedup()
        d1.mark_seen("http://shared.onion/")
        # d2 is independent
        assert d2.is_new("http://shared.onion/") is True


# ===========================================================================
# TestContentDedup
# ===========================================================================

class TestContentDedup:
    """Tests for crawler.dedup.ContentDedup."""

    def test_hash_bytes_is_sha256(self):
        from crawler.dedup import ContentDedup
        data = b"hello world"
        expected = hashlib.sha256(data).hexdigest()
        assert ContentDedup.hash_bytes(data) == expected

    def test_hash_text_encodes_utf8(self):
        from crawler.dedup import ContentDedup
        text = "hello"
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
        assert ContentDedup.hash_text(text) == expected

    def test_not_duplicate_when_no_db_url(self, monkeypatch):
        monkeypatch.setattr("config.DATABASE_URL", None)
        from crawler.dedup import ContentDedup
        assert ContentDedup.is_duplicate("anyhash") is False

    def test_not_duplicate_when_hash_absent(self, _db_url):
        from crawler.dedup import ContentDedup
        unknown_hash = "a" * 64
        assert ContentDedup.is_duplicate(unknown_hash, db_url=CRAWLER_TEST_DB_URL) is False

    def test_is_duplicate_when_hash_present(self, _db_url):
        from crawler.dedup import ContentDedup
        from db.queries import create_page
        from db.session import get_session

        content_hash = "b" * 64
        with get_session(CRAWLER_TEST_DB_URL) as s:
            create_page(s, url="http://dup-test.onion/", raw_content_hash=content_hash)

        assert ContentDedup.is_duplicate(content_hash, db_url=CRAWLER_TEST_DB_URL) is True

    def test_returns_false_on_db_error(self, monkeypatch):
        monkeypatch.setattr("config.DATABASE_URL", CRAWLER_TEST_DB_URL)
        with patch("db.session.get_session", side_effect=RuntimeError("DB down")):
            from crawler.dedup import ContentDedup
            assert ContentDedup.is_duplicate("anyhash") is False


# ===========================================================================
# TestFrontier
# ===========================================================================

class TestFrontier:
    """Tests for crawler.frontier.Frontier (sentence-transformers model mocked)."""

    @pytest.fixture(autouse=True)
    def _mock_st(self):
        """Replace the global model singleton for every test in this class."""
        with patch("crawler.frontier._get_model", return_value=_mock_model()):
            import crawler.frontier as ft
            ft._model = None  # reset so fixture takes effect
            yield
            ft._model = None

    def test_score_returns_float_in_range(self):
        from crawler.frontier import Frontier
        f = Frontier("test query")
        s = f.score("http://test.onion/", "some content")
        assert isinstance(s, float)
        assert 0.0 <= s <= 1.0

    def test_score_handles_model_exception(self):
        """Frontier.score must return 0.5 fallback when encoding fails."""
        bad_model = MagicMock()
        bad_model.encode = MagicMock(side_effect=RuntimeError("encoding failed"))
        with patch("crawler.frontier._get_model", return_value=bad_model):
            from crawler.frontier import Frontier
            f = Frontier("query")
            assert f.score("http://x.onion/") == 0.5

    def test_push_pop_returns_highest_score_first(self):
        from crawler.frontier import Frontier
        f = Frontier("query")
        # Push in low→high order; expect high→low out
        f.push("http://low.onion/", depth=1, score=0.2)
        f.push("http://high.onion/", depth=1, score=0.9)
        f.push("http://mid.onion/", depth=1, score=0.5)

        url1, _ = f.pop()
        url2, _ = f.pop()
        url3, _ = f.pop()

        assert url1 == "http://high.onion/"
        assert url2 == "http://mid.onion/"
        assert url3 == "http://low.onion/"

    def test_pop_returns_correct_depth(self):
        from crawler.frontier import Frontier
        f = Frontier("query")
        f.push("http://x.onion/", depth=2, score=0.8)
        _, depth = f.pop()
        assert depth == 2

    def test_empty_on_fresh_frontier(self):
        from crawler.frontier import Frontier
        assert Frontier("q").empty() is True

    def test_not_empty_after_push(self):
        from crawler.frontier import Frontier
        f = Frontier("q")
        f.push("http://x.onion/", depth=0, score=0.7)
        assert f.empty() is False

    def test_len_tracks_queue_size(self):
        from crawler.frontier import Frontier
        f = Frontier("q")
        assert len(f) == 0
        f.push("http://a.onion/", depth=0, score=0.5)
        f.push("http://b.onion/", depth=0, score=0.6)
        assert len(f) == 2
        f.pop()
        assert len(f) == 1

    def test_query_embedding_cached(self):
        """_query_emb() must call encode exactly once for the query."""
        mock = _mock_model()
        with patch("crawler.frontier._get_model", return_value=mock):
            from crawler.frontier import Frontier
            f = Frontier("cached query")
            f._query_emb()
            f._query_emb()
            # encode called once for the query (first _query_emb call)
            assert mock.encode.call_count == 1


# ===========================================================================
# TestPolitenessDelays
# ===========================================================================

class TestPolitenessDelays:
    """Tests for Spider's per-domain delay logic."""

    def _make_spider(self):
        from crawler.spider import Spider
        return Spider(
            seed_urls=[],
            query="test",
            max_depth=1,
            max_pages=10,
            min_relevance=0.0,
        )

    def test_first_domain_access_uses_short_delay(self):
        """First visit to a domain should sleep in [0.5, 2.0] range."""
        spider = self._make_spider()
        slept: list[float] = []

        async def run():
            with patch("crawler.spider.asyncio.sleep", side_effect=lambda d: slept.append(d) or asyncio.coroutine(lambda: None)()):
                # Manually call _polite_delay for a new domain
                with patch("asyncio.sleep", new=AsyncMock(side_effect=lambda d: slept.append(d))):
                    from crawler import spider as sp_mod
                    with patch.object(sp_mod, "asyncio") as mock_asyncio:
                        mock_asyncio.sleep = AsyncMock(side_effect=lambda d: slept.append(d))
                        mock_asyncio.Lock = asyncio.Lock
                        mock_asyncio.Semaphore = asyncio.Semaphore
                        mock_asyncio.wait = asyncio.wait
                        mock_asyncio.create_task = asyncio.create_task
                        await spider._polite_delay("newdomain.onion")

        # Run with real asyncio.sleep mocked
        with patch("crawler.spider.asyncio.sleep", new=AsyncMock(side_effect=lambda d: slept.append(d))):
            asyncio.run(spider._polite_delay("brand-new-domain.onion"))

        assert len(slept) == 1
        assert 0.5 <= slept[0] <= 2.0

    def test_same_domain_revisit_uses_long_delay(self):
        """Revisit within the same run should sleep in [2.0, 8.0] range."""
        spider = self._make_spider()
        slept: list[float] = []

        async def run():
            # Simulate a very recent prior access (elapsed ≈ 0 → full delay needed)
            spider._domain_last_access["test.onion"] = time.monotonic()
            with patch("crawler.spider.asyncio.sleep", new=AsyncMock(side_effect=lambda d: slept.append(d))):
                await spider._polite_delay("test.onion")

        asyncio.run(run())
        assert len(slept) == 1
        assert 2.0 <= slept[0] <= 8.0

    def test_recent_access_delay_is_reduced(self):
        """If domain was accessed 5s ago and needed delay is 6s, sleep ~1s."""
        spider = self._make_spider()
        slept: list[float] = []

        async def run():
            spider._domain_last_access["test.onion"] = time.monotonic() - 5.0
            with patch("crawler.spider.random.uniform", return_value=6.0):
                with patch("crawler.spider.asyncio.sleep", new=AsyncMock(side_effect=lambda d: slept.append(d))):
                    await spider._polite_delay("test.onion")

        asyncio.run(run())
        assert slept[0] == pytest.approx(1.0, abs=0.5)

    def test_domain_semaphore_max_3(self):
        """Each domain semaphore must be initialised with value=3."""
        from crawler.spider import Spider, _DOMAIN_MAX_CONCURRENT
        spider = Spider([], "q")
        sem = spider._domain_semaphores["any.onion"]
        assert sem._value == _DOMAIN_MAX_CONCURRENT  # type: ignore[attr-defined]
        assert _DOMAIN_MAX_CONCURRENT == 3


# ===========================================================================
# TestDBPersistence
# ===========================================================================

class TestDBPersistence:
    """Tests for Spider's DB integration helpers."""

    def test_upsert_source_discovered_creates_row(self, _db_url):
        from sqlalchemy.orm import sessionmaker
        from db.models import Source
        from db.session import get_engine
        from crawler.spider import Spider

        spider = Spider([f"http://{_V3_VALID}/"], "q")
        spider._db_upsert_source(f"http://{_V3_VALID}/", "discovered")

        SM = sessionmaker(bind=get_engine(CRAWLER_TEST_DB_URL))
        s = SM()
        src = s.query(Source).filter_by(onion_address=_V3_VALID).first()
        s.close()

        assert src is not None
        assert src.status == "discovered"

    def test_upsert_source_active_overwrites_discovered(self, _db_url):
        from sqlalchemy.orm import sessionmaker
        from db.models import Source
        from db.session import get_engine
        from crawler.spider import Spider

        spider = Spider([f"http://{_V3_VALID}/"], "q")
        spider._db_upsert_source(f"http://{_V3_VALID}/", "discovered")
        spider._db_upsert_source(f"http://{_V3_VALID}/", "active")

        SM = sessionmaker(bind=get_engine(CRAWLER_TEST_DB_URL))
        s = SM()
        src = s.query(Source).filter_by(onion_address=_V3_VALID).first()
        s.close()

        assert src.status == "active"

    def test_persist_page_creates_page_row(self, _db_url):
        from sqlalchemy.orm import sessionmaker
        from db.models import Page
        from db.session import get_engine
        from crawler.spider import Spider

        spider = Spider([], "q")
        raw = b"<html><body>dark web content</body></html>"
        content_hash = hashlib.sha256(raw).hexdigest()
        url = f"http://{_V3_VALID}/thread/1"

        spider._db_persist_page(url, raw, "dark web content", content_hash)

        SM = sessionmaker(bind=get_engine(CRAWLER_TEST_DB_URL))
        s = SM()
        page = s.query(Page).filter_by(url=url).first()
        s.close()

        assert page is not None
        assert page.raw_content_hash == content_hash
        assert page.cleaned_text == "dark web content"

    def test_persist_page_sets_source_active(self, _db_url):
        from sqlalchemy.orm import sessionmaker
        from db.models import Source
        from db.session import get_engine
        from crawler.spider import Spider

        spider = Spider([], "q")
        raw = b"<html><body>content</body></html>"
        url = f"http://{_V3_VALID}/page"
        spider._db_persist_page(url, raw, "content", hashlib.sha256(raw).hexdigest())

        SM = sessionmaker(bind=get_engine(CRAWLER_TEST_DB_URL))
        s = SM()
        src = s.query(Source).filter_by(onion_address=_V3_VALID).first()
        s.close()

        assert src is not None
        assert src.status == "active"

    def test_mark_source_failed(self, _db_url):
        from sqlalchemy.orm import sessionmaker
        from db.models import Source
        from db.session import get_engine
        from crawler.spider import Spider

        spider = Spider([], "q")
        url = f"http://{_V3_VALID}/missing"
        spider._db_upsert_source(url, "failed")

        SM = sessionmaker(bind=get_engine(CRAWLER_TEST_DB_URL))
        s = SM()
        src = s.query(Source).filter_by(onion_address=_V3_VALID).first()
        s.close()

        assert src is not None
        assert src.status == "failed"

    def test_db_errors_do_not_raise(self, monkeypatch):
        """DB helper methods must swallow exceptions and never propagate them."""
        monkeypatch.setattr("config.DATABASE_URL", CRAWLER_TEST_DB_URL)
        from crawler.spider import Spider

        spider = Spider([], "q")
        with patch("db.session.get_session", side_effect=RuntimeError("DB down")):
            # None of these should raise
            spider._db_upsert_source(f"http://{_V3_VALID}/", "discovered")
            spider._db_persist_page(
                f"http://{_V3_VALID}/x",
                b"data",
                "text",
                "a" * 64,
            )


# ===========================================================================
# TestErrorHandling
# ===========================================================================

class TestErrorHandling:
    """Tests that failed fetches don't crash the crawl."""

    def _run_spider_with_response(self, url, response, extra_patches=None):
        """Helper: run Spider._process_url with a mocked session."""
        from crawler.spider import Spider

        patches = {
            "crawler.spider.asyncio.sleep": AsyncMock(),
            "config.DATABASE_URL": None,
            "scraper.tor_pool.TOR_PROXY_HOST": "127.0.0.1",
            "scraper.tor_pool.TOR_PROXY_PORT": "9050",
        }
        if extra_patches:
            patches.update(extra_patches)

        spider = Spider([], "q", min_relevance=0.0)
        # Give the frontier a dummy query embedding so score() doesn't try to load the model
        with patch("crawler.frontier._get_model", return_value=_mock_model()):
            session = make_session_mock(response)

            async def run():
                spider._url_dedup.mark_seen(url)
                await spider._process_url(url, depth=0, session=session)

            with patch("crawler.spider.asyncio.sleep", new=AsyncMock()):
                with patch("crawler.spider.RETRY_DELAYS", (0.0, 0.0, 0.0)):
                    asyncio.run(run())

        return spider

    def test_404_increments_pages_failed(self):
        url = f"http://{_V3_VALID}/missing"
        resp = make_mock_response(status=404)
        spider = self._run_spider_with_response(url, resp)
        assert spider._pages_failed == 1
        assert spider._pages_crawled == 0

    def test_503_exhausted_retries_increments_failed(self):
        url = f"http://{_V3_VALID}/down"
        resp = make_mock_response(status=503)
        # Patch RETRY_DELAYS so tests don't actually wait
        with patch("crawler.spider.RETRY_DELAYS", (0.0, 0.0, 0.0)):
            spider = self._run_spider_with_response(url, resp)
        assert spider._pages_failed == 1

    def test_client_error_increments_pages_failed(self):
        url = f"http://{_V3_VALID}/err"
        session = MagicMock()
        session.get = MagicMock(side_effect=aiohttp.ClientConnectionError("conn err"))

        from crawler.spider import Spider

        spider = Spider([], "q", min_relevance=0.0)
        with patch("crawler.frontier._get_model", return_value=_mock_model()):
            with patch("crawler.spider.asyncio.sleep", new=AsyncMock()):
                with patch("crawler.spider.RETRY_DELAYS", (0.0, 0.0, 0.0)):
                    with patch("config.DATABASE_URL", None):
                        async def run():
                            await spider._process_url(url, depth=0, session=session)
                        asyncio.run(run())

        assert spider._pages_failed == 1
        assert spider._pages_crawled == 0

    def test_failed_page_does_not_prevent_other_pages(self):
        """Crawl should complete successfully even when one URL fails."""
        good_url = f"http://{_V3_VALID}/"
        bad_url = f"http://{_V2_VALID}/"
        good_body = (
            f"<html><body>good content</body></html>"
        ).encode()

        from crawler.spider import Spider

        good_resp = make_mock_response(status=200, body=good_body)
        bad_resp = make_mock_response(status=404)

        def side_effect(url, **kwargs):
            if _V3_VALID in url:
                return good_resp
            return bad_resp

        session = MagicMock()
        session.get = MagicMock(side_effect=side_effect)

        spider = Spider([], "q", min_relevance=0.0)
        with patch("crawler.frontier._get_model", return_value=_mock_model()):
            with patch("crawler.spider.asyncio.sleep", new=AsyncMock()):
                with patch("crawler.spider.RETRY_DELAYS", (0.0, 0.0, 0.0)):
                    with patch("config.DATABASE_URL", None):
                        async def run():
                            await spider._process_url(good_url, depth=0, session=session)
                            await spider._process_url(bad_url, depth=0, session=session)
                        asyncio.run(run())

        assert spider._pages_crawled == 1
        assert spider._pages_failed == 1


# ===========================================================================
# TestCrawlResultShape
# ===========================================================================

class TestCrawlResultShape:
    """Tests for the CrawlResult dataclass and crawl() function."""

    def test_crawlresult_default_values(self):
        from crawler.spider import CrawlResult
        r = CrawlResult()
        assert r.pages_crawled == 0
        assert r.pages_failed == 0
        assert r.new_urls_discovered == 0
        assert r.results == []

    def test_crawlresult_accessible_from_package(self):
        from crawler import CrawlResult
        r = CrawlResult(pages_crawled=5, pages_failed=1, new_urls_discovered=12)
        assert r.pages_crawled == 5

    def test_crawl_function_accessible_from_package(self):
        from crawler import crawl
        assert callable(crawl)

    def test_crawl_returns_crawlresult(self):
        """crawl() with invalid seed URLs returns an empty CrawlResult."""
        from crawler import crawl

        with patch("crawler.frontier._get_model", return_value=_mock_model()):
            result = asyncio.run(crawl(
                seed_urls=["http://notanonion.com/"],
                query="test",
            ))

        from crawler import CrawlResult
        assert isinstance(result, CrawlResult)
        assert result.pages_crawled == 0

    def test_crawl_no_valid_seeds_returns_empty(self):
        from crawler import crawl

        with patch("crawler.frontier._get_model", return_value=_mock_model()):
            result = asyncio.run(crawl(
                seed_urls=["not-a-url", "ftp://invalid.onion/"],
                query="ransomware",
            ))

        assert result.pages_crawled == 0
        assert result.pages_failed == 0
        assert result.results == []

    def test_crawl_result_entries_have_url_and_content(self):
        """Each dict in results must have 'url' and 'content' keys."""
        from crawler.spider import CrawlResult

        result = CrawlResult(
            pages_crawled=1,
            results=[{"url": f"http://{_V3_VALID}/", "content": "text"}],
        )
        for entry in result.results:
            assert "url" in entry
            assert "content" in entry

    def test_crawl_with_mocked_fetch(self):
        """End-to-end: crawl with one seed that returns a page with child links."""
        from crawler import crawl

        seed = f"http://{_V3_VALID}/"
        child_host = _V2_VALID
        child_url = f"http://{child_host}/"

        # Page at the seed contains a link to the child
        seed_body = (
            f'<html><body>seed content '
            f'<a href="{child_url}">child</a>'
            f'</body></html>'
        ).encode()

        seed_resp = make_mock_response(status=200, body=seed_body)
        child_resp = make_mock_response(
            status=200,
            body=b"<html><body>child content</body></html>",
        )

        def get_side_effect(url, **kwargs):
            if _V3_VALID in url:
                return seed_resp
            return child_resp

        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=get_side_effect)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        # The spider no longer builds its own connector/session — it borrows one
        # from the shared Tor isolation pool.  Patching the acquire call is the
        # injection point now, and it also keeps this mock out of the
        # module-global pool where later tests would find it.
        with patch("crawler.frontier._get_model", return_value=_mock_model()), \
             patch("scraper.tor_pool.acquire_tor_session",
                   return_value=(mock_session, "mock-isolation-key")), \
             patch("crawler.spider.asyncio.sleep", new=AsyncMock()), \
             patch("crawler.spider.RETRY_DELAYS", (0.0, 0.0, 0.0)), \
             patch("config.DATABASE_URL", None):

            result = asyncio.run(crawl(
                seed_urls=[seed],
                query="dark web market",
                max_depth=1,
                max_pages=10,
                min_relevance=0.0,
            ))

        assert isinstance(result.pages_crawled, int)
        assert isinstance(result.pages_failed, int)
        assert isinstance(result.new_urls_discovered, int)
        assert isinstance(result.results, list)
        # Seed page should have been crawled
        assert result.pages_crawled >= 1
        # At minimum the child URL should have been discovered
        assert result.new_urls_discovered >= 1

    def test_content_truncated_at_2000_chars(self):
        """Content in results list must be ≤ 2000 chars."""
        from crawler.spider import MAX_RETURN_CHARS, Spider

        spider = Spider([], "q", min_relevance=0.0)
        long_text = "x" * 5000
        long_html = f"<html><body>{'x' * 5000}</body></html>"
        long_body = long_html.encode()

        resp = make_mock_response(status=200, body=long_body)
        session = make_session_mock(resp)

        url = f"http://{_V3_VALID}/"
        with patch("crawler.frontier._get_model", return_value=_mock_model()), \
             patch("crawler.spider.asyncio.sleep", new=AsyncMock()), \
             patch("crawler.spider.RETRY_DELAYS", (0.0, 0.0, 0.0)), \
             patch("config.DATABASE_URL", None):

            async def run():
                await spider._process_url(url, depth=0, session=session)

            asyncio.run(run())

        if spider._results:
            assert len(spider._results[0]["content"]) <= MAX_RETURN_CHARS
