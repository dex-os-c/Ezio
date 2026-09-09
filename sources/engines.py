"""
sources/engines.py — Additional dark web search engines not in search.py.

search.py handles 16 engines via the legacy thread-pool path (public API
unchanged for ui.py compatibility).  This module adds engines that need
special handling:

  • DarkSearch  — JSON REST API, paginated, optional API key
  • OnionSearch — HTML scraping of Torch and Haystack onion search engines

Both go through the Tor SOCKS5 proxy (TOR_PROXY_HOST / TOR_PROXY_PORT).

Public API:
    async def search_darksearch(query, pages=2)   -> list[dict]
    async def search_onionsearch(query)            -> list[dict]

Each returns list[dict] with keys: title, url, snippet, source.
Empty list on any error — never raises.
"""

from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import quote_plus

import aiohttp
from bs4 import BeautifulSoup

import pacing
from config import DARKSEARCH_API_KEY
from scraper import tor_pool

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DARKSEARCH_API = "http://darksearch.io/api/search"

# Torch and Haystack — specifically called out in concept.md; not in search.py
_ONIONSEARCH_ENGINES = [
    {
        "name": "Torch",
        "url": (
            "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd"
            ".onion/search?query={query}"
        ),
    },
    {
        "name": "Haystack",
        "url": (
            "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid"
            ".onion/?q={query}"
        ),
    },
]

# `normal` pacing baseline; scaled per call by _timeout().
_CONNECT_TIMEOUT = 15
_READ_TIMEOUT = 45


def _timeout() -> aiohttp.ClientTimeout:
    """Request timeout for the active pacing profile, resolved per call."""
    return aiohttp.ClientTimeout(
        connect=pacing.scale_timeout(_CONNECT_TIMEOUT),
        sock_read=pacing.scale_timeout(_READ_TIMEOUT),
    )
_ONION_RE = re.compile(r"https?://[a-z2-7]{16,56}\.onion[^\s\"'<>]*", re.IGNORECASE)
_LAST_ONIONSEARCH_STATUS: dict[str, str] = {"Torch": "not_run", "Haystack": "not_run"}


def get_last_onionsearch_status() -> dict[str, str]:
    """Return the latest per-engine transport/HTTP/parser status."""
    return dict(_LAST_ONIONSEARCH_STATUS)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ua() -> str:
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) "
        "Gecko/20100101 Firefox/137.0"
    )


# ---------------------------------------------------------------------------
# DarkSearch JSON API
# ---------------------------------------------------------------------------

async def search_darksearch(query: str, pages: int = 2) -> List[dict]:
    """
    Query the DarkSearch JSON API and return up to *pages* pages of results.

    Routed through Tor for anonymity even though darksearch.io is clearnet.
    Uses DARKSEARCH_API_KEY as Authorization header when configured.

    Returns list[dict] with keys: title, url, snippet, source.
    Returns [] on any network or parse error.
    """
    results: List[dict] = []
    headers = {"User-Agent": _ua(), "Accept": "application/json"}
    if DARKSEARCH_API_KEY:
        headers["Authorization"] = f"Bearer {DARKSEARCH_API_KEY}"

    try:
        # One pooled session for every page — they all target the same host, so
        # they are one identity to Tor and belong on one circuit.
        #
        # darksearch.io is clearnet but deliberately Tor-routed (see docstring).
        # `tor_isolation_key` maps non-onion hosts to the shared un-isolated
        # bucket, so this path keeps exactly its present behaviour —
        # credential-less SOCKS5 through Tor — while no longer building a
        # throwaway connector on every call.
        session, iso_key = tor_pool.acquire_tor_session(_DARKSEARCH_API)
        try:
            for page in range(1, pages + 1):
                params = {"query": query, "page": page}
                try:
                    async with session.get(
                        _DARKSEARCH_API,
                        params=params,
                        headers=headers,
                        timeout=_timeout(),
                    ) as resp:
                        if resp.status != 200:
                            _logger.debug(
                                "DarkSearch page %d returned HTTP %d", page, resp.status
                            )
                            break
                        data = await resp.json(content_type=None)
                        items = data.get("data") or []
                        for item in items:
                            link = str(item.get("link") or "").strip()
                            if not link:
                                continue
                            results.append(
                                {
                                    "title": str(item.get("title") or "").strip(),
                                    "url": link,
                                    "snippet": str(
                                        item.get("description") or ""
                                    ).strip()[:500],
                                    "source": "DarkSearch",
                                }
                            )
                        # Stop early if we've reached the last page
                        last = data.get("last_page") or page
                        if page >= last:
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    _logger.debug("DarkSearch page %d error: %s", page, exc)
                    break
        finally:
            tor_pool.release_tor_session(iso_key)
    except Exception as exc:
        _logger.debug("DarkSearch session error: %s", exc)

    return results


# ---------------------------------------------------------------------------
# OnionSearch HTML scraping (Torch + Haystack)
# ---------------------------------------------------------------------------

async def search_onionsearch(query: str) -> List[dict]:
    """
    Scrape Torch and Haystack .onion search engines and return extracted links.

    Each engine's result page is fetched, all .onion hrefs are extracted, and
    the surrounding anchor text is used as the title.  No snippet is available
    from this scraping path (snippet is empty string).

    Returns list[dict] with keys: title, url, snippet, source.
    Returns [] on any error; partial results from working engines are included.
    """
    global _LAST_ONIONSEARCH_STATUS
    results: List[dict] = []
    _LAST_ONIONSEARCH_STATUS = {engine["name"]: "pending" for engine in _ONIONSEARCH_ENGINES}
    encoded = quote_plus(query)

    try:
        for engine in _ONIONSEARCH_ENGINES:
            url = engine["url"].replace("{query}", encoded)
            name = engine["name"]
            # Acquired per engine, not once for the loop.  Torch and Haystack
            # are different onion services; sharing one session put them on one
            # circuit, which let either operator correlate our queries to the
            # other.  Keyed on hostname, so a retry or a repeat query to the
            # same engine still reuses its circuit.
            session, iso_key = tor_pool.acquire_tor_session(url)
            try:
                async with session.get(
                    url, headers={"User-Agent": _ua()}, timeout=_timeout()
                ) as resp:
                    if resp.status != 200:
                        _LAST_ONIONSEARCH_STATUS[name] = f"http_{resp.status}"
                        _logger.debug(
                            "%s returned HTTP %d", name, resp.status
                        )
                        continue
                    html = await resp.text(errors="replace")
                    parsed = _parse_onion_links(html, name)
                    results.extend(parsed)
                    _LAST_ONIONSEARCH_STATUS[name] = f"ok_{len(parsed)}_results"
            except (aiohttp.ClientError, Exception) as exc:
                error_name = type(exc).__name__.lower()
                _LAST_ONIONSEARCH_STATUS[name] = (
                    "error_proxy" if "proxy" in error_name or "proxy" in str(exc).lower()
                    else "error_timeout" if isinstance(exc, asyncio.TimeoutError)
                    else "error_transport"
                )
                _logger.debug("%s fetch error: %s", name, exc)
            finally:
                tor_pool.release_tor_session(iso_key)
    except Exception as exc:
        status = "error_proxy" if "proxy" in type(exc).__name__.lower() or "proxy" in str(exc).lower() else "error_transport"
        _LAST_ONIONSEARCH_STATUS = {name: status for name in _LAST_ONIONSEARCH_STATUS}
        _logger.debug("OnionSearch session error: %s", exc)

    return _deduplicate(results)


def _parse_onion_links(html: str, source_name: str) -> List[dict]:
    """
    Extract .onion links + anchor text from an HTML results page.

    Falls back to regex extraction if BeautifulSoup finds nothing useful.
    """
    items: List[dict] = []
    seen: set[str] = set()

    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = str(tag["href"]).strip()
            match = _ONION_RE.match(href)
            if not match:
                continue
            url = match.group(0).rstrip(".,;)'\"")
            if url in seen or "search" in url.lower():
                continue
            title = tag.get_text(strip=True)
            if len(title) < 3:
                continue
            seen.add(url)
            items.append(
                {"title": title, "url": url, "snippet": "", "source": source_name}
            )
    except Exception:
        pass

    # Regex fallback when structured parsing yields nothing
    if not items:
        for url in _ONION_RE.findall(html):
            url = url.rstrip(".,;)'\"")
            if url not in seen and "search" not in url.lower():
                seen.add(url)
                items.append(
                    {"title": url, "url": url, "snippet": "", "source": source_name}
                )

    return items


def _deduplicate(results: List[dict]) -> List[dict]:
    seen: set[str] = set()
    out: List[dict] = []
    for r in results:
        if r["url"] not in seen:
            seen.add(r["url"])
            out.append(r)
    return out


# asyncio is used inside search_darksearch — import here to avoid circular
import asyncio  # noqa: E402
