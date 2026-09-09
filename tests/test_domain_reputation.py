"""
Tests for sources/domain_reputation.py

Covers: crt.sh parsing, URLScan verdict, Wayback detection,
onion/private domain filtering, caps, cache TTL, graceful degradation,
sources_used tracking, and max domain limit.
"""

from __future__ import annotations

import asyncio
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import sources.domain_reputation as dr
from sources.domain_reputation import (
    _crt_cache,
    _urlscan_cache,
    _wayback_cache,
    check_domain_reputation,
    enrich_domain_entities,
    query_crt_sh,
    query_urlscan,
    query_wayback,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_caches():
    _crt_cache.clear()
    _urlscan_cache.clear()
    _wayback_cache.clear()


def _make_entity(entity_type: str, value: str, confidence: float = 0.9):
    e = MagicMock()
    e.entity_type = entity_type
    e.value = value
    e.confidence = confidence
    return e


def _make_result(entities: list):
    r = MagicMock()
    r.entities = list(entities)
    r.entity_count = len(entities)
    return r


def _crt_response(domain: str, names: list[str]) -> list[dict]:
    return [
        {
            "name_value": name,
            "not_before": "2023-01-01T00:00:00",
            "not_after": "2024-01-01T00:00:00",
            "issuer_name": "Let's Encrypt",
        }
        for name in names
    ]


def _urlscan_response(malicious: bool, tags: list[str], ips: list[str], techs: list[str]) -> dict:
    return {
        "results": [
            {
                "verdicts": {
                    "overall": {
                        "malicious": malicious,
                        "tags": tags,
                        "categories": [],
                    }
                },
                "lists": {"ips": ips},
                "meta": {
                    "processors": {
                        "wappa": {
                            "data": [{"app": t} for t in techs]
                        }
                    }
                },
                "task": {"screenshotURL": "https://urlscan.io/screenshot/test.png"},
            }
        ]
    }


def _wayback_response(timestamps: list[str], status_codes: list[str]) -> list:
    header = ["timestamp", "statuscode", "mimetype"]
    rows = [header] + [
        [ts, sc, "text/html"] for ts, sc in zip(timestamps, status_codes)
    ]
    return rows


def _make_mock_session(json_response):
    """Build a mock aiohttp ClientSession that returns json_response on .get()."""
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=json_response)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_get = MagicMock()
    mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get.__aexit__ = AsyncMock(return_value=False)
    mock_get.return_value = mock_resp

    mock_session = AsyncMock()
    mock_session.get = MagicMock(return_value=mock_get)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    return mock_session


# ---------------------------------------------------------------------------
# 1. crt.sh JSON parsing extracts subdomains correctly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_crt_sh_parses_subdomains():
    _reset_caches()
    names = ["api.example.com", "mail.example.com"]
    payload = _crt_response("example.com", names)

    with patch("aiohttp.ClientSession") as cls:
        cls.return_value = _make_mock_session(payload)
        result = await query_crt_sh("example.com")

    assert len(result) == 2
    values = {r["name"] for r in result}
    assert "api.example.com" in values
    assert "mail.example.com" in values
    for r in result:
        assert "first_seen" in r
        assert "issuer" in r


# ---------------------------------------------------------------------------
# 2. Wildcard subdomains filtered out
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_crt_sh_filters_wildcards():
    _reset_caches()
    payload = _crt_response("example.com", ["*.example.com", "api.example.com"])

    with patch("aiohttp.ClientSession") as cls:
        cls.return_value = _make_mock_session(payload)
        result = await query_crt_sh("example.com")

    names = [r["name"] for r in result]
    assert "*.example.com" not in names
    assert "api.example.com" in names


# ---------------------------------------------------------------------------
# 3. Subdomain cap of 20 enforced
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_crt_sh_caps_at_20():
    _reset_caches()
    names = [f"sub{i}.example.com" for i in range(30)]
    payload = _crt_response("example.com", names)

    with patch("aiohttp.ClientSession") as cls:
        cls.return_value = _make_mock_session(payload)
        result = await query_crt_sh("example.com")

    assert len(result) <= 20


# ---------------------------------------------------------------------------
# 4. URLScan malicious verdict boosts confidence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_urlscan_malicious_boosts_confidence():
    _reset_caches()
    payload = _urlscan_response(malicious=True, tags=["phishing"], ips=["1.2.3.4"], techs=[])

    with patch("aiohttp.ClientSession") as cls:
        cls.return_value = _make_mock_session(payload)
        with patch.dict(os.environ, {}, clear=False):
            rep = await check_domain_reputation("evil.example.com", base_confidence=0.8)

    assert rep["urlscan_malicious"] is True
    assert rep["confidence_delta"] == pytest.approx(0.10)
    assert "urlscan_malicious" in rep["tags"]


# ---------------------------------------------------------------------------
# 5. URLScan tags propagate to entity
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_urlscan_tags_propagate():
    _reset_caches()
    payload = _urlscan_response(
        malicious=False, tags=["malware", "botnet"], ips=[], techs=[]
    )

    with patch("aiohttp.ClientSession") as cls:
        cls.return_value = _make_mock_session(payload)
        result = await query_urlscan("example.com")

    assert "malware" in result["tags"]
    assert "botnet" in result["tags"]


# ---------------------------------------------------------------------------
# 6. URLScan communicating IPs added as new entities
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_urlscan_ips_become_new_entities():
    _reset_caches()
    payload = _urlscan_response(malicious=False, tags=[], ips=["1.2.3.4", "5.6.7.8"], techs=[])

    with patch("aiohttp.ClientSession") as cls:
        cls.return_value = _make_mock_session(payload)
        rep = await check_domain_reputation("example.com", base_confidence=0.8)

    ip_entities = [e for e in rep["new_entities"] if e["entity_type"] == "IP_ADDRESS"]
    assert len(ip_entities) == 2
    ip_values = {e["value"] for e in ip_entities}
    assert "1.2.3.4" in ip_values
    assert "5.6.7.8" in ip_values
    for e in ip_entities:
        assert e["confidence"] == pytest.approx(0.72)
        assert e["source"] == "urlscan"


# ---------------------------------------------------------------------------
# 7. IP cap of 5 from URLScan enforced
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_urlscan_ip_cap_enforced():
    _reset_caches()
    ips = [f"1.1.1.{i}" for i in range(10)]
    payload = _urlscan_response(malicious=False, tags=[], ips=ips, techs=[])

    with patch("aiohttp.ClientSession") as cls:
        cls.return_value = _make_mock_session(payload)
        result = await query_urlscan("example.com")

    assert len(result["ips"]) <= 5


# ---------------------------------------------------------------------------
# 8. Wayback exists correctly detected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wayback_exists_detected():
    _reset_caches()
    payload = _wayback_response(
        timestamps=["20200101120000", "20230601120000"],
        status_codes=["200", "200"],
    )

    with patch("aiohttp.ClientSession") as cls:
        cls.return_value = _make_mock_session(payload)
        result = await query_wayback("example.com")

    assert result["exists"] is True
    assert result["first_seen"] == "2020-01-01"
    assert result["last_seen"] == "2023-06-01"
    assert result["likely_taken_down"] is False


# ---------------------------------------------------------------------------
# 9. Wayback 200→404 pattern detected as likely_taken_down
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wayback_200_to_404_is_taken_down():
    _reset_caches()
    payload = _wayback_response(
        timestamps=["20190101120000", "20240101120000"],
        status_codes=["200", "404"],
    )

    with patch("aiohttp.ClientSession") as cls:
        cls.return_value = _make_mock_session(payload)
        result = await query_wayback("takedown.example.com")

    assert result["exists"] is True
    assert result["likely_taken_down"] is True


# ---------------------------------------------------------------------------
# 10. Wayback first/last seen dates parsed correctly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wayback_dates_parsed():
    _reset_caches()
    payload = _wayback_response(
        timestamps=["20150315093000", "20231225183000"],
        status_codes=["200", "200"],
    )

    with patch("aiohttp.ClientSession") as cls:
        cls.return_value = _make_mock_session(payload)
        result = await query_wayback("dates.example.com")

    assert result["first_seen"] == "2015-03-15"
    assert result["last_seen"] == "2023-12-25"


# ---------------------------------------------------------------------------
# 11. Onion URLs skipped entirely
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_onion_domain_skipped():
    _reset_caches()
    crt_mock = AsyncMock(return_value=[{"name": "sub.example.onion"}])
    urlscan_mock = AsyncMock(return_value={"malicious": True})
    wayback_mock = AsyncMock(return_value={"exists": True})

    with patch.object(dr, "query_crt_sh", crt_mock), \
         patch.object(dr, "query_urlscan", urlscan_mock), \
         patch.object(dr, "query_wayback", wayback_mock):
        rep = await check_domain_reputation("something.onion")

    assert rep["crt_subdomains"] == []
    assert rep["urlscan_malicious"] is False
    assert rep["wayback_exists"] is False
    assert rep["tags"] == []
    crt_mock.assert_not_called()
    urlscan_mock.assert_not_called()
    wayback_mock.assert_not_called()


# ---------------------------------------------------------------------------
# 12. Private/internal domains skipped
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_private_domains_skipped():
    _reset_caches()
    for domain in ("localhost", "server.local", "api.internal"):
        crt_mock = AsyncMock(return_value=[])
        urlscan_mock = AsyncMock(return_value={})
        wayback_mock = AsyncMock(return_value={})

        with patch.object(dr, "query_crt_sh", crt_mock), \
             patch.object(dr, "query_urlscan", urlscan_mock), \
             patch.object(dr, "query_wayback", wayback_mock):
            rep = await check_domain_reputation(domain)

        assert rep["tags"] == [], f"Expected no tags for private domain {domain}"
        crt_mock.assert_not_called()
        urlscan_mock.assert_not_called()
        wayback_mock.assert_not_called()


# ---------------------------------------------------------------------------
# 13. All three sources fail gracefully — original entity unchanged
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_all_sources_fail_gracefully():
    _reset_caches()
    entity = _make_entity("DOMAIN", "example.com", confidence=0.85)
    results = [_make_result([entity])]

    with patch.object(dr, "query_crt_sh", AsyncMock(side_effect=Exception("network error"))), \
         patch.object(dr, "query_urlscan", AsyncMock(side_effect=Exception("timeout"))), \
         patch.object(dr, "query_wayback", AsyncMock(side_effect=Exception("503"))), \
         patch.object(dr, "_update_domain_entities_in_db", return_value=None):
        filtered, stats = await enrich_domain_entities(results, "test-inv-id")

    # Entity unchanged — no suppression, no crash
    assert filtered[0].entities[0].confidence == pytest.approx(0.85)
    assert "domain_reputation" in stats


# ---------------------------------------------------------------------------
# 14. New entities have correct confidence and source
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_new_entities_have_correct_metadata():
    _reset_caches()

    async def _fake_crt(domain):
        return [{"name": "api.example.com", "first_seen": "", "last_seen": "", "issuer": ""}]

    async def _fake_urlscan(domain):
        return {"malicious": False, "tags": [], "categories": [], "ips": [], "technologies": [], "screenshot_url": None}

    async def _fake_wayback(domain):
        return {"exists": False, "first_seen": None, "last_seen": None, "snapshot_url": None, "likely_taken_down": False}

    with patch.object(dr, "query_crt_sh", _fake_crt), \
         patch.object(dr, "query_urlscan", _fake_urlscan), \
         patch.object(dr, "query_wayback", _fake_wayback):
        rep = await check_domain_reputation("example.com", base_confidence=0.9)

    domain_entities = [e for e in rep["new_entities"] if e["entity_type"] == "DOMAIN"]
    assert len(domain_entities) == 1
    assert domain_entities[0]["value"] == "api.example.com"
    assert domain_entities[0]["confidence"] == pytest.approx(0.70)
    assert domain_entities[0]["source"] == "crt_sh"
    assert domain_entities[0]["extraction_method"] == "domain_enrichment"


# ---------------------------------------------------------------------------
# 15. Cache TTL respected for crt.sh results
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_crt_sh_cache_ttl_respected():
    _reset_caches()

    # Prime the cache with a fresh entry
    cached_subdomains = [{"name": "cached.example.com", "first_seen": "", "last_seen": "", "issuer": ""}]
    _crt_cache["example.com"] = {
        "subdomains": cached_subdomains,
        "loaded_at": time.time(),  # just loaded — within TTL
    }

    fetch_called = []

    with patch("aiohttp.ClientSession") as cls:
        # If cache is used, ClientSession should never be instantiated
        cls.side_effect = lambda *a, **kw: fetch_called.append(1)
        result = await query_crt_sh("example.com")

    assert result == cached_subdomains
    assert fetch_called == [], "HTTP fetch should not happen when cache is fresh"


# ---------------------------------------------------------------------------
# 16. URLSCAN_SUBMIT=false prevents scan submission
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_urlscan_submit_false_prevents_submission():
    _reset_caches()
    post_called = []

    async def _fake_post(*args, **kwargs):
        post_called.append(True)
        resp = AsyncMock()
        resp.status = 200
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)
        return resp

    mock_session = AsyncMock()
    mock_session.post = _fake_post
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("aiohttp.ClientSession", return_value=mock_session), \
         patch.dict(os.environ, {"URLSCAN_SUBMIT": "false", "URLSCAN_API_KEY": "test-key"}):
        await dr._submit_urlscan("example.com", "test-key")

    assert post_called == [], "POST should not be called when URLSCAN_SUBMIT=false"


# ---------------------------------------------------------------------------
# 17. sources_used updated correctly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sources_used_updated_correctly():
    _reset_caches()
    entity = _make_entity("DOMAIN", "example.com", confidence=0.9)
    results = [_make_result([entity])]

    async def _fake_rep(domain, base_confidence=1.0):
        return {
            "domain": domain,
            "crt_subdomains": [{"name": "sub.example.com"}],
            "urlscan_malicious": True,
            "urlscan_tags": [],
            "urlscan_ips": [],
            "wayback_exists": True,
            "wayback_first_seen": "2020-01-01",
            "wayback_last_seen": "2023-01-01",
            "likely_taken_down": False,
            "new_entities": [],
            "tags": ["has_ct_history", "urlscan_malicious", "wayback_archived"],
            "confidence_delta": 0.10,
        }

    with patch.object(dr, "check_domain_reputation", _fake_rep), \
         patch.object(dr, "_update_domain_entities_in_db", return_value=None):
        _, stats = await enrich_domain_entities(results, "test-inv-id")

    assert "domain_reputation" in stats
    assert stats["domains_checked"] == 1
    assert stats["ct_records"] == 1
    assert stats["urlscan_malicious"] == 1
    assert stats["wayback_archived"] == 1
    status = stats["domain_reputation"]
    assert status.startswith("ok_1_domains")


# ---------------------------------------------------------------------------
# 18. Max domain limit (30) enforced
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_max_domain_limit_enforced():
    _reset_caches()
    # 35 distinct domains
    entities = [_make_entity("DOMAIN", f"sub{i}.example.com") for i in range(35)]
    results = [_make_result(entities)]

    checked_domains: list[str] = []

    async def _tracking_rep(domain, base_confidence=1.0):
        checked_domains.append(domain)
        return {
            "domain": domain,
            "crt_subdomains": [],
            "urlscan_malicious": False,
            "urlscan_tags": [],
            "urlscan_ips": [],
            "wayback_exists": False,
            "wayback_first_seen": None,
            "wayback_last_seen": None,
            "likely_taken_down": False,
            "new_entities": [],
            "tags": [],
            "confidence_delta": 0.0,
        }

    with patch.object(dr, "check_domain_reputation", _tracking_rep), \
         patch.object(dr, "_update_domain_entities_in_db", return_value=None):
        _, stats = await enrich_domain_entities(results, "test-inv-id")

    assert len(checked_domains) <= 30
    assert stats["domains_checked"] <= 30
