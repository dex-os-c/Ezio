"""
Tests for sources/hash_reputation.py

Covers: source response parsing, verdict tagging, confidence boosting, new entity
creation, caps, cache TTL, deduplication, malware family entity, AV badge data,
graceful degradation, MAX_HASHES limit, and sources_used tracking.
"""

from __future__ import annotations

import asyncio
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import sources.hash_reputation as hr
from sources.hash_reputation import (
    _hash_cache,
    _is_valid_hash,
    _normalize_family,
    check_hash_reputation,
    enrich_hash_entities,
    query_hybrid_analysis,
    query_malwarebazaar,
    query_threatfox,
    query_virustotal_hash,
    HASH_TYPES,
    MAX_HASHES,
)

# ---------------------------------------------------------------------------
# Constants used across tests
# ---------------------------------------------------------------------------

SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
SHA1   = "3395856ce81f2b7382dee72602f798b642f14d0"
MD5    = "d41d8cd98f00b204e9800998ecf8427e"

HA_MALICIOUS_RESPONSE = [
    {
        "job_id": "abc123",
        "sha256": SHA256,
        "verdict": "malicious",
        "vx_family": "Emotet",
        "threat_score": 95,
        "total_av_detections": 45,
        "av_detect": 72,
        "type_short": "peexe",
        "tags": ["banker", "trojan"],
        "network": {
            "hosts": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}],
            "domains": ["evil.com", "badactor.net"],
            "http": [],
        },
    }
]

MB_FOUND_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": SHA256,
            "signature": "Emotet",
            "file_type": "exe",
            "first_seen": "2024-01-15 10:00:00",
            "tags": ["spam", "loader"],
        }
    ],
}

TF_FOUND_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "ioc": SHA256,
            "ioc_type": "sha256_hash",
            "malware": "emotet",
            "malware_printable": "Emotet",
            "confidence_level": 90,
            "first_seen": "2024-01-10 08:00:00",
            "tags": ["botnet"],
        }
    ],
}

VT_FOUND_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 50, "undetected": 20, "harmless": 2},
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.emotet/generic"
            },
            "type_description": "Win32 EXE",
            "first_submission_date": 1700000000,
            "last_analysis_date": 1700500000,
            "last_analysis_results": {},
        }
    }
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_cache():
    _hash_cache.clear()


def _make_entity(entity_type: str, value: str, confidence: float = 0.85):
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


def _mock_ha_session(response_json):
    """Return an aiohttp.ClientSession mock that yields response_json for POST."""
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=response_json)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    return mock_session


def _mock_get_session(response_json, status=200):
    """Return an aiohttp.ClientSession mock that yields response_json for GET."""
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=response_json)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    return mock_session


# ---------------------------------------------------------------------------
# 1. Hybrid Analysis response parsing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hybrid_analysis_parses_verdict_family_score():
    _reset_cache()
    with (
        patch.dict(os.environ, {"HYBRID_ANALYSIS_API_KEY": "test-key"}),
        patch("aiohttp.ClientSession", return_value=_mock_ha_session(HA_MALICIOUS_RESPONSE)),
    ):
        result = await query_hybrid_analysis(SHA256)

    assert result["found"] is True
    assert result["verdict"] == "malicious"
    assert result["malware_family"] == "Emotet"
    assert result["threat_score"] == 95
    assert result["av_detections"] == 45
    assert result["av_total"] == 72


# ---------------------------------------------------------------------------
# 2. Malicious verdict boosts confidence +0.15
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_malicious_verdict_boosts_confidence():
    _reset_cache()

    async def _fake_ha(_):
        return {
            "found": True,
            "verdict": "malicious",
            "malware_family": "Emotet",
            "threat_score": 90,
            "av_detections": 40,
            "av_total": 70,
            "file_type": "exe",
            "tags": [],
            "contacted_ips": [],
            "contacted_domains": [],
        }

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", side_effect=_fake_ha),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={"found": False}),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256, "FILE_HASH_SHA256", base_confidence=0.80)

    assert result["confidence_delta"] == pytest.approx(0.15)
    assert "hybrid_analysis_malicious" in result["tags"]


# ---------------------------------------------------------------------------
# 3. Contacted IPs from sandbox added as new IP_ADDRESS entities
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_contacted_ips_added_as_new_entities():
    _reset_cache()

    async def _fake_ha(_):
        return {
            "found": True,
            "verdict": "malicious",
            "malware_family": "Loader",
            "threat_score": 80,
            "av_detections": 30,
            "av_total": 60,
            "file_type": "exe",
            "tags": [],
            "contacted_ips": ["1.2.3.4", "9.8.7.6"],
            "contacted_domains": [],
        }

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", side_effect=_fake_ha),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={"found": False}),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256, "FILE_HASH_SHA256")

    ip_entities = [e for e in result["new_entities"] if e["entity_type"] == "IP_ADDRESS"]
    assert len(ip_entities) == 2
    assert all(e["confidence"] == pytest.approx(0.82) for e in ip_entities)
    assert all(e["source"] == "hybrid_analysis" for e in ip_entities)


# ---------------------------------------------------------------------------
# 4. Contacted domains from sandbox added as new DOMAIN entities
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_contacted_domains_added_as_new_entities():
    _reset_cache()

    async def _fake_ha(_):
        return {
            "found": True,
            "verdict": "malicious",
            "malware_family": "Loader",
            "threat_score": 80,
            "av_detections": 30,
            "av_total": 60,
            "file_type": "exe",
            "tags": [],
            "contacted_ips": [],
            "contacted_domains": ["evil.com", "bad.net"],
        }

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", side_effect=_fake_ha),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={"found": False}),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256, "FILE_HASH_SHA256")

    domain_entities = [e for e in result["new_entities"] if e["entity_type"] == "DOMAIN"]
    assert len(domain_entities) == 2
    assert all(e["confidence"] == pytest.approx(0.80) for e in domain_entities)


# ---------------------------------------------------------------------------
# 5. IP cap of 10 enforced
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ip_cap_enforced():
    _reset_cache()

    many_ips = [f"10.0.0.{i}" for i in range(20)]

    async def _fake_ha(_):
        return {
            "found": True,
            "verdict": "malicious",
            "malware_family": "",
            "threat_score": 50,
            "av_detections": None,
            "av_total": None,
            "file_type": "",
            "tags": [],
            "contacted_ips": many_ips,
            "contacted_domains": [],
        }

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", side_effect=_fake_ha),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={"found": False}),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256, "FILE_HASH_SHA256")

    ip_entities = [e for e in result["new_entities"] if e["entity_type"] == "IP_ADDRESS"]
    assert len(ip_entities) <= 10


# ---------------------------------------------------------------------------
# 6. Domain cap of 10 enforced
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_domain_cap_enforced():
    _reset_cache()

    many_domains = [f"evil{i}.com" for i in range(20)]

    async def _fake_ha(_):
        return {
            "found": True,
            "verdict": "suspicious",
            "malware_family": "",
            "threat_score": 30,
            "av_detections": None,
            "av_total": None,
            "file_type": "",
            "tags": [],
            "contacted_ips": [],
            "contacted_domains": many_domains,
        }

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", side_effect=_fake_ha),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={"found": False}),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256, "FILE_HASH_SHA256")

    domain_entities = [e for e in result["new_entities"] if e["entity_type"] == "DOMAIN"]
    assert len(domain_entities) <= 10


# ---------------------------------------------------------------------------
# 7. MalwareBazaar hit boosts confidence +0.10
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_malwarebazaar_hit_boosts_confidence():
    _reset_cache()

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", return_value={"found": False}),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={
            "found": True,
            "source": "malwarebazaar",
            "malware_family": "QakBot",
            "file_type": "exe",
            "first_seen": "2024-02-01 00:00:00",
            "tags": [],
        }),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256, "FILE_HASH_SHA256", base_confidence=0.70)

    assert result["confidence_delta"] == pytest.approx(0.10)
    assert "malwarebazaar_confirmed" in result["tags"]


# ---------------------------------------------------------------------------
# 8. MalwareBazaar family name extracted correctly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_malwarebazaar_family_extracted():
    _reset_cache()

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", return_value={"found": False}),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={
            "found": True,
            "malware_family": "QakBot",
            "file_type": "exe",
            "first_seen": "",
            "tags": [],
        }),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256)

    assert "QakBot" in result["malware_families"]


# ---------------------------------------------------------------------------
# 9. ThreatFox hit adds threatfox_confirmed tag
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_threatfox_hit_adds_tag():
    _reset_cache()

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", return_value={"found": False}),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={"found": False}),
        patch("sources.hash_reputation.query_threatfox", return_value={
            "found": True,
            "malware_family": "Cobalt Strike",
            "confidence_level": 75,
            "first_seen": "2024-03-01 00:00:00",
            "tags": [],
            "associated_iocs": [],
        }),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256)

    assert "threatfox_confirmed" in result["tags"]


# ---------------------------------------------------------------------------
# 10. No Hybrid Analysis key — source skipped, MB and TF still run
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_hybrid_analysis_key_mb_tf_still_run():
    _reset_cache()

    mb_called = []
    tf_called = []

    async def _fake_mb(h):
        mb_called.append(h)
        return {"found": True, "malware_family": "Emotet", "file_type": "exe", "first_seen": "", "tags": []}

    async def _fake_tf(h):
        tf_called.append(h)
        return {"found": True, "malware_family": "Emotet", "confidence_level": 80, "first_seen": "", "tags": [], "associated_iocs": []}

    with (
        patch.dict(os.environ, {}, clear=False),
        patch("sources.hash_reputation.query_hybrid_analysis", return_value={"found": False, "source": "hybrid_analysis_skipped"}),
        patch("sources.hash_reputation.query_malwarebazaar", side_effect=_fake_mb),
        patch("sources.hash_reputation.query_threatfox", side_effect=_fake_tf),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256)

    assert len(mb_called) == 1
    assert len(tf_called) == 1
    assert result["confidence_delta"] == pytest.approx(0.20)


# ---------------------------------------------------------------------------
# 11. Hash not found in any source — entity unchanged, no error
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hash_not_found_no_error():
    _reset_cache()

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", return_value={"found": False}),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={"found": False}),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256)

    assert result["verdict"] is None
    assert result["confidence_delta"] == pytest.approx(0.0)
    assert result["tags"] == []
    assert result["new_entities"] == []
    assert result["suppress"] is False


# ---------------------------------------------------------------------------
# 12. 48h cache TTL respected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_ttl_respected():
    _reset_cache()

    call_count = [0]

    async def _fake_ha(_):
        call_count[0] += 1
        return {"found": False}

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", side_effect=_fake_ha),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={"found": False}),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        await check_hash_reputation(SHA256)
        await check_hash_reputation(SHA256)  # should hit cache

    assert call_count[0] == 1


@pytest.mark.asyncio
async def test_cache_ttl_expiry_refetches():
    _reset_cache()

    call_count = [0]

    async def _fake_ha(_):
        call_count[0] += 1
        return {"found": False}

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", side_effect=_fake_ha),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={"found": False}),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        await check_hash_reputation(SHA256)
        # Force-expire the cache entry
        _hash_cache[SHA256]["loaded_at"] = time.time() - (hr.HASH_CACHE_TTL + 1)
        await check_hash_reputation(SHA256)

    assert call_count[0] == 2


# ---------------------------------------------------------------------------
# 13. SHA256 processed before MD5 for same file
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sha256_processed_before_md5():
    _reset_cache()

    processed_order: list[str] = []

    async def _fake_check(hash_value, hash_type="FILE_HASH_SHA256", base_confidence=1.0):
        processed_order.append(hash_type)
        return {
            "hash": hash_value, "hash_type": hash_type, "verdict": None,
            "malware_families": [], "threat_score": None, "av_detections": None,
            "av_total": None, "file_type": None, "first_seen": None,
            "new_entities": [], "tags": [], "confidence_delta": 0.0, "suppress": False,
        }

    sha256_entity = _make_entity("FILE_HASH_SHA256", SHA256)
    md5_entity = _make_entity("FILE_HASH_MD5", MD5)
    extraction_results = [_make_result([md5_entity, sha256_entity])]

    with (
        patch("sources.hash_reputation.check_hash_reputation", side_effect=_fake_check),
        patch("sources.hash_reputation._update_hash_entities_in_db"),
    ):
        await enrich_hash_entities(extraction_results, "inv-id")

    sha256_idx = next((i for i, t in enumerate(processed_order) if t == "FILE_HASH_SHA256"), None)
    md5_idx = next((i for i, t in enumerate(processed_order) if t == "FILE_HASH_MD5"), None)
    assert sha256_idx is not None
    assert md5_idx is not None
    assert sha256_idx < md5_idx


# ---------------------------------------------------------------------------
# 14. Malware family entity created when confirmed by 2+ sources
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_malware_family_entity_created_two_sources():
    _reset_cache()

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", return_value={
            "found": True,
            "verdict": "malicious",
            "malware_family": "Emotet",
            "threat_score": 95,
            "av_detections": 45,
            "av_total": 72,
            "file_type": "exe",
            "tags": [],
            "contacted_ips": [],
            "contacted_domains": [],
        }),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={
            "found": True,
            "malware_family": "Emotet",
            "file_type": "exe",
            "first_seen": "2024-01-01",
            "tags": [],
        }),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256)

    mf_entities = [e for e in result["new_entities"] if e["entity_type"] == "MALWARE_FAMILY"]
    assert len(mf_entities) == 1
    assert "Emotet" in mf_entities[0]["canonical_value"]
    assert mf_entities[0]["confidence"] == pytest.approx(0.90)


# ---------------------------------------------------------------------------
# 15. AV detection badge data included in result
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_av_detection_badge_tag_included():
    _reset_cache()

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", return_value={
            "found": True,
            "verdict": "malicious",
            "malware_family": "",
            "threat_score": 80,
            "av_detections": 45,
            "av_total": 72,
            "file_type": "exe",
            "tags": [],
            "contacted_ips": [],
            "contacted_domains": [],
        }),
        patch("sources.hash_reputation.query_malwarebazaar", return_value={"found": False}),
        patch("sources.hash_reputation.query_threatfox", return_value={"found": False}),
        patch("sources.hash_reputation.query_virustotal_hash", return_value={"found": False}),
    ):
        result = await check_hash_reputation(SHA256)

    av_tags = [t for t in result["tags"] if t.startswith("av_detections_")]
    assert len(av_tags) == 1
    assert av_tags[0] == "av_detections_45_of_72"


# ---------------------------------------------------------------------------
# 16. All sources fail gracefully — original entity unchanged, no error
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_all_sources_fail_gracefully():
    _reset_cache()

    async def _raise(_):
        raise RuntimeError("network error")

    with (
        patch("sources.hash_reputation.query_hybrid_analysis", side_effect=_raise),
        patch("sources.hash_reputation.query_malwarebazaar", side_effect=_raise),
        patch("sources.hash_reputation.query_threatfox", side_effect=_raise),
        patch("sources.hash_reputation.query_virustotal_hash", side_effect=_raise),
    ):
        result = await check_hash_reputation(SHA256)

    assert result["suppress"] is False
    assert result["confidence_delta"] == pytest.approx(0.0)
    assert result["verdict"] is None


# ---------------------------------------------------------------------------
# 17. MAX_HASHES = 50 limit enforced
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_max_hashes_limit_enforced():
    _reset_cache()

    # Generate 60 unique fake SHA256 hashes
    hashes = [f"{'a' * 63}{i:x}" if i < 16 else f"{'b' * 62}{i:02x}" for i in range(60)]
    hashes = [h[:64] for h in [f"{i:064x}" for i in range(60)]]

    entities = [_make_entity("FILE_HASH_SHA256", h) for h in hashes]
    extraction_results = [_make_result(entities)]

    checked: list[str] = []

    async def _fake_check(hash_value, hash_type="FILE_HASH_SHA256", base_confidence=1.0):
        checked.append(hash_value)
        return {
            "hash": hash_value, "hash_type": hash_type, "verdict": None,
            "malware_families": [], "threat_score": None, "av_detections": None,
            "av_total": None, "file_type": None, "first_seen": None,
            "new_entities": [], "tags": [], "confidence_delta": 0.0, "suppress": False,
        }

    with (
        patch("sources.hash_reputation.check_hash_reputation", side_effect=_fake_check),
        patch("sources.hash_reputation._update_hash_entities_in_db"),
    ):
        _, stats = await enrich_hash_entities(extraction_results, "inv-id")

    assert stats["hashes_checked"] == MAX_HASHES
    assert len(checked) == MAX_HASHES


# ---------------------------------------------------------------------------
# 18. sources_used updated correctly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sources_used_updated_correctly():
    _reset_cache()

    sha_entity = _make_entity("FILE_HASH_SHA256", SHA256)
    extraction_results = [_make_result([sha_entity])]

    async def _fake_check(hash_value, hash_type="FILE_HASH_SHA256", base_confidence=1.0):
        return {
            "hash": hash_value, "hash_type": hash_type, "verdict": "malicious",
            "malware_families": ["Emotet"], "threat_score": 90, "av_detections": 40,
            "av_total": 70, "file_type": "exe", "first_seen": None,
            "new_entities": [], "tags": ["hybrid_analysis_malicious", "malwarebazaar_confirmed"],
            "confidence_delta": 0.25, "suppress": False,
        }

    with (
        patch("sources.hash_reputation.check_hash_reputation", side_effect=_fake_check),
        patch("sources.hash_reputation._update_hash_entities_in_db"),
    ):
        _, stats = await enrich_hash_entities(extraction_results, "inv-id")

    assert "hash_reputation" in stats
    assert stats["hash_reputation"].startswith("ok_1_hashes")
    assert stats["malicious"] == 1
    assert stats["hashes_checked"] == 1
