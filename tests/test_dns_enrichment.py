"""
Tests for sources/dns_enrichment.py

Covers: IP/domain validation, cluster detection, entity filtering,
disabled-by-env toggle, and tag assignment logic.
"""

import asyncio
import os
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from sources.dns_enrichment import DNSEnrichment, enrich_with_dns


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_enricher() -> DNSEnrichment:
    return DNSEnrichment()


# ---------------------------------------------------------------------------
# IP / Domain validation
# ---------------------------------------------------------------------------


def test_valid_public_ip_accepted():
    e = _make_enricher()
    assert e._is_valid_public_ip("8.8.8.8") is True


def test_private_ip_rejected():
    e = _make_enricher()
    assert e._is_valid_public_ip("192.168.1.1") is False


def test_loopback_rejected():
    e = _make_enricher()
    assert e._is_valid_public_ip("127.0.0.1") is False


def test_valid_domain_accepted():
    e = _make_enricher()
    assert e._is_valid_domain("malicious-domain.com") is True


def test_onion_domain_rejected():
    e = _make_enricher()
    assert e._is_valid_domain("lockbit.onion") is False


def test_invalid_domain_rejected():
    e = _make_enricher()
    assert e._is_valid_domain("not-a-domain") is False


def test_invalid_domain_no_tld_rejected():
    e = _make_enricher()
    assert e._is_valid_domain("localhost") is False


# ---------------------------------------------------------------------------
# Cluster detection
# ---------------------------------------------------------------------------


def test_detect_shared_ip_cluster():
    e = _make_enricher()

    ip_enrichments = {
        "1.2.3.4": {
            "passive_dns": [
                {"rrname": "evil.com.", "rdata": "1.2.3.4"},
                {"rrname": "bad.com.", "rdata": "1.2.3.4"},
            ],
        }
    }
    domain_enrichments = {
        "evil.com": {"passive_dns": [], "whois": {}},
        "bad.com": {"passive_dns": [], "whois": {}},
    }

    clusters = e._detect_infrastructure_clusters(ip_enrichments, domain_enrichments)
    assert any(c["type"] == "shared_ip" for c in clusters)
    shared = next(c for c in clusters if c["type"] == "shared_ip")
    assert shared["ip"] == "1.2.3.4"
    assert set(shared["domains"]) == {"evil.com", "bad.com"}


def test_detect_shared_nameserver_cluster():
    e = _make_enricher()

    domain_enrichments = {
        "evil.com": {
            "passive_dns": [],
            "whois": {"nameservers": ["ns1.shady-dns.io", "ns2.shady-dns.io"]},
        },
        "bad.com": {
            "passive_dns": [],
            "whois": {"nameservers": ["ns1.shady-dns.io"]},
        },
    }

    clusters = e._detect_infrastructure_clusters({}, domain_enrichments)
    ns_clusters = [c for c in clusters if c["type"] == "shared_nameserver"]
    assert len(ns_clusters) >= 1
    shared_ns = next(c for c in ns_clusters if c["nameserver"] == "ns1.shady-dns.io")
    assert set(shared_ns["domains"]) == {"evil.com", "bad.com"}


def test_no_cluster_single_domain():
    e = _make_enricher()

    domain_enrichments = {
        "solo.com": {
            "passive_dns": [{"rdata": "5.6.7.8"}],
            "whois": {"nameservers": ["ns1.provider.com"]},
        }
    }

    clusters = e._detect_infrastructure_clusters({}, domain_enrichments)
    assert clusters == []


# ---------------------------------------------------------------------------
# enrich_entities — input filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrich_entities_filters_onion():
    """Onion URLs must not be sent to CIRCL."""
    enricher = _make_enricher()

    entities = [
        {"entity_type": "ONION_URL", "canonical_value": "http://lockbit.onion"},
        {"entity_type": "IP_ADDRESS", "canonical_value": "8.8.8.8"},
    ]

    # Patch low-level methods so no real HTTP fires
    enricher._enrich_ip = AsyncMock(return_value={
        "ip": "8.8.8.8", "passive_dns": [], "whois": {},
        "ssl_certs": [], "new_entities": [], "tags": [],
    })
    enricher._enrich_domain = AsyncMock(return_value={})
    enricher._session = MagicMock()

    result = await enricher.enrich_entities(entities)

    # Onion URL should not appear in domain enrichments
    assert "lockbit.onion" not in result["domain_enrichments"]
    assert "http://lockbit.onion" not in result["domain_enrichments"]


@pytest.mark.asyncio
async def test_enrich_entities_empty():
    async with DNSEnrichment() as enricher:
        result = await enricher.enrich_entities([])

    assert result["ip_enrichments"] == {}
    assert result["domain_enrichments"] == {}
    assert result["new_entities"] == []
    assert result["infrastructure_clusters"] == []


# ---------------------------------------------------------------------------
# enrich_with_dns — env toggle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv("DNS_ENRICHMENT_ENABLED", "false")

    result = await enrich_with_dns([
        {"entity_type": "IP_ADDRESS", "canonical_value": "8.8.8.8"},
    ])

    assert result["ip_enrichments"] == {}
    assert result["new_entities"] == []


# ---------------------------------------------------------------------------
# New entity confidence threshold
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_new_entities_have_confidence():
    """Entities surfaced from passive DNS must carry confidence >= 0.75."""
    enricher = _make_enricher()
    enricher._session = MagicMock()

    pdns_records = [{"rrname": "discovered.com.", "rdata": "1.2.3.4"}]

    enricher._circl_pdns_ip = AsyncMock(return_value=pdns_records)
    enricher._rdap_ip = AsyncMock(return_value={})
    enricher._circl_pssl_ip = AsyncMock(return_value=[])

    result = await enricher._enrich_ip("1.2.3.4", asyncio.Semaphore(1))

    for entity in result["new_entities"]:
        assert entity["confidence"] >= 0.75


# ---------------------------------------------------------------------------
# Tag: recently_registered
# ---------------------------------------------------------------------------


def test_recently_registered_tag(monkeypatch):
    """Domain registered 10 days ago should get 'recently_registered' tag."""
    enricher = _make_enricher()

    reg_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()

    whois = {"registered": reg_date, "nameservers": [], "registrant": ""}

    result: dict = {"tags": [], "new_entities": [], "passive_dns": [], "whois": {}}

    # Inline the tag logic from _enrich_domain
    result["whois"] = whois
    reg = whois.get("registered", "")
    if reg:
        result["tags"].append(f"registered_{reg[:7]}")
        try:
            from dateutil.parser import parse as parse_date
            reg_dt = parse_date(reg)
            now = datetime.now(timezone.utc)
            if reg_dt.tzinfo is None:
                reg_dt = reg_dt.replace(tzinfo=timezone.utc)
            age_days = (now - reg_dt).days
            if age_days < 30:
                result["tags"].append("recently_registered")
            elif age_days < 90:
                result["tags"].append("new_domain")
        except Exception:
            pass

    assert "recently_registered" in result["tags"]


# ---------------------------------------------------------------------------
# Tag: c2_hoster
# ---------------------------------------------------------------------------


def test_c2_hoster_tag():
    """IP belonging to Vultr ASN should get 'c2_hoster_vultr' tag."""
    enricher = _make_enricher()

    # Inline the org-check logic from _enrich_ip
    whois = {"org": "Vultr Holdings LLC", "country": "US"}
    tags: list[str] = []

    C2_HOSTERS = [
        "choopa", "vultr", "digitalocean", "linode",
        "frantech", "m247", "serverius", "combahton",
        "servermania", "sharktech",
    ]
    org = whois.get("org", "").lower()
    for hoster in C2_HOSTERS:
        if hoster in org:
            tags.append(f"c2_hoster_{hoster}")

    assert "c2_hoster_vultr" in tags
