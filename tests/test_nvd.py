"""Tests for sources/nvd.py (NVD 2.0 CVE enrichment)."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from sources import nvd
from tests.conftest import make_results, FakeEntity

_NVD_RE = re.compile(r"https://services\.nvd\.nist\.gov/rest/json/cves/2\.0.*")
_CPE_RE = re.compile(r"https://services\.nvd\.nist\.gov/rest/json/cpes/2\.0.*")


def _cve_payload(cve_id="CVE-2021-44228", with_v31=True):
    metrics = {}
    if with_v31:
        metrics["cvssMetricV31"] = [{
            "cvssData": {
                "baseScore": 10.0, "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            },
        }]
    else:
        metrics["cvssMetricV2"] = [{
            "baseSeverity": "HIGH",
            "cvssData": {"baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
        }]
    return {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2026-06-17T04:12:05.460",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "es", "value": "descripcion"},
                    {"lang": "en", "value": "Apache Log4j2 JNDI RCE."},
                ],
                "metrics": metrics,
                "weaknesses": [
                    {"description": [{"value": "CWE-20"}]},
                    {"description": [{"value": "CWE-917"}]},
                ],
            },
        }],
    }


async def test_fetch_nvd_cve_v31():
    with aioresponses() as m:
        m.get(_NVD_RE, status=200, payload=_cve_payload())
        res = await nvd.fetch_nvd_cve("CVE-2021-44228")
    assert res is not None
    assert res["source"] == "nvd"
    assert res["entity_value"] == "CVE-2021-44228"
    assert res["base_score"] == 10.0
    assert res["base_severity"] == "CRITICAL"
    assert res["cwes"] == ["CWE-20", "CWE-917"]
    assert res["description"] == "Apache Log4j2 JNDI RCE."
    assert res["vuln_status"] == "Analyzed"


async def test_fetch_nvd_cve_v2_fallback():
    with aioresponses() as m:
        m.get(_NVD_RE, status=200, payload=_cve_payload(with_v31=False))
        res = await nvd.fetch_nvd_cve("CVE-2021-44228")
    assert res["base_score"] == 7.5
    assert res["base_severity"] == "HIGH"


async def test_fetch_nvd_cve_not_found():
    with aioresponses() as m:
        m.get(_NVD_RE, status=200, payload={"totalResults": 0, "vulnerabilities": []})
        res = await nvd.fetch_nvd_cve("CVE-1999-0001")
    assert res is None


async def test_fetch_nvd_invalid_id_no_request():
    # Malformed ids are rejected before any HTTP call (aioresponses would raise
    # on an unexpected request, so a clean None proves no request was made).
    with aioresponses():
        res = await nvd.fetch_nvd_cve("not-a-cve")
    assert res is None


async def test_fetch_nvd_cve_is_cached():
    """Second lookup for the same CVE is served from cache (no second HTTP call)."""
    with aioresponses() as m:
        m.get(_NVD_RE, status=200, payload=_cve_payload())  # registered once
        first = await nvd.fetch_nvd_cve("CVE-2021-44228")
        second = await nvd.fetch_nvd_cve("CVE-2021-44228")  # must hit cache
    assert first == second
    assert second["base_score"] == 10.0


async def test_enrich_nvd_from_entities():
    with aioresponses() as m:
        m.get(_NVD_RE, status=200, payload=_cve_payload())
        entities = [{"entity_type": "CVE_NUMBER", "value": "CVE-2021-44228"}]
        results = await nvd.enrich_nvd(entities)
    assert len(results) == 1
    assert results[0]["source"] == "nvd"


async def test_enrich_nvd_no_cves():
    results = await nvd.enrich_nvd([{"entity_type": "IP_ADDRESS", "value": "1.2.3.4"}])
    assert results == []


def _cpe_payload(title="Zimbra Collaboration Suite", product="zimbra_collaboration_suite"):
    return {
        "totalResults": 1,
        "products": [{
            "cpe": {
                "titles": [{"lang": "en", "title": title}],
                "cpeName": [{
                    "cpeName": f"cpe:2.3:a:vendor:{product}:1.0:*:*:*:*:*:*:*",
                }],
            },
        }],
    }


async def test_fetch_nvd_cpe_exact_product_match():
    with aioresponses() as m:
        m.get(_CPE_RE, status=200, payload=_cpe_payload())
        result = await nvd.fetch_nvd_cpe("Zimbra Collaboration Suite")
    assert result["source"] == "nvd_cpe"
    assert result["matched"] is True


async def test_fetch_nvd_cpe_nonmatching_catalog_result_is_not_suppression():
    with aioresponses() as m:
        m.get(_CPE_RE, status=200, payload=_cpe_payload("Unrelated Product", "unrelated_product"))
        result = await nvd.fetch_nvd_cpe("Zimbra Collaboration Suite")
    assert result["matched"] is False
