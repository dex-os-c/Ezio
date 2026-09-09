"""Tests for the IOC package export (export/ioc_package.py).

Basic real-entity / real-output coverage matching the standard set by the other
export-format tests: build a concrete entity set, generate the real ZIP
artifact, and assert on its members and metadata. Also pins the fix that
``sources_used`` supplied on the investigation dict actually reaches
``metadata.json`` (the API IOC-export path backfills it from investigation
metadata, mirroring the CLI export).
"""

from __future__ import annotations

import io
import json
import zipfile

from export.ioc_package import generate_ioc_package


def _entities():
    return [
        {"entity_type": "FILE_HASH_SHA256", "value": "a" * 64, "confidence": 0.95,
         "source_url": "http://leak.onion/dump"},
        {"entity_type": "IP_ADDRESS", "value": "185.220.101.1", "confidence": 0.9,
         "source_url": "http://leak.onion/c2"},
        {"entity_type": "DOMAIN", "value": "evil-example.com", "confidence": 0.85,
         "source_url": "http://leak.onion/c2"},
        {"entity_type": "ONION_URL", "value": "abcdefghij234567.onion", "confidence": 0.8,
         "source_url": "http://index.onion"},
        {"entity_type": "EMAIL_ADDRESS", "value": "actor@proton.me", "confidence": 0.7,
         "source_url": "http://forum.onion/thread"},
        {"entity_type": "CVE_NUMBER", "value": "CVE-2024-3094", "confidence": 0.9,
         "source_url": "http://forum.onion/exploit"},
        {"entity_type": "MALWARE_FAMILY", "value": "LockBit", "confidence": 0.9,
         "source_url": "http://leak.onion/lockbit"},
    ]


def _investigation():
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "query": "lockbit leak",
        "summary": "Test investigation summary.",
        "created_at": "2026-08-02T00:00:00+00:00",
        "sources_used": {
            "otx": "ok_3_enrichments",
            "malwarebazaar": "ok_1_enrichments",
            "greynoise": "skipped_no_key",
        },
    }


async def test_generate_ioc_package_contains_expected_members():
    """The ZIP carries the core IOC / threat-intel / detection / report files."""
    zip_bytes = await generate_ioc_package(
        investigation_id="11111111-1111-1111-1111-111111111111",
        entities=_entities(),
        investigation=_investigation(),
        session=None,
        tlp="amber",
        redact_credentials=True,
        include_raw=False,
    )
    assert isinstance(zip_bytes, bytes) and zip_bytes[:2] == b"PK"

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        names = set(zf.namelist())

    for expected in {
        "README.md",
        "metadata.json",
        "iocs/hashes.txt",
        "iocs/ip_addresses.txt",
        "iocs/domains.txt",
        "iocs/onion_urls.txt",
        "iocs/email_addresses.txt",
        "iocs/cve_identifiers.txt",
        "threat_intel/stix.json",
        "threat_intel/misp.json",
        "detections/sigma.yml",
        "reports/entities.csv",
    }:
        assert expected in names, f"missing {expected}; got {sorted(names)}"


async def test_metadata_json_reflects_entities_and_sources_used():
    """metadata.json round-trips sources_used and counts real entity types."""
    zip_bytes = await generate_ioc_package(
        investigation_id="11111111-1111-1111-1111-111111111111",
        entities=_entities(),
        investigation=_investigation(),
        session=None,
        tlp="amber",
        redact_credentials=True,
        include_raw=False,
    )
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        meta = json.loads(zf.read("metadata.json").decode("utf-8"))

    # sources_used must survive from the investigation dict into the package
    # metadata — this is exactly what the API export path backfills.
    assert meta["sources_used"] == _investigation()["sources_used"]
    assert meta["tlp"] == "TLP:AMBER"
    assert meta["query"] == "lockbit leak"
    counts = meta["entity_counts"]
    assert counts.get("IP_ADDRESS") == 1
    assert counts.get("FILE_HASH_SHA256") == 1


async def test_ioc_files_contain_the_real_indicator_values():
    """The plain-text IOC files carry the actual indicator strings."""
    zip_bytes = await generate_ioc_package(
        investigation_id="11111111-1111-1111-1111-111111111111",
        entities=_entities(),
        investigation=_investigation(),
        session=None,
        tlp="white",
        redact_credentials=True,
        include_raw=False,
    )
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        hashes = zf.read("iocs/hashes.txt").decode("utf-8")
        cves = zf.read("iocs/cve_identifiers.txt").decode("utf-8")
        onions = zf.read("iocs/onion_urls.txt").decode("utf-8")

    assert "a" * 64 in hashes
    assert "CVE-2024-3094" in cves
    assert "abcdefghij234567.onion" in onions
