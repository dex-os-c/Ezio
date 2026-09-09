"""Tests for sources/infostealer.py (Hudson Rock Cavalier)."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from sources import infostealer as ist
from tests.conftest import make_results, FakeEntity

_EMAIL_RE = re.compile(r"https://cavalier\.hudsonrock\.com/api/json/v2/osint-tools/search-by-email.*")
_DOMAIN_RE = re.compile(r"https://cavalier\.hudsonrock\.com/api/json/v2/osint-tools/search-by-domain.*")


async def test_hudsonrock_email_infected():
    with aioresponses() as m:
        m.get(_EMAIL_RE, status=200, payload={
            "message": "This email address is associated with a computer infected by an info-stealer.",
            "stealers": [
                {"date_compromised": "2026-07-20T19:03:02.166Z", "total_corporate_services": 52},
                {"date_compromised": "2026-07-19T07:50:31.660Z", "total_corporate_services": 8},
            ],
        })
        res = await ist.query_hudsonrock_email("fatih@corp.example")
    assert res["found"] is True
    assert res["source"] == "hudsonrock"
    assert res["machine_count"] == 2
    assert res["most_recent_compromise"].startswith("2026-07-20")
    assert res["corporate_services_exposed"] == 60


async def test_hudsonrock_email_clean():
    with aioresponses() as m:
        m.get(_EMAIL_RE, status=200, payload={
            "message": "This email address is not associated with known infections.",
            "stealers": [],
        })
        res = await ist.query_hudsonrock_email("clean@corp.example")
    assert res["found"] is False
    assert res["source"] == "hudsonrock_not_found"


async def test_hudsonrock_domain_exposed():
    with aioresponses() as m:
        m.get(_DOMAIN_RE, status=200, payload={
            "total": 605948, "totalStealers": 35924019,
            "employees": 2880, "users": 601482, "third_parties": 1586,
        })
        res = await ist.query_hudsonrock_domain("corp.example")
    assert res["found"] is True
    assert res["employees"] == 2880
    assert res["users"] == 601482
    assert res["total"] == 605948


async def test_hudsonrock_domain_empty_body_is_not_found():
    with aioresponses() as m:
        m.get(_DOMAIN_RE, status=200, body="")
        res = await ist.query_hudsonrock_domain("nodata.example")
    assert res["found"] is False
    assert res["source"] == "hudsonrock_not_found"


async def test_enrich_infostealer_entities_email_and_domain():
    with aioresponses() as m:
        m.get(_EMAIL_RE, status=200, payload={
            "message": "infected", "stealers": [{"date_compromised": "2026-01-01T00:00:00Z"}],
        })
        m.get(_DOMAIN_RE, status=200, payload={
            "total": 10, "employees": 3, "users": 7, "third_parties": 0,
        })
        results = make_results(
            FakeEntity("EMAIL_ADDRESS", "victim@corp.example"),
            FakeEntity("DOMAIN", "corp.example"),
        )
        _, stats = await ist.enrich_infostealer_entities(results, "inv-1")

    assert stats["hudsonrock"] == "ok_2_results"
    assert stats["emails_infected"] == 1
    assert stats["domains_exposed"] == 1
    assert stats["total_machines"] == 1


async def test_enrich_infostealer_skips_freemail_domains():
    """Freemail domains are meaningless for domain-level infostealer lookup."""
    with aioresponses() as m:
        # Only the email endpoint should be hit; gmail.com must be skipped.
        m.get(_EMAIL_RE, status=200, payload={"message": "clean", "stealers": []})
        results = make_results(
            FakeEntity("EMAIL_ADDRESS", "someone@gmail.com"),
            FakeEntity("DOMAIN", "gmail.com"),
        )
        _, stats = await ist.enrich_infostealer_entities(results, "inv-1")
    assert stats["domains_checked"] == 0
    assert stats["emails_checked"] == 1


async def test_enrich_infostealer_no_entities():
    results = make_results(FakeEntity("IP_ADDRESS", "1.2.3.4"))
    _, stats = await ist.enrich_infostealer_entities(results, "inv-1")
    assert stats["hudsonrock"] == "ok_0_results"
