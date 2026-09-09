"""Tests for sources/breach_lookup.py (XposedOrNot + LeakCheck)."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from sources import breach_lookup as bl
from tests.conftest import make_results, FakeEntity

_XON_RE = re.compile(r"https://api\.xposedornot\.com/v1/check-email/.*")
_LEAK_RE = re.compile(r"https://leakcheck\.io/api/public.*")


async def test_xposedornot_found_with_stealer_log():
    with aioresponses() as m:
        m.get(_XON_RE, status=200, payload={
            "breaches": [["Canva", "Adobe", "AlienStealerLogs"]],
            "email": "x@y.com",
            "status": "success",
        })
        res = await bl.query_xposedornot("x@y.com")
    assert res["found"] is True
    assert res["source"] == "xposedornot"
    assert res["breach_count"] == 3
    assert res["stealer_log_exposure"] is True
    assert "Adobe" in res["breach_names"]


async def test_xposedornot_not_found():
    with aioresponses() as m:
        m.get(_XON_RE, status=200, payload={"Error": "Not found", "email": None})
        res = await bl.query_xposedornot("nobody@nowhere.tld")
    assert res["found"] is False
    assert res["source"] == "xposedornot_not_found"
    assert res["breach_count"] == 0


async def test_xposedornot_rate_limited():
    with aioresponses() as m:
        m.get(_XON_RE, status=429)
        res = await bl.query_xposedornot("x@y.com")
    assert res["found"] is False
    assert res["source"] == "xposedornot_rate_limited"


async def test_leakcheck_found():
    with aioresponses() as m:
        m.get(_LEAK_RE, status=200, payload={
            "success": True,
            "found": 3,
            "fields": ["password", "username"],
            "sources": [
                {"name": "Canva.com", "date": "2019-05"},
                {"name": "Adobe", "date": "2013-10"},
            ],
        })
        res = await bl.query_leakcheck("x@y.com")
    assert res["found"] is True
    assert res["source"] == "leakcheck"
    assert res["breach_count"] == 3
    assert "Canva.com" in res["sources"]
    assert "password" in res["fields"]


async def test_leakcheck_no_success():
    with aioresponses() as m:
        m.get(_LEAK_RE, status=200, payload={"success": False, "error": "not found"})
        res = await bl.query_leakcheck("x@y.com")
    assert res["found"] is False
    assert res["source"] == "leakcheck_not_found"


async def test_enrich_breach_entities_corroborated():
    """An email found in BOTH corpora is tagged corroborated and both statuses are ok_1."""
    with aioresponses() as m:
        m.get(_XON_RE, status=200, payload={
            "breaches": [["Canva", "StealerLogs"]], "status": "success",
        })
        m.get(_LEAK_RE, status=200, payload={
            "success": True, "found": 2,
            "sources": [{"name": "Canva.com", "date": "2019-05"}], "fields": ["password"],
        })
        results = make_results(FakeEntity("EMAIL_ADDRESS", "victim@corp.example"))
        _, stats = await bl.enrich_breach_entities(results, "inv-1")

    assert stats["xposedornot"] == "ok_1_results"
    assert stats["leakcheck"] == "ok_1_results"
    assert stats["xon_breached"] == 1
    assert stats["leakcheck_breached"] == 1
    assert stats["stealer_log_exposed"] == 1
    assert stats["corroborated"] == 1


async def test_enrich_breach_entities_no_emails():
    results = make_results(FakeEntity("IP_ADDRESS", "1.2.3.4"))
    _, stats = await bl.enrich_breach_entities(results, "inv-1")
    assert stats["xposedornot"] == "ok_0_results"
    assert stats["leakcheck"] == "ok_0_results"
    assert stats["emails_checked"] == 0


async def test_check_breach_exposure_confidence_delta():
    with aioresponses() as m:
        m.get(_XON_RE, status=200, payload={"breaches": [["Canva"]], "status": "success"})
        m.get(_LEAK_RE, status=200, payload={"success": True, "found": 1, "sources": [{"name": "Canva.com"}]})
        rep = await bl.check_breach_exposure("a@b.com")
    # 0.12 (xon) + 0.08 (leakcheck) + 0.10 (corroborated) = 0.30
    assert rep["corroborated"] is True
    assert round(rep["confidence_delta"], 2) == 0.30
    assert "breach_corroborated" in rep["tags"]
