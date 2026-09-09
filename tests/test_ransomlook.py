"""Tests for ransomlook.io integration + the partial-results deadline helper
(both live in sources/enrichment.py)."""

from __future__ import annotations

import asyncio
import re

import pytest
from aioresponses import aioresponses

from sources import enrichment as enr

_GROUPS_RE = re.compile(r"https://www\.ransomlook\.io/api/groups$")
_GROUP_RE = re.compile(r"https://www\.ransomlook\.io/api/group/.+")
_RECENT_RE = re.compile(r"https://www\.ransomlook\.io/api/recent$")


def test_onion_normalization_matches_ransomwarelive_format():
    locs = [
        {"fqdn": "ABC.onion/", "available": False},
        {"fqdn": "http://xyz.onion", "available": True},
        {"fqdn": "not-an-onion.com", "available": True},
        {"fqdn": "xyz.onion", "available": True},  # duplicate of the http:// one
    ]
    urls = enr._ransomlook_onion_from_locations(locs)
    # available first, lowercased, scheme+slash stripped then http:// prefixed, deduped
    assert urls == ["http://xyz.onion", "http://abc.onion"]


def test_ransomlook_to_pages_shapes():
    groups = [{
        "group": "lockbit3",
        "description": "LockBit 3.0",
        "onion_urls": ["http://lockbitxxx.onion"],
        "references": ["https://example.com/ref"],
        "victims": [{"post_title": "VictimCo", "discovered": "2026-07-20"}],
    }]
    pages = enr.ransomlook_to_pages(groups)
    summary = [p for p in pages if not p.get("_scrape_seed")]
    seeds = [p for p in pages if p.get("_scrape_seed")]
    assert len(summary) == 1
    assert summary[0]["source"] == "ransomlook"
    assert summary[0]["via"] == "ransomlook_api"
    assert "VictimCo" in summary[0]["content"]
    assert len(seeds) == 1
    assert seeds[0]["source"] == "ransomlook"
    assert seeds[0]["url"] == "http://lockbitxxx.onion"
    assert seeds[0]["via"] == "ransomlook_onion_seed"


async def test_fetch_ransomlook_matches_and_parses():
    with aioresponses() as m:
        m.get(_GROUPS_RE, status=200, payload=["lockbit3", "conti", "blackcat"])
        m.get(_GROUP_RE, status=200, payload=[{
            "locations": [{"fqdn": "lockbitleak.onion", "available": True}],
            "profile": ["https://threatpost.com/lockbit"],
            "meta": "LockBit ransomware group",
        }])
        m.get(_RECENT_RE, status=200, payload=[
            {"group_name": "lockbit3", "post_title": "VictimCo", "discovered": "2026-07-20"},
            {"group_name": "conti", "post_title": "Other", "discovered": "2026-07-19"},
        ])
        groups = await enr.fetch_ransomlook("lockbit")

    assert len(groups) == 1
    g = groups[0]
    assert g["group"] == "lockbit3"
    assert g["onion_urls"] == ["http://lockbitleak.onion"]
    assert g["description"] == "LockBit ransomware group"
    assert len(g["victims"]) == 1
    assert g["victims"][0]["post_title"] == "VictimCo"


async def test_fetch_ransomlook_no_match():
    with aioresponses() as m:
        m.get(_GROUPS_RE, status=200, payload=["conti", "blackcat"])
        groups = await enr.fetch_ransomlook("nonexistentgroup")
    assert groups == []


async def test_gather_with_partial_results_preserves_finished():
    """A finished source's result survives even when a sibling exceeds the deadline."""
    async def fast():
        return [1, 2, 3]

    async def slow():
        await asyncio.sleep(5)
        return ["should-not-appear"]

    packed = await enr._gather_with_partial_results(
        [("fast", fast()), ("slow", slow())],
        timeout=0.3,
        phase_label="test",
    )
    assert packed["fast"] == [1, 2, 3]   # preserved
    assert packed["slow"] == []          # unfinished → empty, not lost-with-everything


async def test_gather_with_partial_results_captures_exception():
    async def boom():
        raise ValueError("nope")

    async def ok():
        return ["ok"]

    packed = await enr._gather_with_partial_results(
        [("boom", boom()), ("ok", ok())],
        timeout=2.0,
        phase_label="test",
    )
    assert isinstance(packed["boom"], Exception)
    assert packed["ok"] == ["ok"]
