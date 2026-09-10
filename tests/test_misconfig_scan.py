"""Tests for sources/misconfig_scan.py — real passive misconfiguration scanning.

Uses aioresponses to mock the HTTP layer (matching the pattern used by
tests/test_nvd.py etc.) — no live network access required. The TLS check
uses raw sockets against the real hostname rather than aiohttp, so against
a fake test domain it can't connect; this is exercised explicitly to
confirm it degrades to a logged error rather than raising.
"""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from sources.misconfig_scan import _normalize_target, scan_target

_ANY_PATH = re.compile(r"https://example-test\.invalid/.*")


def test_normalize_target_adds_scheme():
    assert _normalize_target("example.com") == "https://example.com"


def test_normalize_target_keeps_explicit_scheme():
    assert _normalize_target("http://example.com") == "http://example.com"


def test_normalize_target_rejects_bad_scheme():
    with pytest.raises(ValueError):
        _normalize_target("ftp://example.com")


def test_normalize_target_rejects_empty():
    with pytest.raises(ValueError):
        _normalize_target("   ")


@pytest.mark.asyncio
async def test_missing_security_headers_detected():
    with aioresponses() as m:
        m.get("https://example-test.invalid/", status=200, headers={})
        m.get(_ANY_PATH, status=404, repeat=True)

        result = await scan_target("example-test.invalid", timeout=2)

    checks = {f["check"] for f in result["findings"]}
    assert "missing security header" in checks
    # every one of the 5 tracked headers should produce a finding when absent
    missing_header_count = sum(1 for f in result["findings"] if f["check"] == "missing security header")
    assert missing_header_count == 5


@pytest.mark.asyncio
async def test_present_security_headers_not_flagged():
    good_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    with aioresponses() as m:
        m.get("https://example-test.invalid/", status=200, headers=good_headers)
        m.get(_ANY_PATH, status=404, repeat=True)

        result = await scan_target("example-test.invalid", timeout=2)

    assert not any(f["check"] == "missing security header" for f in result["findings"])


@pytest.mark.asyncio
async def test_server_banner_disclosure_flagged():
    with aioresponses() as m:
        m.get("https://example-test.invalid/", status=200, headers={"Server": "Apache/2.4.41 (Ubuntu)"})
        m.get(_ANY_PATH, status=404, repeat=True)

        result = await scan_target("example-test.invalid", timeout=2)

    banner_findings = [f for f in result["findings"] if f["check"] == "verbose server banner"]
    assert len(banner_findings) == 1
    assert "Apache/2.4.41" in banner_findings[0]["note"]


@pytest.mark.asyncio
async def test_exposed_git_config_detected():
    with aioresponses() as m:
        m.get("https://example-test.invalid/", status=200, headers={})
        m.get("https://example-test.invalid/.git/config", status=200, body="[core]\n")
        m.get(_ANY_PATH, status=404, repeat=True)

        result = await scan_target("example-test.invalid", timeout=2)

    exposed = [f for f in result["findings"] if f["path"] == "/.git/config"]
    assert len(exposed) == 1
    assert exposed[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_admin_panel_open_vs_behind_auth():
    with aioresponses() as m:
        m.get("https://example-test.invalid/", status=200, headers={})
        m.get("https://example-test.invalid/admin", status=200, body="Dashboard")
        m.get("https://example-test.invalid/wp-admin", status=401, body="")
        m.get(_ANY_PATH, status=404, repeat=True)

        result = await scan_target("example-test.invalid", timeout=2)

    by_path = {f["path"]: f for f in result["findings"] if f["check"].startswith("default admin panel")}
    assert by_path["/admin"]["severity"] == "medium"
    assert by_path["/wp-admin"]["severity"] == "low"


@pytest.mark.asyncio
async def test_unreachable_root_produces_error_not_crash():
    with aioresponses() as m:
        m.get("https://example-test.invalid/", exception=ConnectionError("refused"))
        m.get(_ANY_PATH, exception=ConnectionError("refused"), repeat=True)

        result = await scan_target("example-test.invalid", timeout=2)

    assert result["findings"] == []
    assert any("skipped" in e for e in result["errors"])


@pytest.mark.asyncio
async def test_invalid_target_returns_error_not_exception():
    result = await scan_target("ftp://example.com")
    assert result["findings"] == []
    assert "invalid target" in result["errors"][0]


@pytest.mark.asyncio
async def test_tls_check_failure_is_graceful_not_fatal():
    # example-test.invalid does not resolve, so the raw-socket TLS check
    # must fail gracefully into `errors`, not raise out of scan_target.
    with aioresponses() as m:
        m.get("https://example-test.invalid/", status=200, headers={})
        m.get(_ANY_PATH, status=404, repeat=True)

        result = await scan_target("example-test.invalid", timeout=2)

    assert any("TLS" in e for e in result["errors"])
