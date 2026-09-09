"""
Tests for the Snort / Suricata export module (export/snort_export.py).

Coverage:

* IP reputation rules
* DNS / TLS SNI rules for domains and .onion URLs
* HTTP rules for .onion URLs with a path
* File-hash detection (Suricata only)
* CVE exploit-attempt rules
* SID range, uniqueness, and metadata
* Suricata-specific ``metadata:`` block
"""

from __future__ import annotations

import re

import pytest

from export.snort_export import (
    SID_RANGE_MAX,
    SID_RANGE_MIN,
    generate_snort_rules,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _alert_blocks(text: str) -> list[str]:
    """Return each ``alert ... ( ... )`` block as a string."""
    return re.findall(r"alert\s+\S+.*?\n\)", text, flags=re.DOTALL)


def _sids(text: str) -> list[int]:
    """Return the list of ``sid:`` values in declaration order."""
    return [int(m) for m in re.findall(r"\bsid:(\d+)\s*;", text)]


# ---------------------------------------------------------------------------
# IP rules
# ---------------------------------------------------------------------------


def test_ip_rule_generated():
    """A high-confidence IP entity → valid Snort alert rule."""
    entities = [
        {
            "entity_type": "IP_ADDRESS",
            "value": "185.220.101.45",
            "confidence": 0.94,
            "corroborating_sources": "c2_confirmed",
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    assert "alert ip 185.220.101.45" in out
    assert "185.220.101.45" in out
    assert "classtype:trojan-activity" in out
    assert "sid:" in out
    assert "rev:1" in out


def test_low_confidence_ip_skipped():
    """Low-confidence IPs (confidence < 0.85, no C2 tag) are not emitted."""
    entities = [
        {
            "entity_type": "IP_ADDRESS",
            "value": "1.2.3.4",
            "confidence": 0.3,
            "corroborating_sources": "",
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    assert "1.2.3.4" not in out


def test_c2_tag_low_confidence_still_emitted():
    """An IP with a ``c2`` corroborating-source tag is treated as C2."""
    entities = [
        {
            "entity_type": "IP_ADDRESS",
            "value": "1.2.3.4",
            "confidence": 0.4,
            "corroborating_sources": "c2,scan",
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    assert "1.2.3.4" in out


# ---------------------------------------------------------------------------
# DNS / domain / onion rules
# ---------------------------------------------------------------------------


def test_domain_dns_rule():
    """A DOMAIN entity → DNS alert rule with content match."""
    entities = [
        {
            "entity_type": "DOMAIN",
            "value": "evil.example",
            "confidence": 0.85,
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    assert "alert dns" in out
    assert 'content:"evil.example"' in out
    assert "nocase" in out
    assert "classtype:trojan-activity" in out


def test_onion_url_dns_rule():
    """An ONION_URL entity also produces a DNS rule."""
    entities = [
        {
            "entity_type": "ONION_URL",
            "value": "evil.onion",
            "confidence": 0.9,
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    assert "alert dns" in out
    assert "evil.onion" in out


# ---------------------------------------------------------------------------
# HTTP rules for .onion URLs with a path
# ---------------------------------------------------------------------------


def test_http_rule_for_onion_path():
    """An ONION_URL with a path → HTTP rule with host match."""
    entities = [
        {
            "entity_type": "ONION_URL",
            "value": "http://evil.onion/login.php",
            "confidence": 0.9,
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    assert "alert http" in out
    assert "evil.onion" in out


def test_http_rule_skipped_for_bare_onion():
    """An ONION_URL with no meaningful path is *not* emitted as an HTTP rule."""
    entities = [
        {
            "entity_type": "ONION_URL",
            "value": "evil.onion",
            "confidence": 0.9,
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    # Only the DNS rule is emitted
    assert "alert http" not in out
    assert "alert dns" in out


# ---------------------------------------------------------------------------
# File-hash rules (Suricata only)
# ---------------------------------------------------------------------------


def test_filemd5_rule_suricata_only():
    """filemd5: keyword is only emitted when format=suricata."""
    entities = [
        {
            "entity_type": "FILE_HASH_MD5",
            "value": "a" * 32,
            "confidence": 0.9,
        }
    ]
    snort_out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    assert "filemd5:" not in snort_out

    suri_out = generate_snort_rules(entities, {"query": "q"}, format="suricata")
    assert "filemd5:" in suri_out
    assert "a" * 32 in suri_out


# ---------------------------------------------------------------------------
# CVE rules
# ---------------------------------------------------------------------------


def test_cve_rule_generated():
    """A CVE entity → rule with reference:cve and a CVE-####-#### message."""
    entities = [
        {
            "entity_type": "CVE_NUMBER",
            "value": "CVE-2024-1234",
            "confidence": 1.0,
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    assert "alert http" in out
    assert "CVE-2024-1234" in out
    assert "reference:cve,CVE-2024-1234" in out
    assert "flow:established,to_server" in out


def test_invalid_cve_skipped():
    """A CVE that doesn't match the canonical format is dropped."""
    entities = [
        {
            "entity_type": "CVE_NUMBER",
            "value": "CVE-not-a-number",
            "confidence": 1.0,
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    assert "CVE-not-a-number" not in out


# ---------------------------------------------------------------------------
# Suricata-specific behaviour
# ---------------------------------------------------------------------------


def test_suricata_metadata():
    """Suricata format adds a ``metadata:`` block to IP rules."""
    entities = [
        {
            "entity_type": "IP_ADDRESS",
            "value": "185.220.101.45",
            "confidence": 0.94,
            "corroborating_sources": "c2_confirmed",
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="suricata")
    assert "metadata:" in out
    assert "malware_family" in out
    assert "signature_severity" in out
    assert "performance_impact" in out
    assert "created_at" in out


def test_suricata_uses_tls_sni_for_domains():
    """Suricata format prefers ``tls.sni`` over ``dns.query`` for HTTPS rules."""
    entities = [
        {
            "entity_type": "DOMAIN",
            "value": "evil.example",
            "confidence": 0.85,
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="suricata")
    assert "alert tls" in out
    assert "tls.sni" in out
    assert "evil.example" in out


# ---------------------------------------------------------------------------
# SID management
# ---------------------------------------------------------------------------


def test_sid_range():
    """All emitted SIDs are inside the Ezio reserved range."""
    entities = [
        {
            "entity_type": "IP_ADDRESS",
            "value": "185.220.101.45",
            "confidence": 0.94,
            "corroborating_sources": "c2",
        },
        {
            "entity_type": "DOMAIN",
            "value": "evil.example",
            "confidence": 0.9,
        },
        {
            "entity_type": "CVE_NUMBER",
            "value": "CVE-2024-1234",
            "confidence": 1.0,
        },
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    sids = _sids(out)
    assert sids, "expected at least one SID"
    for s in sids:
        assert SID_RANGE_MIN <= s <= SID_RANGE_MAX, f"SID {s} out of range"


def test_no_duplicate_sids():
    """No two emitted rules share a SID."""
    entities = [
        {
            "entity_type": "IP_ADDRESS",
            "value": "1.1.1.1",
            "confidence": 0.95,
            "corroborating_sources": "c2",
        },
        {
            "entity_type": "IP_ADDRESS",
            "value": "2.2.2.2",
            "confidence": 0.95,
            "corroborating_sources": "c2",
        },
        {
            "entity_type": "IP_ADDRESS",
            "value": "3.3.3.3",
            "confidence": 0.95,
            "corroborating_sources": "c2",
        },
        {
            "entity_type": "DOMAIN",
            "value": "a.example",
            "confidence": 0.9,
        },
        {
            "entity_type": "DOMAIN",
            "value": "b.example",
            "confidence": 0.9,
        },
        {
            "entity_type": "CVE_NUMBER",
            "value": "CVE-2024-1111",
            "confidence": 1.0,
        },
        {
            "entity_type": "CVE_NUMBER",
            "value": "CVE-2024-2222",
            "confidence": 1.0,
        },
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    sids = _sids(out)
    assert len(sids) == len(set(sids)), (
        f"Duplicate SIDs found: {[s for s in sids if sids.count(s) > 1]}"
    )


def test_sid_auto_increment():
    """SIDs are monotonically increasing."""
    entities = [
        {
            "entity_type": "IP_ADDRESS",
            "value": f"10.0.0.{i}",
            "confidence": 0.95,
            "corroborating_sources": "c2",
        }
        for i in range(1, 6)
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    sids = _sids(out)
    assert sids == sorted(sids)
    assert sids[0] == SID_RANGE_MIN


def test_sid_custom_start():
    """A custom ``start_sid`` is honoured."""
    entities = [
        {
            "entity_type": "IP_ADDRESS",
            "value": "10.0.0.1",
            "confidence": 0.95,
            "corroborating_sources": "c2",
        },
        {
            "entity_type": "IP_ADDRESS",
            "value": "10.0.0.2",
            "confidence": 0.95,
            "corroborating_sources": "c2",
        },
    ]
    out = generate_snort_rules(
        entities, {"query": "q"}, format="snort", start_sid=9_005_000
    )
    sids = _sids(out)
    assert sids[0] == 9_005_000
    assert sids[1] == 9_005_001


# ---------------------------------------------------------------------------
# Empty / malformed input
# ---------------------------------------------------------------------------


def test_empty_entities_yields_minimal_output():
    """An empty input produces a header but no alert rules."""
    out = generate_snort_rules([], {"query": "q"}, format="snort")
    assert "Ezio Snort rules" in out
    # No alert lines
    assert not re.search(r"^alert\s", out, flags=re.MULTILINE)


def test_invalid_format_raises():
    """An unknown format string raises ValueError, not a silent fallback."""
    with pytest.raises(ValueError):
        generate_snort_rules([], {"query": "q"}, format="bogus")  # type: ignore[arg-type]


def test_rule_blocks_have_balanced_parens():
    """Each emitted alert rule has balanced parentheses."""
    entities = [
        {
            "entity_type": "IP_ADDRESS",
            "value": "1.1.1.1",
            "confidence": 0.95,
            "corroborating_sources": "c2",
        },
        {
            "entity_type": "DOMAIN",
            "value": "evil.example",
            "confidence": 0.9,
        },
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    for block in _alert_blocks(out):
        assert block.count("(") == block.count(")"), block


def test_cve_reference():
    """End-to-end: the CVE rule includes both the message and the reference."""
    entities = [
        {
            "entity_type": "CVE_NUMBER",
            "value": "CVE-2023-44487",
            "confidence": 1.0,
        }
    ]
    out = generate_snort_rules(entities, {"query": "q"}, format="snort")
    assert "CVE-2023-44487" in out
    assert "reference:cve,CVE-2023-44487" in out
    # Also surfaced in the message field
    assert 'msg:"Ezio - Possible CVE-2023-44487 Exploit Attempt"' in out
