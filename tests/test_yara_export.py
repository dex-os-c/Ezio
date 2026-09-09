"""
Tests for the YARA export module (export/yara_export.py).

The tests cover the public surface area:

* Hash-based rules (SHA256, SHA1, MD5)
* Malware family string rules
* Network IOC string rules (ONION_URL / high-confidence DOMAIN)
* Credential leak pattern rules
* Rule-name sanitisation
* Empty / minimal input handling
* Syntactic validity of the emitted YARA (balanced braces, required fields)
"""

from __future__ import annotations

import re

import pytest

from export.yara_export import (
    _safe_rule_name,
    generate_yara_rules,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _rule_names(text: str) -> list[str]:
    """Return the list of ``rule <Name>`` declarations in a YARA file."""
    return re.findall(r"^rule\s+([A-Za-z_][A-Za-z0-9_]*)", text, flags=re.MULTILINE)


def _section_titles(text: str) -> list[str]:
    return re.findall(r"^//\s*={3,}\s*//\s*(.*?)\s*//\s*={3,}", text, flags=re.MULTILINE)


# ---------------------------------------------------------------------------
# Hash rules
# ---------------------------------------------------------------------------


def test_hash_rule_generated():
    """SHA256 hash → valid YARA rule with hash.sha256 condition."""
    entities = [
        {
            "entity_type": "FILE_HASH_SHA256",
            "value": "a" * 64,
            "confidence": 0.9,
        }
    ]
    out = generate_yara_rules(entities, {"query": "test", "id": "inv-1"})
    assert 'import "hash"' in out
    assert "hash.sha256(0, filesize)" in out
    assert "a" * 64 in out
    names = _rule_names(out)
    assert any(n.startswith("Ezio_Hash_SHA256_") for n in names), names


def test_md5_and_sha1_hash_rules():
    """MD5 and SHA1 hash entities produce their respective hash.* rules."""
    entities = [
        {
            "entity_type": "FILE_HASH_MD5",
            "value": "b" * 32,
            "confidence": 0.8,
        },
        {
            "entity_type": "FILE_HASH_SHA1",
            "value": "c" * 40,
            "confidence": 0.85,
        },
    ]
    out = generate_yara_rules(entities, {"query": "test", "id": "inv-2"})
    assert "hash.md5(0, filesize)" in out
    assert "hash.sha1(0, filesize)" in out
    assert "b" * 32 in out
    assert "c" * 40 in out
    names = _rule_names(out)
    assert any(n.startswith("Ezio_Hash_MD5_") for n in names)
    assert any(n.startswith("Ezio_Hash_SHA1_") for n in names)


def test_invalid_hash_value_skipped():
    """A non-canonical hash value is dropped, not emitted as a broken rule."""
    entities = [
        {
            "entity_type": "FILE_HASH_SHA256",
            "value": "not-a-hash",
            "confidence": 0.5,
        }
    ]
    out = generate_yara_rules(entities, {"query": "x", "id": "y"})
    # No hash rule should be generated for an invalid value
    assert "hash.sha256" not in out
    # The header is still emitted
    assert "Ezio YARA rules" in out


# ---------------------------------------------------------------------------
# Malware family string rules
# ---------------------------------------------------------------------------


def test_malware_string_rule():
    """MALWARE_FAMILY entity → string detection rule with fullword nocase."""
    entities = [
        {
            "entity_type": "MALWARE_FAMILY",
            "value": "LockBit",
            "confidence": 0.95,
        }
    ]
    out = generate_yara_rules(entities, {"query": "LockBit", "id": "inv-3"})
    assert "LockBit" in out
    assert "fullword nocase" in out
    assert "any of them" in out
    names = _rule_names(out)
    assert any("lockbit" in n and n.startswith("Ezio_Malware_") for n in names), names


def test_ransomware_group_string_rule():
    """RANSOMWARE_GROUP entity also produces a malware string rule."""
    entities = [
        {
            "entity_type": "RANSOMWARE_GROUP",
            "value": "BlackCat",
            "confidence": 0.9,
        }
    ]
    out = generate_yara_rules(entities, {"query": "BlackCat", "id": "inv-4"})
    assert "BlackCat" in out
    assert "any of them" in out


# ---------------------------------------------------------------------------
# Network IOC rules
# ---------------------------------------------------------------------------


def test_onion_network_rule():
    """ONION_URL entity → Network_<ident> rule with the URL as a string match."""
    entities = [
        {
            "entity_type": "ONION_URL",
            "value": "lockbit-pay.onion",
            "confidence": 0.85,
        }
    ]
    out = generate_yara_rules(entities, {"query": "q", "id": "i"})
    assert "lockbit-pay.onion" in out
    assert 'ioc_type = "onion_url"' in out
    names = _rule_names(out)
    assert any(n.startswith("Ezio_Network_") for n in names)


def test_high_confidence_domain_rule():
    """A high-confidence DOMAIN entity produces a network rule."""
    entities = [
        {
            "entity_type": "DOMAIN",
            "value": "evil.example",
            "confidence": 0.9,
        }
    ]
    out = generate_yara_rules(entities, {"query": "q", "id": "i"})
    assert "evil.example" in out
    assert 'ioc_type = "domain"' in out


def test_low_confidence_domain_skipped():
    """Low-confidence domains (confidence < 0.7) are not emitted as YARA rules."""
    entities = [
        {
            "entity_type": "DOMAIN",
            "value": "maybe-evil.example",
            "confidence": 0.3,
        }
    ]
    out = generate_yara_rules(entities, {"query": "q", "id": "i"})
    assert "maybe-evil.example" not in out


# ---------------------------------------------------------------------------
# Credential leak rules
# ---------------------------------------------------------------------------


def test_credential_leak_rules_always_present():
    """The credential-leak pattern rules are always emitted."""
    out = generate_yara_rules([], {"query": "q", "id": "i"})
    assert "Ezio_CredLeak_AWS_AccessKey" in out
    assert "Ezio_CredLeak_GitHub_Token" in out
    assert "Ezio_CredLeak_JWT" in out


def test_credential_patterns_use_yara_regex_syntax():
    """AWS / GitHub credential patterns are valid YARA regexes."""
    out = generate_yara_rules([], {"query": "q", "id": "i"})
    # YARA regex syntax requires /.../ literal form
    assert "/AKIA[0-9A-Z]{16}/" in out
    assert "/gh[pousr]_[A-Za-z0-9]{30,}/" in out


# ---------------------------------------------------------------------------
# Rule-name sanitisation
# ---------------------------------------------------------------------------


def test_rule_name_sanitization():
    """Special chars are stripped; rule names stay identifier-safe."""
    assert _safe_rule_name("LockBit 3.0 (Black)") == "LockBit_3_0_Black"
    assert _safe_rule_name("foo/bar") == "foo_bar"
    assert _safe_rule_name("...") == "IOC"  # falls back to default
    # Leading digit: must start with a letter
    assert _safe_rule_name("3LockBit")[0].isalpha()
    # Empty input
    assert _safe_rule_name("") == "IOC"


def test_rule_name_max_length():
    """Rule names are capped at 128 characters."""
    long = "A" * 500
    safe = _safe_rule_name(long)
    assert len(safe) <= 128
    # No trailing underscores after truncation
    assert not safe.endswith("_") or len(safe) == 128


def test_no_special_chars_in_rule_name():
    """End-to-end: emitted rule names are pure [A-Za-z0-9_]."""
    entities = [
        {
            "entity_type": "MALWARE_FAMILY",
            "value": "LockBit 3.0 (Black)!!!",
            "confidence": 0.9,
        }
    ]
    out = generate_yara_rules(entities, {"query": "q", "id": "i"})
    pat = re.compile(r"^rule\s+([A-Za-z_][A-Za-z0-9_]*)", flags=re.MULTILINE)
    for m in pat.finditer(out):
        name = m.group(1)
        assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name), name


# ---------------------------------------------------------------------------
# Empty / minimal input
# ---------------------------------------------------------------------------


def test_no_rules_empty_entities():
    """Empty entity list → minimal valid YARA file with header + cred rules."""
    out = generate_yara_rules([], {"query": "q", "id": "i"})
    # Header is present
    assert "Ezio YARA rules" in out
    # No hash-import block when no hash entities were provided
    assert 'import "hash"' not in out
    # Credential-leak pattern rules are still emitted (they don't depend
    # on the input entities)
    assert "Ezio_CredLeak_" in out
    # Trailing newline (well-formed file)
    assert out.endswith("\n")


def test_no_rules_no_entities_no_creds_marker():
    """When there's literally no input and we explicitly disable cred rules
    by NOT having cred entities, we still emit the header."""
    out = generate_yara_rules([], {"query": "x", "id": "y"})
    assert out.startswith("// Ezio YARA rules")


# ---------------------------------------------------------------------------
# Syntactic validity
# ---------------------------------------------------------------------------


def test_yara_syntax_valid():
    """Braces are balanced and every rule has the required meta + condition."""
    entities = [
        {
            "entity_type": "FILE_HASH_SHA256",
            "value": "a" * 64,
            "confidence": 0.9,
        },
        {
            "entity_type": "MALWARE_FAMILY",
            "value": "LockBit",
            "confidence": 0.95,
        },
        {
            "entity_type": "ONION_URL",
            "value": "lockbit-pay.onion",
            "confidence": 0.85,
        },
    ]
    out = generate_yara_rules(entities, {"query": "LockBit", "id": "inv"})
    # Balanced braces (counting only those that aren't inside regex literals)
    # The simplest check: total ``{`` == total ``}`` outside of any line
    # that looks like a regex literal.  We don't have a full YARA parser,
    # but a simple count is enough to catch obvious mistakes.
    stripped = re.sub(r"/[^/\n]*/", "", out)  # remove regex literals
    assert stripped.count("{") == stripped.count("}"), (
        f"Unbalanced braces: {{={stripped.count('{')} }}={stripped.count('}')}"
    )
    # Every rule has a ``condition:`` block
    rule_blocks = re.findall(r"rule\s+\w+\s*\{(.*?)^\}", out, flags=re.MULTILINE | re.DOTALL)
    assert rule_blocks, "No rule blocks found"
    for block in rule_blocks:
        assert "condition:" in block, block
        assert "meta:" in block, block


def test_yara_includes_investigation_metadata():
    """The generated YARA embeds the investigation query in the header."""
    entities = [
        {
            "entity_type": "MALWARE_FAMILY",
            "value": "LockBit",
            "confidence": 0.9,
        }
    ]
    out = generate_yara_rules(
        entities,
        {"query": "LockBit ransomware", "id": "abc-123"},
        tlp="TLP:AMBER",
    )
    assert "LockBit ransomware" in out
    assert "abc-123" in out
    assert "TLP:AMBER" in out


def test_yara_section_headers():
    """The YARA file is organised into labelled sections."""
    entities = [
        {
            "entity_type": "FILE_HASH_SHA256",
            "value": "a" * 64,
            "confidence": 0.9,
        },
        {
            "entity_type": "MALWARE_FAMILY",
            "value": "LockBit",
            "confidence": 0.95,
        },
    ]
    out = generate_yara_rules(entities, {"query": "q", "id": "i"})
    titles = _section_titles(out)
    assert any("Hash" in t for t in titles)
    assert any("Malware" in t for t in titles)
    assert any("Credential" in t for t in titles)
