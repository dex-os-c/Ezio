"""Tests for the Sigma export module (export/sigma.py).

Basic real-entity / real-output coverage matching the standard already set by
test_stix_export.py, test_yara_export.py, and test_snort_export.py: feed a
concrete set of entities, generate real Sigma output, and assert on its
structure — the exact class of check that catches a narrow format regression
before it ships.
"""

from __future__ import annotations

from types import SimpleNamespace

import yaml

from export.sigma import (
    entities_to_sigma_rules,
    sigma_rule_to_yaml,
)


def _entity(entity_type: str, value: str, *, source_url: str = "", confidence: float = 0.9):
    return SimpleNamespace(
        entity_type=entity_type,
        value=value,
        source_url=source_url,
        confidence=confidence,
    )


def test_supported_entity_types_produce_rules():
    """IP / ONION / CVE / MALWARE / RANSOMWARE each yield exactly one rule."""
    entities = [
        _entity("IP_ADDRESS", "185.220.101.1", source_url="http://x.onion"),
        _entity("ONION_URL", "abcdefghij234567.onion"),
        _entity("CVE_NUMBER", "CVE-2024-3094"),
        _entity("MALWARE_FAMILY", "LockBit"),
        _entity("RANSOMWARE_GROUP", "BlackCat"),
    ]
    rules = entities_to_sigma_rules(entities)
    assert len(rules) == 5
    # Every rule must carry the mandatory Sigma keys.
    for rule in rules:
        assert rule["title"]
        assert rule["id"]
        assert rule["logsource"]
        assert rule["detection"]
        assert "condition" in rule["detection"]
        assert rule["level"] in {"low", "medium", "high", "critical"}


def test_ip_rule_targets_destination_ip_and_emits_valid_yaml():
    """The IP rule detects on DestinationIp and round-trips through YAML."""
    [rule] = entities_to_sigma_rules([_entity("IP_ADDRESS", "185.220.101.1")])
    assert rule["detection"]["selection"] == {"DestinationIp": "185.220.101.1"}

    text = sigma_rule_to_yaml(rule)
    assert text  # non-empty
    parsed = yaml.safe_load(text)
    # The serialized YAML must reproduce the rule structure faithfully.
    assert parsed["detection"]["selection"]["DestinationIp"] == "185.220.101.1"
    assert parsed["logsource"]["category"] == "network"
    assert "185.220.101.1" in parsed["title"]


def test_source_url_becomes_reference():
    """A rule references the source URL when the entity carries one."""
    [rule] = entities_to_sigma_rules(
        [_entity("MALWARE_FAMILY", "Emotet", source_url="http://leak.onion/emotet")]
    )
    assert rule["references"] == ["http://leak.onion/emotet"]


def test_unsupported_entity_types_are_skipped():
    """Types with no Sigma mapping produce no rules (and don't raise)."""
    entities = [
        _entity("EMAIL_ADDRESS", "a@b.com"),
        _entity("CRYPTO_WALLET", "bc1qxyz"),
        _entity("PERSON_NAME", "John Doe"),
    ]
    assert entities_to_sigma_rules(entities) == []


def test_empty_input_returns_empty_list():
    assert entities_to_sigma_rules([]) == []
