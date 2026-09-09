import pytest

from extractor.dependency_relationship import extract_dependency_relationships


def _extract(text, *entities):
    return extract_dependency_relationships(text, list(entities))


@pytest.mark.parametrize(
    ("text", "source", "target", "expected"),
    [
        (
            "LockBit uses Cobalt Strike.",
            ("THREAT_ACTOR_HANDLE", "LockBit"),
            ("TOOL", "Cobalt Strike"),
            "USES",
        ),
        (
            "LockBit controls 10.0.0.1.",
            ("THREAT_ACTOR_HANDLE", "LockBit"),
            ("IP_ADDRESS", "10.0.0.1"),
            "CONTROLS",
        ),
        (
            "Emotet downloads QakBot.",
            ("MALWARE_FAMILY", "Emotet"),
            ("MALWARE_FAMILY", "QakBot"),
            "DROPS",
        ),
        (
            "LockBit targets Acme Corp.",
            ("THREAT_ACTOR_HANDLE", "LockBit"),
            ("ORGANIZATION_NAME", "Acme Corp"),
            "TARGETS",
        ),
        (
            "LockBit exploits CVE-2024-1234.",
            ("THREAT_ACTOR_HANDLE", "LockBit"),
            ("CVE", "CVE-2024-1234"),
            "EXPLOITS",
        ),
        (
            "LockBit connects to evil.example.",
            ("THREAT_ACTOR_HANDLE", "LockBit"),
            ("DOMAIN", "evil.example"),
            "COMMUNICATES_WITH",
        ),
    ],
)
def test_observed_verb_and_entity_types_extract_one_typed_relationship(
    text, source, target, expected
):
    relationships = _extract(
        text,
        {"type": source[0], "value": source[1]},
        {"type": target[0], "value": target[1]},
    )

    assert len(relationships) == 1
    assert relationships[0]["relationship_type"] == expected
    assert relationships[0]["source_value"] == source[1]
    assert relationships[0]["target_value"] == target[1]


def test_passive_voice_flips_direction():
    relationships = _extract(
        "Acme Corp was targeted by LockBit.",
        {"type": "ORGANIZATION_NAME", "value": "Acme Corp"},
        {"type": "THREAT_ACTOR_HANDLE", "value": "LockBit"},
    )

    assert relationships[0]["relationship_type"] == "TARGETS"
    assert relationships[0]["source_value"] == "LockBit"
    assert relationships[0]["target_value"] == "Acme Corp"


def test_generic_verb_abstains():
    relationships = _extract(
        "LockBit says Acme Corp.",
        {"type": "THREAT_ACTOR_HANDLE", "value": "LockBit"},
        {"type": "ORGANIZATION_NAME", "value": "Acme Corp"},
    )

    assert relationships == []


def test_compatibility_rejection_abstains():
    relationships = _extract(
        "Acme Corp targets Beta Corp.",
        {"type": "ORGANIZATION_NAME", "value": "Acme Corp"},
        {"type": "ORGANIZATION_NAME", "value": "Beta Corp"},
    )

    assert relationships == []


def test_side_source_route_invokes_same_extractor():
    from ezio_cli.commands.investigate import (
        _annotate_no_llm_dependency_relationships,
    )

    pages = _annotate_no_llm_dependency_relationships(
        [{"url": "https://example.test/report", "text": "LockBit uses Mimikatz."}],
        "rss-side-source",
    )

    assert pages[0]["dependency_extraction_invoked"] is True
    assert pages[0]["dependency_extraction_route"] == "rss-side-source"
    assert pages[0]["dependency_relationships"][0]["relationship_type"] == "USES"
