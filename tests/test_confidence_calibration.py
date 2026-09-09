from __future__ import annotations

from extractor.normalizer import NormalizedEntity, _confidence_for, normalize_entities
from extractor.pipeline import apply_entity_cap


def test_confidence_tiers_assign_expected_base_scores():
    assert _confidence_for("BITCOIN_ADDRESS") == 1.0
    assert _confidence_for("FILE_HASH_SHA256") == 1.0
    assert _confidence_for("CVE") == 1.0
    assert _confidence_for("ETHEREUM_ADDRESS") == 0.90
    assert _confidence_for("PHONE_NUMBER") == 0.90
    assert _confidence_for("THREAT_ACTOR_HANDLE") == 0.82
    assert _confidence_for("ORGANIZATION_NAME") == 0.82
    assert _confidence_for("DATE") == 0.82


def test_normalize_entities_uses_base_tier():
    entities = normalize_entities(
        {
            "BITCOIN_ADDRESS": ["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"],
            "THREAT_ACTOR_HANDLE": ["shadowfox"],
        },
        page_url="https://example.com/post",
        page_id=None,
        page_text="shadowfox and 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    )

    scores = {entity.entity_type: entity.confidence for entity in entities}
    assert scores["BITCOIN_ADDRESS"] == 0.94
    assert scores["THREAT_ACTOR_HANDLE"] == 0.717


def test_placeholder_entities_stay_at_or_below_threshold():
    placeholder = NormalizedEntity(
        entity_type="DOMAIN",
        value="example.invalid",
        confidence=0.79,
        source_url="https://primary.example/post",
        page_id=None,
        source_quality=0.0,
    )

    capped, _ = apply_entity_cap([placeholder], cap=50, investigation_id=None)

    assert capped == []


def test_occurrence_boost_caps_at_five_hundredths():
    entities = [
        NormalizedEntity(
            entity_type="THREAT_ACTOR_HANDLE",
            value="shadowfox",
            confidence=0.82,
            source_url=f"https://example.com/page-{idx}",
            page_id=None,
        )
        for idx in range(8)
    ]

    capped, original_count = apply_entity_cap(entities, cap=50, investigation_id=None)

    assert original_count == 8
    assert len(capped) == 8
    assert {round(entity.confidence, 2) for entity in capped} == {0.97}
    assert max(entity.confidence for entity in capped) <= 0.97


def test_apply_entity_cap_culls_low_confidence_and_placeholders():
    entities = [
        NormalizedEntity(
            entity_type="BITCOIN_ADDRESS",
            value="bc1qrealaddress00000000000000000000000000",
            confidence=1.0,
            source_url="https://primary.example/post-1",
            page_id=None,
        ),
        NormalizedEntity(
            entity_type="THREAT_ACTOR_HANDLE",
            value="shadowfox",
            confidence=0.82,
            source_url="https://primary.example/post-1",
            page_id=None,
        ),
        NormalizedEntity(
            entity_type="ORGANIZATION_NAME",
            value="Umbra Labs",
            confidence=0.79,
            source_url="https://primary.example/post-2",
            page_id=None,
        ),
        NormalizedEntity(
            entity_type="DOMAIN",
            value="example.invalid",
            confidence=0.81,
            source_url="https://primary.example/post-3",
            page_id=None,
            source_quality=0.0,
        ),
    ]

    capped, original_count = apply_entity_cap(entities, cap=50, investigation_id=None)

    assert original_count == 4
    assert len(capped) == 3
    assert all(entity.confidence >= 0.80 for entity in capped)
    assert all(entity.source_quality != 0.0 for entity in capped)
    assert {entity.entity_type for entity in capped} == {
        "BITCOIN_ADDRESS", "THREAT_ACTOR_HANDLE", "ORGANIZATION_NAME"
    }
