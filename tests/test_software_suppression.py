from types import SimpleNamespace

import pytest

from extractor.entity_shape import evaluate
from extractor.normalizer import normalize_entities
from extractor.relationship_extract import _is_compatible_relationship
from extractor.software_suppression import (
    is_cpe_candidate,
    suppress_cpe_matched_organizations,
)


def _entity(entity_type, value, url="https://example.test/page"):
    return SimpleNamespace(entity_type=entity_type, value=value, source_url=url)


def test_bare_short_acronym_is_not_an_organization_by_shape_alone():
    verdict = evaluate("ORGANIZATION_NAME", "ZCS")
    assert verdict.accept is False
    assert verdict.tier == "reject"


def test_short_acronym_with_organization_context_survives():
    verdict = evaluate(
        "ORGANIZATION_NAME",
        "ZCS",
        "ZCS is a company operated by the Zeta Cybersecurity group.",
    )
    assert verdict.accept is True


def test_normalizer_suppresses_products_but_preserves_genuine_organizations():
    raw = {
        "ORGANIZATION_NAME": [
            "ZCS",
            "PowerShell",
            "WordPress",
            "CISA",
            "Acme Corp",
        ],
    }
    text = (
        "The advisory describes ZCS and PowerShell software. "
        + ("context " * 80)
        + "WordPress is software. "
        + ("context " * 80)
        + "CISA is an agency. Acme Corp is a company."
    )
    entities = normalize_entities(raw, "https://example.test/page", page_text=text)
    assert {entity.value for entity in entities} == {"CISA", "Acme Corp"}


def test_cpe_candidate_can_use_nearby_product_context_for_titlecase_names():
    assert is_cpe_candidate("Zimbra", "Users of Zimbra Collaboration Suite should update.")


@pytest.mark.asyncio
async def test_cpe_match_suppresses_only_the_matching_page_entity(monkeypatch):
    async def fake_fetch(value):
        return {"matched": value == "AcmeProduct"}

    monkeypatch.setattr("sources.nvd.fetch_nvd_cpe", fake_fetch)
    entities = [
        _entity("ORGANIZATION_NAME", "AcmeProduct", "https://example.test/a"),
        _entity("ORGANIZATION_NAME", "AcmeProduct", "https://example.test/b"),
        _entity("ORGANIZATION_NAME", "Genuine Corp", "https://example.test/a"),
    ]
    kept, count = await suppress_cpe_matched_organizations(
        entities,
        {"https://example.test/a": "AcmeProduct is software.", "https://example.test/b": "AcmeProduct."},
    )
    assert count == 2
    assert [entity.value for entity in kept] == ["Genuine Corp"]


def test_existing_targets_gate_rejects_a_software_target_without_changes():
    actor = {"type": "THREAT_ACTOR_HANDLE"}
    assert _is_compatible_relationship(
        "TARGETS", actor, {"type": "ORGANIZATION_NAME"}
    ) is True
    assert _is_compatible_relationship(
        "TARGETS", actor, {"type": "SOFTWARE"}
    ) is False
