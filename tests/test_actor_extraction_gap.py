"""Regression tests for known actor extraction from short clearnet pages."""

from __future__ import annotations

from types import SimpleNamespace

from extractor import entity_shape, ner


def test_known_multiword_actor_is_not_rejected_as_common_language() -> None:
    verdict = entity_shape.evaluate("THREAT_ACTOR_HANDLE", "Lazarus Group")

    assert verdict.accept is True
    assert verdict.tier == "gazetteer"


def test_known_actor_org_span_is_checked_without_threat_context(monkeypatch) -> None:
    class FakeNLP:
        def __call__(self, text):
            return SimpleNamespace(
                ents=[SimpleNamespace(text="Lazarus Group", label_="ORG")]
            )

    monkeypatch.setattr(ner, "_get_nlp", lambda: FakeNLP())

    result = ner.extract_named_entities(
        "Cyber threat analysis of Lazarus Group (APT38)."
    )

    assert "Lazarus Group" in result["THREAT_ACTOR_HANDLE"]
