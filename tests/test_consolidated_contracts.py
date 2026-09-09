from types import SimpleNamespace

from extractor.confidence import get_entity_confidence
from extractor.normalizer import _source_label_from_url
from extractor.relationship_extract import (
    _LLM_REL_VOCAB,
    _RELATIONSHIP_TYPE_COMPATIBILITY,
)
from graph.model import EDGE_TYPES, RELATIONSHIP_TYPE_STIX


def test_confidence_is_monotonic_for_repeated_observations():
    entity = SimpleNamespace(confidence=0.72)

    assert get_entity_confidence(entity) == 0.72
    assert get_entity_confidence(entity, 0.61) == 0.72
    assert get_entity_confidence(entity, 0.91) == 0.91
    assert get_entity_confidence(entity, 1.4) == 1.0


def test_relationship_consumers_derive_from_graph_model():
    canonical_typed = set(_RELATIONSHIP_TYPE_COMPATIBILITY)

    canonical_all = {
        value for name, value in vars(EDGE_TYPES).items()
        if name.isupper() and isinstance(value, str)
    }
    assert canonical_typed <= canonical_all
    assert canonical_typed <= set(_LLM_REL_VOCAB.values())
    assert set(RELATIONSHIP_TYPE_STIX) == canonical_all


def test_source_label_is_stable_and_distinguishes_sources():
    assert _source_label_from_url("https://www.github.com/acme/repo") == "github.com"
    assert _source_label_from_url("https://paste.example/a") == "paste.example"
    assert _source_label_from_url("not a url") == ""
