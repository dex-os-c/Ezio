from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from utils.entity_priority import score_entities


def _entity(entity_id, *, confidence, source_count=1, investigation_count=1, days_ago=0):
    seen = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return SimpleNamespace(
        id=entity_id,
        entity_type="IP_ADDRESS",
        confidence=confidence,
        source_count=source_count,
        investigation_count=investigation_count,
        last_seen_at=seen,
        first_seen_at=seen,
    )


def test_sparse_graph_scores_are_differentiated_without_relationships():
    entities = [
        _entity("fresh-high", confidence=0.96, source_count=3),
        _entity("fresh-mid", confidence=0.78, source_count=1),
        _entity("stale-mid", confidence=0.78, source_count=1, days_ago=200),
    ]

    scored = score_entities(entities)
    scores = [item["priority_score"] for item in scored]

    assert len(set(scores)) == 3
    assert scores[0] > scores[1] > scores[2]
    assert all(item["priority_score_components"]["centrality"] == 0.0 for item in scored)


def test_typed_relationship_signal_is_visible_but_low_weight():
    entities = [
        _entity("linked-a", confidence=0.70),
        _entity("linked-b", confidence=0.70),
        _entity("uncorrelated-high", confidence=0.96, source_count=4),
    ]
    relationships = [
        {"entity_a_id": "linked-a", "entity_b_id": "linked-b", "relationship_type": "USED"},
    ]

    scored = {item["id"]: item for item in score_entities(entities, relationships)}

    assert scored["linked-a"]["priority_score_components"]["centrality"] > 0.0
    assert scored["linked-b"]["priority_score_components"]["centrality"] > 0.0
    assert scored["linked-a"]["priority_score_centrality_contribution"] > 0.0
    assert scored["uncorrelated-high"]["priority_score"] > scored["linked-a"]["priority_score"]
    assert scored["linked-a"]["priority_score"] - scored["linked-b"]["priority_score"] == 0.0


def test_all_tied_typed_degrees_do_not_create_a_centrality_rank():
    entities = [_entity("a", confidence=0.8), _entity("b", confidence=0.8)]
    relationships = [
        {"entity_a_id": "a", "entity_b_id": "b", "relationship_type": "TARGETS"},
    ]

    scored = score_entities(entities, relationships)

    assert all(item["typed_relationship_degree"] == 1 for item in scored)
    assert all(item["priority_score_components"]["centrality"] == 0.0 for item in scored)
    assert all(item["priority_score_centrality_contribution"] == 0.0 for item in scored)


def test_cli_and_api_shaped_records_use_the_same_score():
    orm_entity = _entity("same", confidence=0.91, source_count=2, investigation_count=2)
    api_record = {
        "id": "same",
        "entity_type": orm_entity.entity_type,
        "confidence": orm_entity.confidence,
        "source_count": orm_entity.source_count,
        "investigation_count": orm_entity.investigation_count,
        "last_seen_at": orm_entity.last_seen_at,
        "first_seen_at": orm_entity.first_seen_at,
    }

    orm_score = score_entities([orm_entity])[0]
    api_score = score_entities([api_record])[0]

    assert orm_score["priority_score"] == api_score["priority_score"]
    assert orm_score["priority_score_components"] == api_score["priority_score_components"]
