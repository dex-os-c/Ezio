"""Signal-based prioritization for investigation entities.

The prioritization score is intentionally independent of graph density.  The
confidence, corroboration, and freshness signals are always available; typed
relationship degree is an optional, low-weight hint when the investigation has
enough variation for it to be meaningful.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from math import isfinite, log1p
from typing import Any

from utils.ioc_freshness import FreshnessTag, get_freshness_tag

# Keep the score shape explicit and easy to audit.  Centrality is opportunistic
# by design: one sparse edge cannot outweigh strong evidence from the other
# three signals.
PRIORITY_WEIGHTS = {
    "confidence": 0.45,
    "corroboration": 0.30,
    "freshness": 0.20,
    "centrality": 0.05,
}

_SOURCE_COUNT_CAP = 10
_INVESTIGATION_COUNT_CAP = 5
_CENTRALITY_DEGREE_CAP = 10
_CO_OCCURRENCE_EDGE = "CO_APPEARED_ON"

_FRESHNESS_SCORES = {
    FreshnessTag.FRESH.value: 1.0,
    FreshnessTag.AGING.value: 0.67,
    FreshnessTag.STALE.value: 0.33,
    FreshnessTag.EXPIRED.value: 0.0,
    # Missing timestamps are not evidence of staleness.  Keep this neutral so
    # legacy rows do not receive an arbitrary hard penalty.
    FreshnessTag.UNKNOWN.value: 0.5,
}


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        return number if isfinite(number) else default
    except (TypeError, ValueError):
        return default


def _clamp(value: Any, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, _number(value)))


def _log_capped(value: Any, cap: int) -> float:
    """Normalize a non-negative count with a fixed logarithmic cap."""
    count = max(0.0, _number(value, 1.0))
    if cap <= 1:
        return 1.0 if count >= cap else 0.0
    return min(1.0, log1p(max(0.0, count - 1.0)) / log1p(cap - 1.0))


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _freshness_score(item: Any) -> tuple[str, float]:
    tag = _value(item, "freshness_tag")
    tag_value = getattr(tag, "value", tag)
    if tag_value:
        normalized = str(tag_value).lower()
        return normalized, _FRESHNESS_SCORES.get(normalized, 0.5)

    entity_type = str(_value(item, "entity_type", "") or "")
    last_seen = _parse_datetime(
        _value(item, "last_seen_at") or _value(item, "last_seen")
    )
    first_seen = _parse_datetime(
        _value(item, "first_seen_at") or _value(item, "first_seen")
    )
    freshness = get_freshness_tag(entity_type, last_seen, first_seen)
    return freshness.value, _FRESHNESS_SCORES[freshness.value]


def _entity_id(item: Any) -> str:
    return str(_value(item, "id", ""))


def _typed_degrees(
    entities: Iterable[Any], relationships: Iterable[Any],
) -> dict[str, int]:
    """Return undirected degree counts for typed edges only."""
    entity_ids = {_entity_id(entity) for entity in entities if _entity_id(entity)}
    degrees = {entity_id: 0 for entity_id in entity_ids}
    for relationship in relationships or ():
        relationship_type = str(
            _value(relationship, "relationship_type", "") or ""
        ).upper()
        if not relationship_type or relationship_type == _CO_OCCURRENCE_EDGE:
            continue
        entity_a_id = str(_value(relationship, "entity_a_id", "") or "")
        entity_b_id = str(_value(relationship, "entity_b_id", "") or "")
        if entity_a_id in degrees and entity_b_id in degrees:
            degrees[entity_a_id] += 1
            degrees[entity_b_id] += 1
    return degrees


def score_entities(
    entities: Iterable[Any],
    relationships: Iterable[Any] = (),
) -> list[dict[str, Any]]:
    """Return per-entity prioritization fields in a normalized ``[0, 1]`` range.

    The returned list has one mapping per input item and does not mutate ORM
    rows.  Centrality is zero when there are no typed edges or when every
    entity has the same typed degree (including the all-tied sparse case).
    """
    entity_list = list(entities or ())
    degree_by_id = _typed_degrees(entity_list, relationships)
    degree_values = list(degree_by_id.values())
    has_centrality_variation = bool(degree_values) and max(degree_values) > min(degree_values)

    result: list[dict[str, Any]] = []
    for entity in entity_list:
        confidence = _clamp(_value(entity, "confidence", 0.0))
        source_count = max(1.0, _number(_value(entity, "source_count", 1), 1.0))
        investigation_count = max(
            1.0, _number(_value(entity, "investigation_count", 1), 1.0)
        )
        source_signal = _log_capped(source_count, _SOURCE_COUNT_CAP)
        investigation_signal = _log_capped(
            investigation_count, _INVESTIGATION_COUNT_CAP
        )
        corroboration = (source_signal + investigation_signal) / 2.0
        freshness_tag, freshness = _freshness_score(entity)

        degree = degree_by_id.get(_entity_id(entity), 0)
        centrality = 0.0
        if has_centrality_variation:
            centrality = _log_capped(degree + 1, _CENTRALITY_DEGREE_CAP)

        score = (
            PRIORITY_WEIGHTS["confidence"] * confidence
            + PRIORITY_WEIGHTS["corroboration"] * corroboration
            + PRIORITY_WEIGHTS["freshness"] * freshness
            + PRIORITY_WEIGHTS["centrality"] * centrality
        )
        centrality_contribution = PRIORITY_WEIGHTS["centrality"] * centrality
        result.append(
            {
                "id": _entity_id(entity),
                "priority_score": round(max(0.0, min(1.0, score)), 6),
                "freshness_tag": freshness_tag,
                "priority_score_components": {
                    "confidence": round(confidence, 6),
                    "corroboration": round(corroboration, 6),
                    "freshness": round(freshness, 6),
                    "centrality": round(centrality, 6),
                },
                "priority_score_centrality_contribution": round(
                    centrality_contribution, 6
                ),
                "typed_relationship_degree": degree,
            }
        )
    return result


def score_map(
    entities: Iterable[Any],
    relationships: Iterable[Any] = (),
) -> dict[str, dict[str, Any]]:
    """Convenience lookup keyed by the entity id used by both surfaces."""
    return {item["id"]: item for item in score_entities(entities, relationships)}
