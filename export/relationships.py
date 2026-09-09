"""Shared relationship loading for structured exporters.

The graph builder is the canonical source for both persisted typed edges and
the bounded co-occurrence edges used by exports.  Keeping the enumeration in
one place prevents one format from silently losing relationships that another
format preserves.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
import uuid

from graph.model import RELATIONSHIP_TYPE_STIX

logger = logging.getLogger(__name__)


def load_export_relationships(
    investigation_id: Any,
    endpoint_map: dict[str, str],
) -> tuple[list[dict[str, Any]], Optional[str]]:
    """Return graph relationships whose endpoints exist in ``endpoint_map``.

    Each result contains the original Ezio ``edge_type`` plus its STIX
    spelling.  Consumers can therefore share the exact same deduplication and
    endpoint selection while rendering format-specific relationship records.
    """
    try:
        from graph.builder import build_graph_from_db  # noqa: PLC0415

        inv_uuid = _coerce_uuid(investigation_id)
        graph = build_graph_from_db(investigation_id=inv_uuid)
        relationships: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()

        for source_node, target_node, data in graph.edges(data=True):
            source_ref = endpoint_map.get(source_node)
            target_ref = endpoint_map.get(target_node)
            if not source_ref or not target_ref:
                continue

            edge_type = _normalise_edge_type(data.get("edge_type", "related-to"))
            stix_type = RELATIONSHIP_TYPE_STIX.get(edge_type, "related-to")
            key = (stix_type, source_ref, target_ref)
            if key in seen:
                continue
            seen.add(key)
            relationships.append(
                {
                    "source_ref": source_ref,
                    "target_ref": target_ref,
                    "edge_type": edge_type,
                    "stix_relationship_type": stix_type,
                    "confidence": data.get("confidence"),
                }
            )
        return relationships, None
    except Exception as exc:
        logger.warning("load_export_relationships failed: %s", exc)
        return [], f"load_export_relationships failed: {exc}"


def _normalise_edge_type(edge_type: Any) -> str:
    """Normalise enum/string edge types without changing their meaning."""
    value = getattr(edge_type, "value", edge_type)
    text = str(value or "related-to").strip()
    upper = text.upper()
    if upper in RELATIONSHIP_TYPE_STIX:
        return upper
    return text


def _coerce_uuid(value: Any) -> Optional[uuid.UUID]:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None
