"""One-time repairs for legacy investigation data.

This module deliberately does not change the schema.  It repairs two pieces of
derived data that were introduced after some investigations had already been
stored: the page provenance on typed relationship edges and the persisted
community partition used by the HTTP graph endpoint.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import uuid
from collections import defaultdict
from typing import Any, Optional

from sqlalchemy.orm import joinedload

from extractor.relationship_extract import _LLM_REL_VOCAB, _is_compatible_relationship
from graph.builder import build_graph_from_db, detect_communities

logger = logging.getLogger(__name__)


def _as_uuid(value: Any) -> Optional[uuid.UUID]:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value)) if value else None
    except (TypeError, ValueError, AttributeError):
        return None


def _metadata_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str) and value:
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return dict(decoded) if isinstance(decoded, dict) else {}
    return {}


def _validated_entities(session, investigation_id: uuid.UUID):
    """Return the current entity set, including cross-investigation links."""
    from db.models import Entity, InvestigationEntityLink

    return (
        session.query(Entity)
        .outerjoin(
            InvestigationEntityLink,
            InvestigationEntityLink.entity_id == Entity.id,
        )
        .filter(
            (Entity.investigation_id == investigation_id)
            | (InvestigationEntityLink.investigation_id == investigation_id)
        )
        .options(joinedload(Entity.page))
        .distinct()
        .all()
    )


def _resolve_source_page_id(
    relationship,
    entity_a,
    entity_b,
    validated_entities: list,
) -> Optional[uuid.UUID]:
    """Resolve provenance using the live pipeline's validated entity set.

    Typed relationship direction is meaningful: the live pipeline persists the
    page on which the claim was extracted.  For a legacy row without that
    field, the source endpoint's page is the strongest deterministic evidence;
    the target page and a page containing both endpoints are conservative
    fallbacks.  No page outside the validated investigation set is accepted.
    """
    if not _is_compatible_relationship(
        str(relationship.relationship_type or ""),
        {"type": entity_a.entity_type},
        {"type": entity_b.entity_type},
    ):
        return None

    valid_page_ids = {
        ent.page_id for ent in validated_entities if ent.page_id is not None
    }
    if not valid_page_ids:
        return None

    page_entity_ids: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    for ent in validated_entities:
        if ent.page_id is not None:
            page_entity_ids[ent.page_id].add(ent.id)

    # The source endpoint is the direct equivalent of the page_id attached by
    # relationship_extract.extract_relationships_from_results().
    candidates = [
        entity_a.page_id,
        entity_b.page_id,
    ]
    for page_id, entity_ids in page_entity_ids.items():
        if entity_a.id in entity_ids and entity_b.id in entity_ids:
            candidates.append(page_id)
    for page_id, entity_ids in page_entity_ids.items():
        if entity_a.id in entity_ids:
            candidates.append(page_id)

    seen: set[uuid.UUID] = set()
    for page_id in candidates:
        if page_id is None or page_id in seen:
            continue
        seen.add(page_id)
        if page_id in valid_page_ids:
            return page_id
    return None


def backfill_typed_relationship_page_ids(
    session,
    investigation_id: Optional[uuid.UUID] = None,
) -> dict[str, int]:
    """Populate missing ``source_page_id`` values on validated typed edges."""
    from db.models import Entity, EntityRelationship

    typed_types = set(_LLM_REL_VOCAB.values())
    query = session.query(EntityRelationship).filter(
        EntityRelationship.source_page_id.is_(None),
        EntityRelationship.relationship_type.in_(typed_types),
    )
    if investigation_id is not None:
        query = query.filter(EntityRelationship.investigation_id == investigation_id)

    rows = query.options(
        joinedload(EntityRelationship.entity_a).joinedload(Entity.page),
        joinedload(EntityRelationship.entity_b).joinedload(Entity.page),
    ).all()
    entities_by_investigation: dict[uuid.UUID, list] = {}
    scanned = resolved = unresolved = 0

    for relationship in rows:
        scanned += 1
        entity_a = relationship.entity_a
        entity_b = relationship.entity_b
        target_investigation = (
            _as_uuid(relationship.investigation_id)
            or _as_uuid(getattr(entity_a, "investigation_id", None))
            or _as_uuid(getattr(entity_b, "investigation_id", None))
        )
        if target_investigation is None:
            unresolved += 1
            continue
        if target_investigation not in entities_by_investigation:
            entities_by_investigation[target_investigation] = _validated_entities(
                session, target_investigation
            )
        page_id = _resolve_source_page_id(
            relationship,
            entity_a,
            entity_b,
            entities_by_investigation[target_investigation],
        )
        if page_id is None:
            unresolved += 1
            continue
        relationship.source_page_id = page_id
        resolved += 1

    if resolved:
        session.flush()
    return {"scanned": scanned, "resolved": resolved, "unresolved": unresolved}


def backfill_community_partitions(
    session,
    investigation_id: Optional[uuid.UUID] = None,
) -> dict[str, int]:
    """Persist detector output for completed investigations lacking a partition."""
    from db.models import Investigation

    query = session.query(Investigation).filter(Investigation.status == "completed")
    if investigation_id is not None:
        query = query.filter(Investigation.id == investigation_id)

    scanned = persisted = skipped = 0
    for investigation in query.order_by(Investigation.created_at).all():
        scanned += 1
        metadata = _metadata_dict(investigation.metadata_json)
        existing = metadata.get("communities")
        if isinstance(existing, dict) and existing:
            skipped += 1
            continue

        graph = build_graph_from_db(investigation_id=investigation.id)
        partition = {
            str(node_id): int(community_id)
            for node_id, community_id in detect_communities(graph).items()
        }
        metadata["communities"] = partition
        metadata["community_count"] = len(set(partition.values())) if partition else 0
        investigation.metadata_json = metadata
        session.flush()
        persisted += 1

    return {"scanned": scanned, "persisted": persisted, "skipped": skipped}


def run_backfill(
    session,
    investigation_id: Optional[uuid.UUID] = None,
) -> dict[str, dict[str, int]]:
    """Run both repairs in one transaction."""
    typed = backfill_typed_relationship_page_ids(session, investigation_id)
    communities = backfill_community_partitions(session, investigation_id)
    return {"typed_relationship_pages": typed, "community_partitions": communities}


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", help="SQLite database path (defaults to EZIO_DB_PATH)")
    parser.add_argument("--investigation-id", help="Limit the repair to one investigation")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    db_path = args.db_path or os.getenv("EZIO_DB_PATH")
    if db_path:
        db_path = os.path.abspath(os.path.expanduser(db_path))
        os.environ["EZIO_DB_PATH"] = db_path
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path.replace(os.sep, '/') }"

    target_id = _as_uuid(args.investigation_id)
    if args.investigation_id and target_id is None:
        parser.error("--investigation-id must be a UUID")

    from db.session import get_session

    with get_session() as session:
        result = run_backfill(session, target_id)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
