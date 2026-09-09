"""Tests for the one-time v2.0.3 legacy-data repair."""

from __future__ import annotations

import datetime
import uuid


def test_backfill_resolves_typed_page_and_persists_communities(db_engine):
    from db.models import Entity, EntityRelationship, Investigation, Page
    from db.session import get_session
    from ezio.backfill import run_backfill

    now = datetime.datetime.now(datetime.timezone.utc)
    investigation_id = uuid.uuid4()
    page_id = uuid.uuid4()
    source_id, target_id = uuid.uuid4(), uuid.uuid4()

    with get_session() as session:
        session.add(
            Investigation(
                id=investigation_id,
                query="legacy backfill test",
                status="completed",
                graph_status="built",
                created_at=now,
            )
        )
        session.add(
            Page(
                id=page_id,
                url="https://example.test/legacy",
                cleaned_text="Actor uses malware",
                scrape_timestamp=now,
                created_at=now,
            )
        )
        session.add_all(
            [
                Entity(
                    id=source_id,
                    page_id=page_id,
                    investigation_id=investigation_id,
                    entity_type="THREAT_ACTOR_HANDLE",
                    value="actor-one",
                    canonical_value="actor-one",
                    confidence=0.95,
                    first_seen=now,
                    last_seen=now,
                    created_at=now,
                ),
                Entity(
                    id=target_id,
                    page_id=page_id,
                    investigation_id=investigation_id,
                    entity_type="MALWARE_FAMILY",
                    value="malware-one",
                    canonical_value="malware-one",
                    confidence=0.95,
                    first_seen=now,
                    last_seen=now,
                    created_at=now,
                ),
            ]
        )
        session.add(
            EntityRelationship(
                entity_a_id=source_id,
                entity_b_id=target_id,
                relationship_type="USES",
                confidence=0.9,
                investigation_id=investigation_id,
                source_page_id=None,
                first_seen=now,
            )
        )
        session.commit()

        result = run_backfill(session, investigation_id)
        session.commit()

        relationship = session.query(EntityRelationship).one()
        investigation = session.get(Investigation, investigation_id)

        assert result["typed_relationship_pages"]["resolved"] == 1
        assert relationship.source_page_id == page_id
        assert investigation.metadata_json["communities"]
        assert investigation.metadata_json["community_count"] == 1


def test_backfill_does_not_assign_invalid_typed_relationship_page(db_engine):
    from db.models import Entity, EntityRelationship, Investigation, Page
    from db.session import get_session
    from ezio.backfill import backfill_typed_relationship_page_ids

    now = datetime.datetime.now(datetime.timezone.utc)
    investigation_id = uuid.uuid4()
    page_id = uuid.uuid4()
    source_id, target_id = uuid.uuid4(), uuid.uuid4()

    with get_session() as session:
        session.add(
            Investigation(
                id=investigation_id,
                query="invalid legacy relationship",
                status="completed",
                created_at=now,
            )
        )
        session.add(Page(id=page_id, url="https://example.test/invalid", scrape_timestamp=now, created_at=now))
        session.add_all(
            [
                Entity(id=source_id, page_id=page_id, investigation_id=investigation_id,
                       entity_type="ORGANIZATION_NAME", value="org", canonical_value="org"),
                Entity(id=target_id, page_id=page_id, investigation_id=investigation_id,
                       entity_type="IP_ADDRESS", value="192.0.2.1", canonical_value="192.0.2.1"),
                EntityRelationship(entity_a_id=source_id, entity_b_id=target_id,
                                   relationship_type="TARGETS", investigation_id=investigation_id,
                                   first_seen=now),
            ]
        )
        session.commit()
        result = backfill_typed_relationship_page_ids(session, investigation_id)
        assert result == {"scanned": 1, "resolved": 0, "unresolved": 1}
