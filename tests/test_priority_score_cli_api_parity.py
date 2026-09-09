"""Cross-surface parity: the ``priority_score`` a CLI export reports for an
entity must equal what the API's investigation-scoped scorer reports for the
same entity.

The ``api/routes/entities.py`` change that adds ``priority_score`` to the
``/entities`` surface claims in-comment that the value is "byte-for-byte
comparable to ``GET /investigations/{id}/entities`` and to the CLI JSON/CSV/MD
export".  That claim is only meaningful if all surfaces feed ``score_map`` the
same investigation-wide input set.  This test builds a real investigation and
asserts the CLI and API scores agree for every entity.
"""

from __future__ import annotations

import datetime
import uuid


def test_cli_export_priority_matches_api_investigation_scope(db_engine):
    from db.session import get_session
    from db.models import Investigation, Page, Entity, EntityRelationship
    from api.routes.entities import _investigation_priority_map
    from ezio_cli.adapters import sqlite as sqlite_adapter

    inv_id = uuid.uuid4()
    page_a, page_b = uuid.uuid4(), uuid.uuid4()
    now = datetime.datetime.now(datetime.timezone.utc)
    ids = {name: uuid.uuid4() for name in ("e1", "e2", "e3", "e4")}

    def _entity(eid, etype, value, page_id):
        return Entity(
            id=eid, page_id=page_id, investigation_id=inv_id,
            entity_type=etype, value=value, confidence=0.9,
            canonical_value=value.lower(), extraction_method="regex",
            first_seen_at=now, last_seen_at=now, created_at=now,
        )

    with get_session() as session:
        session.add(Investigation(
            id=inv_id, query="q", status="completed",
            created_at=now, entity_count=4, page_count=2,
        ))
        session.add(Page(id=page_a, url="http://a.onion", cleaned_text="a",
                         scrape_timestamp=now, created_at=now))
        session.add(Page(id=page_b, url="http://b.onion", cleaned_text="b",
                         scrape_timestamp=now, created_at=now))
        session.add(_entity(ids["e1"], "THREAT_ACTOR_HANDLE", "Actor1", page_a))
        session.add(_entity(ids["e2"], "MALWARE_FAMILY", "Mal2", page_a))
        session.add(_entity(ids["e3"], "IP_ADDRESS", "1.2.3.3", page_a))
        session.add(_entity(ids["e4"], "IP_ADDRESS", "1.2.3.4", page_b))
        for a, b in [("e1", "e2"), ("e1", "e3"), ("e2", "e3"), ("e3", "e4")]:
            session.add(EntityRelationship(
                id=uuid.uuid4(), entity_a_id=ids[a], entity_b_id=ids[b],
                relationship_type="CO_APPEARED_ON", confidence=0.5,
                investigation_id=inv_id, source_page_id=page_a, first_seen=now,
            ))
        session.commit()

    # CLI export surface.
    cli_entities = sqlite_adapter.get_entities(str(inv_id))
    cli_scores = {e["id"]: round(e.get("priority_score", 0.0), 6) for e in cli_entities}

    # API investigation-scoped surface.
    with get_session() as session:
        api_map = _investigation_priority_map(session, inv_id)
    api_scores = {k: round(v.get("priority_score", 0.0), 6) for k, v in api_map.items()}

    assert cli_scores, "CLI produced no entities/scores"
    assert set(cli_scores) == set(api_scores), (
        f"entity id sets differ: CLI-only={set(cli_scores)-set(api_scores)} "
        f"API-only={set(api_scores)-set(cli_scores)}"
    )
    for eid in cli_scores:
        assert cli_scores[eid] == api_scores[eid], (
            f"priority_score mismatch for {eid}: CLI={cli_scores[eid]} API={api_scores[eid]}"
        )
