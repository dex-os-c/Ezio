from __future__ import annotations

import uuid


import pytest
from sqlalchemy.orm import sessionmaker

from ezio_cli.commands import export as export_cmd


# ---------------------------------------------------------------------------
# Regression tests — Phase 0 (STIX export regression fix)
# ---------------------------------------------------------------------------
#
# The _load_entities_for_investigation function calls get_session() which uses
# the get_engine() lru_cache keyed by DATABASE_URL.  To ensure the test
# session and the function's session share the same engine (same SQLite file),
# we inject DATABASE_URL at module scope via a session-scoped fixture that
# runs before any of the test functions in this module.

@pytest.fixture(scope="module", autouse=True)
def _set_db_url_for_stix_tests():
    """
    Set DATABASE_URL for the entire stix_export test module.

    The db_engine fixture creates an engine via get_engine(test_url) and caches
    it by URL.  When _load_entities_for_investigation opens its own session via
    get_session(), it also calls get_engine(url).  For both to share the same
    SQLite file, the URL must be identical — which this fixture ensures by
    setting DATABASE_URL to the test DB path BEFORE any test code that calls
    get_engine or get_session.
    """
    import os
    from db.session import get_engine, _get_engine_cached

    # Use a named in-memory SQLite database with SharedCache so that multiple
    # connections (from different get_engine calls) see the same data.
    # The URI is stable across the module, avoiding URL-mismatch cache misses.
    _TEST_DB_URI = "sqlite:///file::memory:?cache=shared&uri=true"
    os.environ["DATABASE_URL"] = _TEST_DB_URI

    # Clear any previously cached engine so the new URL takes effect.
    _get_engine_cached.cache_clear()

    yield _TEST_DB_URI

    # Teardown: dispose the engine and restore.
    try:
        engine = get_engine(_TEST_DB_URI)
        engine.dispose()
    except Exception:
        pass
    _get_engine_cached.cache_clear()
    os.environ.pop("DATABASE_URL", None)


def test_stix_bundle_non_empty_with_real_entities(db_engine):
    """The exporter can see rows through its real ``get_session()`` path."""
    from db.models import Entity, Investigation, Page
    from export.stix import investigation_to_stix_bundle
    Session = sessionmaker(bind=db_engine)
    with Session() as session:
        inv = Investigation(query="real session STIX smoke test")
        page = Page(url="https://stix-fixture.example/page")
        session.add_all([inv, page])
        session.flush()
        session.add(Entity(page_id=page.id, investigation_id=inv.id,
                            entity_type="IP_ADDRESS", value="198.51.100.42",
                            canonical_value="198.51.100.42", confidence=0.95))
        session.commit()
        investigation_id = inv.id
    bundle = investigation_to_stix_bundle(investigation_id, include_relationships=False)
    assert bundle is not None
    assert len(bundle.objects) == 1
    assert bundle.objects[0].type == "indicator"


def test_stix_mixed_case_typed_relationship_refs_real_export(db_engine):
    """Typed SRO endpoints resolve to the correct objects after canonicalisation."""
    from db.models import Entity, EntityRelationship, Investigation, InvestigationEntityLink, Page
    from export.stix import bundle_to_dict, investigation_to_stix_bundle

    Session = sessionmaker(bind=db_engine)
    with Session() as session:
        inv = Investigation(query="mixed case identity regression")
        page = Page(url="https://intel.example/mixed-case")
        session.add_all([inv, page])
        session.flush()
        source = Entity(
            page_id=page.id, investigation_id=inv.id,
            entity_type="FILE_HASH_SHA256",
            value="ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
            canonical_value="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            confidence=0.9,
        )
        target = Entity(
            page_id=page.id, investigation_id=inv.id,
            entity_type="FILE_HASH_SHA256",
            value="0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            canonical_value="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            confidence=0.85,
        )
        session.add_all([source, target])
        session.flush()
        session.add(EntityRelationship(entity_a_id=source.id, entity_b_id=target.id,
                                        relationship_type="USES", investigation_id=inv.id,
                                        confidence=0.8))
        session.add_all([
            InvestigationEntityLink(entity_id=source.id, investigation_id=inv.id),
            InvestigationEntityLink(entity_id=target.id, investigation_id=inv.id),
        ])
        source_value = source.value
        target_value = target.value
        session.commit()
        investigation_id = inv.id

    data = bundle_to_dict(investigation_to_stix_bundle(investigation_id))
    indicators = [o for o in data["objects"] if o.get("type") == "indicator"]
    assert len(indicators) == 2
    by_pattern = {o["pattern"]: o["id"] for o in indicators}
    source_id = by_pattern[f"[file:hashes.'SHA-256' = '{source_value.lower()}']"]
    target_id = by_pattern[f"[file:hashes.'SHA-256' = '{target_value.lower()}']"]
    typed = next(o for o in data["objects"]
                 if o.get("type") == "relationship" and o["relationship_type"] == "uses")
    assert typed["source_ref"] == source_id
    assert typed["target_ref"] == target_id


def test_stix_malware_classification_uses_entity_type_and_family_metadata():
    """Malware objects expose useful STIX types instead of a fixed placeholder."""
    from extractor.normalizer import NormalizedEntity
    from export.stix import entity_to_stix_malware

    ransomware = NormalizedEntity(
        entity_type="RANSOMWARE_GROUP", value="LockBit", confidence=0.95,
        source_url="https://intel.example/lockbit", page_id=None,
    )
    emotet = NormalizedEntity(
        entity_type="MALWARE_FAMILY", value="Emotet", confidence=0.95,
        source_url="https://intel.example/emotet", page_id=None,
    )

    assert entity_to_stix_malware(ransomware)["malware_types"] == ["ransomware"]
    assert entity_to_stix_malware(emotet)["malware_types"] == ["bot"]


def test_stix_export_warns_when_relationships_are_missing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(export_cmd, "_load_target", lambda target: ("123e4567-e89b-12d3-a456-426614174000", {"investigation": {}}))
    monkeypatch.setattr("export.investigation_to_stix_bundle", lambda inv_id: object())
    monkeypatch.setattr("export.bundle_to_json", lambda bundle: '{"type":"bundle","objects":[]}')
    monkeypatch.setattr("export.stix.get_last_relationship_warning", lambda: "_build_stix_relationships failed: boom")

    out = tmp_path / "stix.json"
    export_cmd.run("123e4567-e89b-12d3-a456-426614174000", fmt="stix", output=out)

    captured = capsys.readouterr().out
    assert "relationships were not included" in captured.lower()
    assert out.read_text(encoding="utf-8") == '{"type":"bundle","objects":[]}'


class TestLoadEntitiesForInvestigation:
    """
    Regression test for the Phase 0 BLOCKER fix.

    Prior to the fix, _load_entities_for_investigation used:
        Entity.id.in_(linked_ids_subq.c.entity_id)
    inside an ORM query, which raised an ArgumentError in SQLAlchemy 2.x:
    "IN expression list, SELECT construct, or bound parameter object expected,
    got Column(...)" — causing the function to return [], producing a
    82-byte empty STIX bundle.

    The fix replaces the subquery-IN pattern with a JOIN on InvestigationEntityLink.
    """

    def test_loads_direct_entities(self, db_engine):
        """Entities owned directly by the investigation are loaded."""
        from db.models import Investigation, Entity, Page, Source
        from export.stix import _load_entities_for_investigation

        Session = sessionmaker(bind=db_engine)
        session = Session()
        try:
            # Set up: investigation + page + entity owned directly
            inv = Investigation(query="regression test query")
            session.add(inv)
            session.flush()

            source = Source(onion_address="regressiontest1234567890.onion")
            session.add(source)
            session.flush()

            page = Page(url="http://regressiontest1234567890.onion/p/1", source_id=source.id)
            session.add(page)
            session.flush()

            entity = Entity(
                page_id=page.id,
                investigation_id=inv.id,
                entity_type="BITCOIN_ADDRESS",
                value="bc1qtest123",
                confidence=0.95,
            )
            session.add(entity)
            session.flush()

            session.commit()

            # Act — pass session so the function uses the test's DB connection
            result = _load_entities_for_investigation(inv.id, session=session)

            # Assert: entity is returned (no SQLAlchemy error, no empty list)
            assert len(result) == 1
            assert result[0].entity_type == "BITCOIN_ADDRESS"
            assert result[0].value == "bc1qtest123"
        finally:
            session.close()

    def test_loads_linked_entities_via_junction_table(self, db_engine):
        """
        Entities linked via InvestigationEntityLink (junction table) are loaded.
        This was the primary regression case — the subquery IN pattern silently
        returned [] for entities that were only linked, not owned directly.
        """
        from db.models import Investigation, Entity, Page, Source, InvestigationEntityLink
        from export.stix import _load_entities_for_investigation

        Session = sessionmaker(bind=db_engine)
        session = Session()
        try:
            # Set up: investigation with entity ONLY in junction table (not owned directly)
            inv = Investigation(query="junction table test")
            session.add(inv)
            session.flush()

            source = Source(onion_address="junctiontest1234567890.onion")
            session.add(source)
            session.flush()

            page = Page(url="http://junctiontest1234567890.onion/p/1", source_id=source.id)
            session.add(page)
            session.flush()

            entity = Entity(
                page_id=page.id,
                investigation_id=None,  # not owned directly
                entity_type="ONION_URL",
                value="http://junctiontest1234567890.onion/p/1",
                confidence=0.90,
            )
            session.add(entity)
            session.flush()

            # Link entity to investigation via junction table
            link = InvestigationEntityLink(
                entity_id=entity.id,
                investigation_id=inv.id,
            )
            session.add(link)
            session.flush()

            session.commit()

            # Act — pass session so the function uses the test's DB connection
            result = _load_entities_for_investigation(inv.id, session=session)

            # Assert: junction-table-linked entity is returned
            assert len(result) == 1, (
                f"Expected 1 entity via junction table, got {len(result)}. "
                "The JOIN fix may not have worked — check for SQLAlchemy ArgumentError."
            )
            assert result[0].entity_type == "ONION_URL"
        finally:
            session.close()

    def test_loads_both_direct_and_linked(self, db_engine):
        """Entities owned directly + entities linked via junction table are both returned."""
        from db.models import Investigation, Entity, Page, Source, InvestigationEntityLink
        from export.stix import _load_entities_for_investigation

        Session = sessionmaker(bind=db_engine)
        session = Session()
        try:
            inv = Investigation(query="mixed direct and linked")
            session.add(inv)
            session.flush()

            source = Source(onion_address="mixedtest1234567890.onion")
            session.add(source)
            session.flush()

            page = Page(url="http://mixedtest1234567890.onion/p/1", source_id=source.id)
            session.add(page)
            session.flush()

            # Entity 1: owned directly
            direct_entity = Entity(
                page_id=page.id,
                investigation_id=inv.id,
                entity_type="IP_ADDRESS",
                value="1.2.3.4",
                confidence=1.0,
            )
            session.add(direct_entity)

            # Entity 2: only via junction table
            linked_entity = Entity(
                page_id=page.id,
                investigation_id=None,
                entity_type="EMAIL_ADDRESS",
                value="test@example.com",
                confidence=0.85,
            )
            session.add(linked_entity)
            session.flush()

            link = InvestigationEntityLink(
                entity_id=linked_entity.id,
                investigation_id=inv.id,
            )
            session.add(link)
            session.flush()

            session.commit()

            result = _load_entities_for_investigation(inv.id, session=session)

            # Assert: both entities are returned (the primary regression check)
            assert len(result) == 2, (
                f"Expected 2 entities (1 direct + 1 linked), got {len(result)}. "
                "The JOIN fix must return entities from both paths."
            )
            types = {e.entity_type for e in result}
            assert types == {"IP_ADDRESS", "EMAIL_ADDRESS"}
        finally:
            session.close()

    def test_returns_empty_when_investigation_not_found(self, db_engine):
        """Returns [] when investigation ID doesn't exist — no SQLAlchemy exception."""
        from export.stix import _load_entities_for_investigation

        fake_uuid = str(uuid.uuid4())
        result = _load_entities_for_investigation(fake_uuid)
        assert result == []

    def test_returns_empty_when_no_database_url(self):
        """Returns [] gracefully when DATABASE_URL is not set."""
        from export.stix import _load_entities_for_investigation
        import os

        orig = os.environ.pop("DATABASE_URL", None)
        try:
            result = _load_entities_for_investigation(str(uuid.uuid4()))
            assert result == []
        finally:
            if orig is not None:
                os.environ["DATABASE_URL"] = orig

    
    def test_stix_bundle_non_empty_with_real_entities(self, db_engine):
        """Compatibility alias for the real integration smoke test."""
        test_stix_bundle_non_empty_with_real_entities(db_engine)
