"""
Tests for the db/ module (Phase 1A).

Uses SQLite in-memory — no PostgreSQL instance required to run the suite.
The engine fixture is module-scoped so the schema is created once and all
tests in this file share the same in-memory database.  Individual session
fixtures are function-scoped and roll back after each test, keeping tests
independent without the overhead of recreating the schema each time.

Run with:
    pytest tests/test_db.py -v
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

TEST_URL = "sqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def _db_engine():
    """
    Create (and cache) a shared in-memory SQLite engine with the full schema.

    We use get_engine() rather than create_engine() directly so that
    TestSessionFactory tests which also call get_engine(TEST_URL) receive the
    *same* engine instance — and therefore the same in-memory database that
    already has the schema created.
    """
    from db.models import Base
    from db.session import get_engine

    engine = get_engine(TEST_URL)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def session(_db_engine):
    """
    Yield a fresh Session for each test, rolling back any changes afterwards.
    This keeps tests isolated without needing to recreate the schema.
    """
    Session = sessionmaker(bind=_db_engine, autoflush=False, autocommit=False)
    s = Session()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


# ---------------------------------------------------------------------------
# Schema sanity checks
# ---------------------------------------------------------------------------

class TestSchema:
    def test_all_tables_exist(self, _db_engine):
        inspector = inspect(_db_engine)
        tables = set(inspector.get_table_names())
        expected = {
            "investigations",
            "sources",
            "investigation_sources",
            "pages",
            "entities",
            "entity_relationships",
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"

    def test_investigations_columns(self, _db_engine):
        inspector = inspect(_db_engine)
        cols = {c["name"] for c in inspector.get_columns("investigations")}
        assert {"id", "run_id", "query", "refined_query", "model_used", "preset",
                "summary", "created_at"}.issubset(cols)

    def test_sources_columns(self, _db_engine):
        inspector = inspect(_db_engine)
        cols = {c["name"] for c in inspector.get_columns("sources")}
        assert {"id", "onion_address", "first_seen", "last_seen",
                "status", "source_type"}.issubset(cols)

    def test_pages_columns(self, _db_engine):
        inspector = inspect(_db_engine)
        cols = {c["name"] for c in inspector.get_columns("pages")}
        assert {"id", "source_id", "url", "raw_content_hash", "cleaned_text",
                "scrape_timestamp", "posted_at", "language", "byte_size", "created_at"}.issubset(cols)

    def test_entities_columns(self, _db_engine):
        inspector = inspect(_db_engine)
        cols = {c["name"] for c in inspector.get_columns("entities")}
        assert {"id", "page_id", "investigation_id", "entity_type", "value",
                "confidence", "context_snippet", "first_seen", "last_seen",
                "created_at", "canonical_value", "historical_context", "extraction_method"}.issubset(cols)

    def test_entity_relationships_columns(self, _db_engine):
        inspector = inspect(_db_engine)
        cols = {c["name"] for c in inspector.get_columns("entity_relationships")}
        assert {"id", "entity_a_id", "entity_b_id", "relationship_type",
                "source_page_id", "confidence", "first_seen"}.issubset(cols)


# ---------------------------------------------------------------------------
# Investigation model
# ---------------------------------------------------------------------------

class TestInvestigation:
    def test_create_minimal(self, session):
        from db.models import Investigation

        inv = Investigation(query="test ransomware query")
        session.add(inv)
        session.flush()

        assert inv.id is not None
        assert isinstance(inv.id, uuid.UUID)
        assert inv.run_id is not None
        assert isinstance(inv.run_id, uuid.UUID)
        assert inv.created_at is not None

    def test_create_full(self, session):
        from db.models import Investigation

        inv = Investigation(
            query="lockbit affiliate recruitment",
            refined_query="lockbit recruitment dark",
            model_used="gpt-4.1",
            preset="threat_intel",
            summary="Found 3 recruitment posts.",
        )
        session.add(inv)
        session.flush()

        fetched = session.get(Investigation, inv.id)
        assert fetched.query == "lockbit affiliate recruitment"
        assert fetched.model_used == "gpt-4.1"
        assert fetched.preset == "threat_intel"
        assert fetched.summary == "Found 3 recruitment posts."

    def test_run_id_unique(self, session):
        from db.models import Investigation

        run_id = uuid.uuid4()
        inv1 = Investigation(query="q1", run_id=run_id)
        inv2 = Investigation(query="q2", run_id=run_id)
        session.add(inv1)
        session.flush()
        session.add(inv2)

        with pytest.raises(IntegrityError):
            session.flush()

    def test_repr(self, session):
        from db.models import Investigation

        inv = Investigation(query="repr test query")
        session.add(inv)
        session.flush()
        assert "Investigation" in repr(inv)


# ---------------------------------------------------------------------------
# Source model
# ---------------------------------------------------------------------------

class TestSource:
    def test_create(self, session):
        from db.models import Source, SourceStatus, SourceType

        source = Source(
            onion_address="testxxx1234567890ab.onion",
            status=SourceStatus.ACTIVE.value,
            source_type=SourceType.SEARCH_RESULT.value,
        )
        session.add(source)
        session.flush()

        assert source.id is not None
        assert source.first_seen is not None
        assert source.last_seen is not None

    def test_onion_address_uniqueness(self, session):
        from db.models import Source

        s1 = Source(onion_address="duplicate12345678.onion")
        session.add(s1)
        session.flush()

        s2 = Source(onion_address="duplicate12345678.onion")
        session.add(s2)
        with pytest.raises(IntegrityError):
            session.flush()

    def test_default_status(self, session):
        from db.models import Source, SourceStatus

        source = Source(onion_address="defaultstatus1234.onion")
        session.add(source)
        session.flush()
        assert source.status == SourceStatus.UNKNOWN.value

    def test_repr(self, session):
        from db.models import Source

        source = Source(onion_address="reprsource1234567.onion")
        session.add(source)
        session.flush()
        assert "reprsource1234567.onion" in repr(source)


# ---------------------------------------------------------------------------
# Page model
# ---------------------------------------------------------------------------

class TestPage:
    def _make_source(self, session, addr: str):
        from db.models import Source
        s = Source(onion_address=addr)
        session.add(s)
        session.flush()
        return s

    def test_create_with_source(self, session):
        from db.models import Page

        source = self._make_source(session, "pagesource123456.onion")
        page = Page(
            url="http://pagesource123456.onion/forum/1",
            source_id=source.id,
            cleaned_text="ransomware payment details",
            raw_content_hash="a" * 64,
            byte_size=4096,
        )
        session.add(page)
        session.flush()

        assert page.id is not None
        assert page.source_id == source.id
        assert page.scrape_timestamp is not None

    def test_create_without_source(self, session):
        from db.models import Page

        # source_id is nullable — pages discovered before source domain is known
        page = Page(url="http://orphanpage1234567.onion/post/99")
        session.add(page)
        session.flush()

        assert page.id is not None
        assert page.source_id is None

    def test_url_uniqueness(self, session):
        from db.models import Page

        p1 = Page(url="http://uniquepage12345.onion/a")
        session.add(p1)
        session.flush()

        p2 = Page(url="http://uniquepage12345.onion/a")
        session.add(p2)
        with pytest.raises(IntegrityError):
            session.flush()

    def test_relationship_to_source(self, session):
        from db.models import Page

        source = self._make_source(session, "pagerelsource1234.onion")
        page = Page(url="http://pagerelsource1234.onion/t/1", source_id=source.id)
        session.add(page)
        session.flush()

        assert page.source.onion_address == "pagerelsource1234.onion"


# ---------------------------------------------------------------------------
# Entity model
# ---------------------------------------------------------------------------

class TestEntity:
    def _make_page(self, session, suffix: str):
        from db.models import Source, Page
        s = Source(onion_address=f"entitysrc{suffix}.onion")
        session.add(s)
        session.flush()
        p = Page(url=f"http://entitysrc{suffix}.onion/p/1", source_id=s.id)
        session.add(p)
        session.flush()
        return p

    def test_create_wallet(self, session):
        from db.models import Entity, EntityType

        page = self._make_page(session, "wallet01")
        entity = Entity(
            page_id=page.id,
            entity_type=EntityType.CRYPTO_WALLET.value,
            value="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            confidence=0.98,
            context="Payment address listed in post body",
        )
        session.add(entity)
        session.flush()

        assert entity.id is not None
        assert entity.confidence == 0.98

    def test_create_handle(self, session):
        from db.models import Entity, EntityType

        page = self._make_page(session, "handle01")
        entity = Entity(
            page_id=page.id,
            entity_type=EntityType.HANDLE.value,
            value="darkactor99",
            confidence=0.9,
        )
        session.add(entity)
        session.flush()
        assert entity.entity_type == "handle"

    def test_default_confidence(self, session):
        from db.models import Entity

        page = self._make_page(session, "defconf01")
        entity = Entity(page_id=page.id, entity_type="cve", value="CVE-2024-12345")
        session.add(entity)
        session.flush()
        assert entity.confidence == 1.0

    def test_cascade_delete_with_page(self, session):
        from db.models import Entity, Page, Source

        s = Source(onion_address="cascadedel12345.onion")
        session.add(s)
        session.flush()
        p = Page(url="http://cascadedel12345.onion/p/1", source_id=s.id)
        session.add(p)
        session.flush()
        e = Entity(page_id=p.id, entity_type="email", value="test@example.com")
        session.add(e)
        session.flush()
        entity_id = e.id

        session.delete(p)
        session.flush()

        assert session.get(Entity, entity_id) is None

    def test_repr(self, session):
        from db.models import Entity

        page = self._make_page(session, "reprtest1")
        e = Entity(page_id=page.id, entity_type="handle", value="actor_x")
        session.add(e)
        session.flush()
        assert "handle" in repr(e)
        assert "actor_x" in repr(e)


# ---------------------------------------------------------------------------
# EntityRelationship model
# ---------------------------------------------------------------------------

class TestEntityRelationship:
    def _make_entities(self, session, suffix: str):
        from db.models import Source, Page, Entity

        s = Source(onion_address=f"relsrc{suffix}.onion")
        session.add(s)
        session.flush()
        p = Page(url=f"http://relsrc{suffix}.onion/p/1", source_id=s.id)
        session.add(p)
        session.flush()
        e1 = Entity(page_id=p.id, entity_type="handle", value=f"actor_{suffix}")
        e2 = Entity(page_id=p.id, entity_type="malware", value=f"Malware_{suffix}")
        session.add_all([e1, e2])
        session.flush()
        return e1, e2, p

    def test_create(self, session):
        from db.models import EntityRelationship, RelationshipType

        e1, e2, page = self._make_entities(session, "cr01")
        rel = EntityRelationship(
            entity_a_id=e1.id,
            entity_b_id=e2.id,
            relationship_type=RelationshipType.USES.value,
            source_page_id=page.id,
            confidence=0.85,
        )
        session.add(rel)
        session.flush()

        assert rel.id is not None
        assert rel.confidence == 0.85
        assert rel.relationship_type == "USES"

    def test_bidirectional_orm_access(self, session):
        from db.models import EntityRelationship

        e1, e2, page = self._make_entities(session, "bi01")
        rel = EntityRelationship(
            entity_a_id=e1.id,
            entity_b_id=e2.id,
            relationship_type="CO_APPEARED_ON",
            source_page_id=page.id,
        )
        session.add(rel)
        session.flush()

        assert rel.entity_a.value == e1.value
        assert rel.entity_b.value == e2.value
        assert rel.source_page.url == page.url

    def test_cascade_delete_with_entity(self, session):
        from db.models import Entity, EntityRelationship

        e1, e2, page = self._make_entities(session, "cas01")
        rel = EntityRelationship(
            entity_a_id=e1.id,
            entity_b_id=e2.id,
            relationship_type="LINKED_TO",
        )
        session.add(rel)
        session.flush()
        rel_id = rel.id

        session.delete(e1)
        session.flush()

        assert session.get(EntityRelationship, rel_id) is None

    def test_typed_relationship_dedup_is_scoped_to_investigation(self, session):
        from db.models import Entity, EntityRelationship, Investigation, Page
        from db.queries import save_typed_relationships

        prior = Investigation(query="prior typed relationship")
        current = Investigation(query="current typed relationship")
        session.add_all([prior, current])
        session.flush()

        page = Page(url="https://example.test/typed-scope")
        session.add(page)
        session.flush()
        source = Entity(
            page_id=page.id,
            entity_type="THREAT_ACTOR_HANDLE",
            value="LAUNDRY BEAR",
        )
        target = Entity(
            page_id=page.id,
            entity_type="ORGANIZATION_NAME",
            value="ZCS",
        )
        session.add_all([source, target])
        session.flush()

        session.add(
            EntityRelationship(
                entity_a_id=source.id,
                entity_b_id=target.id,
                relationship_type="TARGETS",
                investigation_id=prior.id,
                source_page_id=page.id,
                confidence=0.85,
            )
        )
        session.flush()

        relationship = {
            "entity_a_id": source.id,
            "entity_b_id": target.id,
            "relationship_type": "TARGETS",
            "confidence": 0.85,
            "source_page_id": page.id,
        }
        assert save_typed_relationships(session, current.id, [relationship]) == 1
        assert save_typed_relationships(session, current.id, [relationship]) == 0

        rows = (
            session.query(EntityRelationship)
            .filter_by(
                entity_a_id=source.id,
                entity_b_id=target.id,
                relationship_type="TARGETS",
            )
            .all()
        )
        assert {row.investigation_id for row in rows} == {prior.id, current.id}


# ---------------------------------------------------------------------------
# Investigation <-> Source junction
# ---------------------------------------------------------------------------

class TestInvestigationSourcesJunction:
    def test_link_source_to_investigation(self, session):
        from db.models import Investigation, Source

        inv = Investigation(query="junction test")
        source = Source(onion_address="junctiontest1234.onion")
        session.add_all([inv, source])
        session.flush()

        inv.sources.append(source)
        session.flush()

        fetched = session.get(Investigation, inv.id)
        assert len(fetched.sources) == 1
        assert fetched.sources[0].onion_address == "junctiontest1234.onion"

    def test_source_back_populates_investigations(self, session):
        from db.models import Investigation, Source

        inv = Investigation(query="back_pop test")
        source = Source(onion_address="backpoptest12345.onion")
        session.add_all([inv, source])
        session.flush()

        inv.sources.append(source)
        session.flush()

        fetched_source = session.get(Source, source.id)
        assert any(i.id == inv.id for i in fetched_source.investigations)

    def test_many_sources_per_investigation(self, session):
        from db.models import Investigation, Source

        inv = Investigation(query="multi source test")
        sources = [Source(onion_address=f"multisrc{i:04d}test.onion") for i in range(3)]
        session.add(inv)
        session.add_all(sources)
        session.flush()

        for s in sources:
            inv.sources.append(s)
        session.flush()

        fetched = session.get(Investigation, inv.id)
        assert len(fetched.sources) == 3


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

class TestSessionFactory:
    def test_get_engine_with_explicit_url(self, _db_engine):
        # _db_engine fixture already created and cached the engine with the schema.
        from db.session import get_engine

        engine = get_engine(TEST_URL)
        assert engine is not None
        # Engine should be the same cached instance — no dispose; fixture owns teardown.

    def test_get_engine_missing_url_raises(self, monkeypatch):
        """get_engine() with no URL and no DATABASE_URL env var must raise clearly."""
        import db.session as sess_module

        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setattr(sess_module, "DATABASE_URL", None)
        with pytest.raises(RuntimeError, match="DATABASE_URL"):
            sess_module.get_engine(url=None)

    def test_get_session_factory(self):
        from db.session import get_session_factory
        from sqlalchemy.orm import sessionmaker

        factory = get_session_factory(TEST_URL)
        assert isinstance(factory, sessionmaker)

    def test_context_manager_commits(self, _db_engine):
        # _db_engine fixture ensures the schema exists on the shared cached engine.
        from db.models import Investigation
        from db.session import get_session

        run_id = uuid.uuid4()
        with get_session(TEST_URL) as s:
            inv = Investigation(query="ctx mgr test", run_id=run_id)
            s.add(inv)
        # Session committed; open a new one to verify persistence
        with get_session(TEST_URL) as s:
            fetched = s.query(Investigation).filter_by(run_id=run_id).first()
            assert fetched is not None
            assert fetched.query == "ctx mgr test"

    def test_context_manager_rolls_back_on_error(self, _db_engine):
        from db.models import Investigation
        from db.session import get_session

        run_id = uuid.uuid4()
        with pytest.raises(ValueError):
            with get_session(TEST_URL) as s:
                s.add(Investigation(query="will rollback", run_id=run_id))
                raise ValueError("forced error")

        with get_session(TEST_URL) as s:
            fetched = s.query(Investigation).filter_by(run_id=run_id).first()
            assert fetched is None


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

class TestQueries:
    def test_db_health_check_true(self, session):
        from db.queries import db_health_check
        assert db_health_check(session) is True

    def test_db_health_check_false_on_execute_error(self, session):
        from db.queries import db_health_check
        from unittest.mock import MagicMock
        session.execute = MagicMock(side_effect=RuntimeError("db down"))
        assert db_health_check(session) is False

    def test_create_investigation(self, session):
        from db.queries import create_investigation

        inv = create_investigation(
            session,
            query="helper create test",
            model_used="gpt-4.1",
            preset="threat_intel",
        )
        assert inv.id is not None
        assert inv.query == "helper create test"
        assert inv.model_used == "gpt-4.1"

    def test_get_investigation_by_run_id_found(self, session):
        from db.queries import create_investigation, get_investigation_by_run_id

        inv = create_investigation(session, query="run id lookup")
        result = get_investigation_by_run_id(session, inv.run_id)
        assert result is not None
        assert result.id == inv.id

    def test_get_investigation_by_run_id_missing(self, session):
        from db.queries import get_investigation_by_run_id

        result = get_investigation_by_run_id(session, uuid.uuid4())
        assert result is None

    def test_get_recent_investigations_ordering(self, session):
        from datetime import timedelta
        from db.queries import create_investigation, get_recent_investigations  # noqa: PLC0415

        now = datetime.now(timezone.utc)
        older = create_investigation(session, query="oldest")
        older.created_at = now - timedelta(seconds=10)
        newer = create_investigation(session, query="newest")
        newer.created_at = now
        session.flush()

        results = get_recent_investigations(session, limit=2)
        assert results[0].query == "newest"

    def test_update_investigation_summary(self, session):
        from db.queries import create_investigation, update_investigation_summary

        inv = create_investigation(session, query="summary update test")
        update_investigation_summary(session, inv.id, "Updated summary text.")
        session.flush()
        session.refresh(inv)
        assert inv.summary == "Updated summary text."

    def test_get_or_create_source_new(self, session):
        from db.queries import get_or_create_source

        source, created = get_or_create_source(session, "newqsource1234.onion")
        assert created is True
        assert source.onion_address == "newqsource1234.onion"
        assert source.id is not None

    def test_get_or_create_source_existing(self, session):
        from db.queries import get_or_create_source

        get_or_create_source(session, "existingsrc123.onion")
        source, created = get_or_create_source(session, "existingsrc123.onion")
        assert created is False

    def test_update_source_status(self, session):
        from db.models import SourceStatus
        from db.queries import get_or_create_source, update_source_status

        source, _ = get_or_create_source(session, "statusupdate123.onion")
        update_source_status(session, source.id, SourceStatus.ACTIVE.value)
        session.flush()
        session.refresh(source)
        assert source.status == SourceStatus.ACTIVE.value

    def test_link_source_to_investigation(self, session):
        from db.queries import create_investigation, get_or_create_source, link_source_to_investigation

        inv = create_investigation(session, query="link test")
        source, _ = get_or_create_source(session, "linksrc1234567.onion")
        link_source_to_investigation(session, inv, source)
        session.flush()
        assert source in inv.sources

    def test_link_source_idempotent(self, session):
        from db.queries import create_investigation, get_or_create_source, link_source_to_investigation

        inv = create_investigation(session, query="idempotent link test")
        source, _ = get_or_create_source(session, "idempotent12345.onion")
        link_source_to_investigation(session, inv, source)
        link_source_to_investigation(session, inv, source)  # second call should be a no-op
        session.flush()
        assert len(inv.sources) == 1

    def test_create_page(self, session):
        from db.queries import create_page, get_or_create_source

        source, _ = get_or_create_source(session, "createpg12345.onion")
        page = create_page(
            session,
            url="http://createpg12345.onion/t/1",
            source_id=source.id,
            cleaned_text="threat actor discussion",
            raw_content_hash="c" * 64,
            byte_size=8192,
        )
        assert page.id is not None
        assert page.url == "http://createpg12345.onion/t/1"

    def test_get_page_by_url_found(self, session):
        from db.queries import create_page, get_page_by_url

        create_page(session, url="http://getpgbyurl123.onion/p/1")
        page = get_page_by_url(session, "http://getpgbyurl123.onion/p/1")
        assert page is not None

    def test_get_page_by_url_missing(self, session):
        from db.queries import get_page_by_url

        page = get_page_by_url(session, "http://doesnotexist.onion/x")
        assert page is None

    def test_get_page_by_hash_found(self, session):
        from db.queries import create_page, get_page_by_hash

        content_hash = "d" * 64
        create_page(session, url="http://getpghash12345.onion/p/1", raw_content_hash=content_hash)
        page = get_page_by_hash(session, content_hash)
        assert page is not None

    def test_get_page_by_hash_missing(self, session):
        from db.queries import get_page_by_hash

        page = get_page_by_hash(session, "0" * 64)
        assert page is None

    def test_get_pages_for_source(self, session):
        from db.queries import create_page, get_or_create_source, get_pages_for_source

        source, _ = get_or_create_source(session, "pgsforsrc12345.onion")
        create_page(session, url="http://pgsforsrc12345.onion/p/1", source_id=source.id)
        create_page(session, url="http://pgsforsrc12345.onion/p/2", source_id=source.id)

        pages = get_pages_for_source(session, source.id)
        assert len(pages) == 2

    def test_create_entity(self, session):
        from db.queries import create_page, create_entity

        page = create_page(session, url="http://entitycreate1.onion/p/1")
        entity = create_entity(
            session,
            page_id=page.id,
            entity_type="crypto_wallet",
            value="bc1qtestwalletaddress",
            confidence=0.97,
            context="Wallet mentioned in ransom note.",
        )
        assert entity.id is not None
        assert entity.confidence == 0.97

    def test_get_entities_by_type(self, session):
        from db.queries import create_page, create_entity, get_entities_by_type

        page = create_page(session, url="http://entbytype12345.onion/p/1")
        unique_type = f"test_type_{uuid.uuid4().hex[:8]}"
        create_entity(session, page_id=page.id, entity_type=unique_type, value="val1")
        create_entity(session, page_id=page.id, entity_type=unique_type, value="val2")

        results = get_entities_by_type(session, unique_type)
        assert len(results) == 2

    def test_get_entities_by_value(self, session):
        from db.queries import create_page, create_entity, get_entities_by_value

        page = create_page(session, url="http://entbyvalue12345.onion/p/1")
        unique_val = f"bc1q_unique_{uuid.uuid4().hex[:12]}"
        create_entity(session, page_id=page.id, entity_type="crypto_wallet", value=unique_val)

        results = get_entities_by_value(session, unique_val)
        assert len(results) == 1
        assert results[0].value == unique_val

    def test_get_entities_by_value_no_match(self, session):
        from db.queries import get_entities_by_value

        results = get_entities_by_value(session, "this_value_does_not_exist_xyz")
        assert results == []

    def test_get_entities_for_investigation(self, session):
        from db.queries import (
            create_entity,
            create_investigation,
            create_page,
            get_entities_for_investigation,
        )

        inv = create_investigation(session, query="entities for inv test")
        page = create_page(session, url="http://entforinv12345.onion/p/1")
        create_entity(session, page_id=page.id, entity_type="handle",
                      value="actor_a", investigation_id=inv.id)
        create_entity(session, page_id=page.id, entity_type="malware",
                      value="BadMalware", investigation_id=inv.id)

        all_results = get_entities_for_investigation(session, inv.id)
        assert len(all_results) == 2

        filtered = get_entities_for_investigation(session, inv.id, entity_type="handle")
        assert len(filtered) == 1
        assert filtered[0].value == "actor_a"

    def test_create_entity_relationship(self, session):
        from db.queries import create_entity, create_entity_relationship, create_page

        page = create_page(session, url="http://relcreate1234567.onion/p/1")
        e1 = create_entity(session, page_id=page.id, entity_type="handle", value="threat_actor_x")
        e2 = create_entity(session, page_id=page.id, entity_type="malware", value="Ransomware_Y")

        rel = create_entity_relationship(
            session,
            entity_a_id=e1.id,
            entity_b_id=e2.id,
            relationship_type="USES",
            source_page_id=page.id,
            confidence=0.9,
        )
        assert rel.id is not None
        assert rel.relationship_type == "USES"
        assert rel.confidence == 0.9

    def test_get_relationships_for_entity(self, session):
        from db.queries import (
            create_entity,
            create_entity_relationship,
            create_page,
            get_relationships_for_entity,
        )

        page = create_page(session, url="http://getrels12345678.onion/p/1")
        e1 = create_entity(session, page_id=page.id, entity_type="handle", value="actor_query")
        e2 = create_entity(session, page_id=page.id, entity_type="malware", value="Malware_Q")
        e3 = create_entity(session, page_id=page.id, entity_type="handle", value="alias_q")

        create_entity_relationship(session, e1.id, e2.id, "USES", page.id)
        create_entity_relationship(session, e3.id, e1.id, "LIKELY_SAME_ACTOR", page.id)

        rels = get_relationships_for_entity(session, e1.id)
        assert len(rels) == 2  # e1 appears as entity_a in first, entity_b in second


# ---------------------------------------------------------------------------
# Enum coverage
# ---------------------------------------------------------------------------

class TestEnums:
    def test_source_status_values(self):
        from db.models import SourceStatus
        assert SourceStatus.ACTIVE.value == "active"
        assert SourceStatus.DOWN.value == "down"
        assert SourceStatus.UNKNOWN.value == "unknown"

    def test_source_type_values(self):
        from db.models import SourceType
        assert SourceType.SEARCH_RESULT.value == "search_result"
        assert SourceType.CRAWLED.value == "crawled"
        assert SourceType.SEED.value == "seed"
        assert SourceType.TELEGRAM.value == "telegram"

    def test_entity_type_values(self):
        from db.models import EntityType
        expected = {
            "crypto_wallet", "email", "pgp_key", "onion_url", "cve",
            "ip_address", "phone", "handle", "malware", "ransomware_group",
            "domain", "other", "file_hash_md5", "file_hash_sha1",
            "file_hash_sha256", "mitre_technique",
        }
        actual = {e.value for e in EntityType}
        assert expected == actual

    def test_relationship_type_values(self):
        from db.models import RelationshipType
        expected = {
            "CO_APPEARED_ON", "POSTED_BY", "LINKED_TO", "PAID_TO",
            "MEMBER_OF", "USES", "CLAIMED", "LIKELY_SAME_ACTOR",
            "CONFIRMED_SAME_ACTOR", "FUNDED_BY", "POSSIBLE_SAME_AUTHOR",
            "DROPS", "CONTROLS", "TARGETS", "EXPLOITS", "COMMUNICATES_WITH",
        }
        actual = {r.value for r in RelationshipType}
        assert expected == actual
