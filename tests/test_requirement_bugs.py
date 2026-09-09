from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker


def test_entity_path_persists_cleaned_page_text(db_engine, monkeypatch):
    from db.models import Page
    from db.queries import create_investigation
    from extractor.normalizer import NormalizedEntity, merge_with_db

    db_url = str(db_engine.url)
    monkeypatch.setenv("DATABASE_URL", db_url)
    import db.session as session_module

    monkeypatch.setattr(session_module, "DATABASE_URL", db_url)
    session_module._get_engine_cached.cache_clear()

    with sessionmaker(bind=db_engine, autoflush=False)() as session:
        investigation = create_investigation(session, query="page text test")
        investigation_id = investigation.id
        session.commit()

    entity = NormalizedEntity(
        entity_type="CVE_NUMBER",
        value="CVE-2026-42897",
        confidence=0.99,
        source_url="https://example.test/rss/article",
        page_id=None,
        cleaned_text="LAUNDRY BEAR exploits CVE-2026-42897.",
    )

    ids = merge_with_db([entity], investigation_id)
    assert len(ids) == 1 and ids[0]

    with sessionmaker(bind=db_engine, autoflush=False)() as session:
        page = session.query(Page).filter_by(url=entity.source_url).one()
        assert page.cleaned_text == entity.cleaned_text


def test_dependency_claim_resolution_falls_back_to_validated_global_entity():
    from extractor.pipeline import _resolve_dependency_relationship_endpoint

    validated_entity = SimpleNamespace(
        entity_type="CVE_NUMBER",
        value="CVE-2026-42897",
    )
    pair = (validated_entity, "entity-cve-id")

    resolved = _resolve_dependency_relationship_endpoint(
        page_entities={},
        all_entities={("CVE_NUMBER", "cve-2026-42897"): pair},
        entity_type="CVE",
        value="CVE-2026-42897",
    )

    assert resolved == pair


def test_stale_schema_fails_before_investigation(tmp_path, monkeypatch):
    from db.models import Base
    from ezio_cli.adapters import sqlite as sqlite_adapter

    db_path = tmp_path / "stale.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE entities DROP COLUMN investigation_count"))

    monkeypatch.setenv("EZIO_DB_PATH", str(db_path))
    import db.session as session_module

    session_module._get_engine_cached.cache_clear()
    with pytest.raises(sqlite_adapter.DatabaseSchemaError, match="entities.investigation_count"):
        sqlite_adapter.validate_schema()
