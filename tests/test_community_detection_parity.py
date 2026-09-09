"""API/CLI community-detection parity checks."""

from __future__ import annotations

import datetime

import networkx as nx
from unittest.mock import MagicMock, patch
import uuid


def _grouping(partition: dict[str, int]) -> set[frozenset[str]]:
    groups: dict[int, set[str]] = {}
    for node_id, community_id in partition.items():
        groups.setdefault(community_id, set()).add(node_id)
    return {frozenset(nodes) for nodes in groups.values()}


def test_api_graph_adapter_matches_cli_graph_shape_for_detection():
    """The API adapter and CLI's simple Graph produce the same partition."""
    from api.routes.investigations import _detect_communities_for_graph
    from graph.builder import detect_communities

    api_graph = nx.MultiDiGraph()
    api_graph.add_edges_from(
        [
            ("actor-a", "malware-a"),
            ("malware-a", "infra-a"),
            ("infra-a", "actor-a"),
            ("actor-b", "malware-b"),
            ("malware-b", "infra-b"),
            ("infra-b", "actor-b"),
        ]
    )

    api_partition = _detect_communities_for_graph(api_graph)
    cli_graph = nx.Graph(api_graph)
    cli_partition = detect_communities(cli_graph)

    assert _grouping(api_partition) == _grouping(cli_partition)
    assert set(api_partition) == set(api_graph.nodes)


def test_api_detection_uses_complete_graph_not_display_slice():
    """Detection includes nodes beyond the graph endpoint's display limit."""
    from api.routes.investigations import _detect_communities_for_graph

    graph = nx.MultiDiGraph()
    graph.add_edges_from((f"node-{i}", f"node-{i + 1}") for i in range(5))

    partition = _detect_communities_for_graph(graph)

    assert set(partition) == {f"node-{i}" for i in range(6)}


async def test_api_graph_phase_detects_before_returning_to_finalize():
    """The API graph phase invokes detection after persistence, pre-finalize."""
    from api.routes import investigations

    graph = nx.MultiDiGraph()
    graph.add_edges_from(
        [("actor", "malware"), ("malware", "infra"), ("infra", "actor")]
    )
    events: list[str] = []
    session = MagicMock()
    session_context = MagicMock()
    session_context.__enter__.return_value = session
    session_context.__exit__.return_value = False

    with (
        patch("graph.builder.build_graph_from_db", return_value=graph),
        patch("graph.builder.infer_relationships", side_effect=lambda value: value),
        patch(
            "api.routes.investigations._persist_graph_edges_sync",
            side_effect=lambda *_args: (
                events.append("persist") or {"status": "written", "edges_written": 3}
            ),
        ),
        patch(
            "api.routes.investigations._detect_communities_for_graph",
            side_effect=lambda _graph: (events.append("detect") or {"actor": 0, "malware": 0, "infra": 0}),
        ),
        patch(
            "api.routes.investigations._set_communities",
            side_effect=lambda *_args: events.append("store"),
        ),
        patch("db.session.get_session", return_value=session_context),
    ):
        result = await investigations._build_graph_phase(
            [], uuid.uuid4(), uuid.uuid4()
        )

    assert result is True
    assert events == ["persist", "detect", "store"]


def _groups_by_entity(partition):
    """Group entity ids by community id -> set of frozensets (grouping identity)."""
    groups = {}
    for node_id, community_id in partition.items():
        groups.setdefault(community_id, set()).add(str(node_id))
    return {frozenset(nodes) for nodes in groups.values()}


def test_cli_investigation_partition_matches_api_canonical_grouping(db_engine):
    """End-to-end construction parity: the CLI's per-investigation community
    partition must group the same entities as the API's canonical graph
    partition for the same investigation.

    This is the invariant the audit repeatedly flagged: the two surfaces used
    to build *different graphs* (CLI = one node per entity UUID over persisted
    relationships; API = one node per canonical ``entity_graph_id`` over
    page-derived, semantically-filtered co-occurrence).  The algorithm-level
    parity test above never caught it because it fed both sides the *same*
    graph.  Here we build a real investigation and assert the groupings agree.
    """
    from db.session import get_session
    from db.models import (
        Investigation,
        Page,
        Entity,
        EntityRelationship,
    )
    from extractor.identity import entity_graph_id
    from graph.builder import build_graph_from_db
    from api.routes.investigations import _detect_communities_for_graph
    from ezio_cli.commands.investigate import (
        _detect_communities_for_investigation,
    )

    inv_id = uuid.uuid4()
    page_a, page_b = uuid.uuid4(), uuid.uuid4()
    now = datetime.datetime.now(datetime.timezone.utc)
    ids = {name: uuid.uuid4() for name in ("e1", "e2", "e3", "e4")}

    def _entity(eid, etype, value, page_id):
        return Entity(
            id=eid,
            page_id=page_id,
            investigation_id=inv_id,
            entity_type=etype,
            value=value,
            confidence=0.9,
            canonical_value=value.lower(),
            extraction_method="regex",
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
        )

    with get_session() as session:
        session.add(
            Investigation(
                id=inv_id, query="q", status="completed",
                created_at=now, entity_count=4, page_count=2,
            )
        )
        session.add(Page(id=page_a, url="http://a.onion", cleaned_text="a",
                         scrape_timestamp=now, created_at=now))
        session.add(Page(id=page_b, url="http://b.onion", cleaned_text="b",
                         scrape_timestamp=now, created_at=now))
        # Page A: e1,e2,e3 ; Page B: e3,e4 (e3 bridges the two pages)
        session.add(_entity(ids["e1"], "THREAT_ACTOR_HANDLE", "Actor1", page_a))
        session.add(_entity(ids["e2"], "MALWARE_FAMILY", "Mal2", page_a))
        session.add(_entity(ids["e3"], "IP_ADDRESS", "1.2.3.3", page_a))
        session.add(_entity(ids["e4"], "IP_ADDRESS", "1.2.3.4", page_b))
        # Persisted CO_APPEARED_ON rows (what the OLD CLI graph consumed).
        for a, b in [("e1", "e2"), ("e1", "e3"), ("e2", "e3"), ("e3", "e4")]:
            session.add(EntityRelationship(
                id=uuid.uuid4(), entity_a_id=ids[a], entity_b_id=ids[b],
                relationship_type="CO_APPEARED_ON", confidence=0.5,
                investigation_id=inv_id, source_page_id=page_a, first_seen=now,
            ))
        session.add(EntityRelationship(
            id=uuid.uuid4(), entity_a_id=ids["e1"], entity_b_id=ids["e4"],
            relationship_type="USES", confidence=0.9,
            investigation_id=inv_id, first_seen=now,
        ))
        session.commit()

    cli_partition = _detect_communities_for_investigation(str(inv_id))

    graph = build_graph_from_db(investigation_id=inv_id)
    api_partition = _detect_communities_for_graph(graph)
    with get_session() as session:
        entities = (
            session.query(Entity)
            .filter(Entity.investigation_id == inv_id)
            .all()
        )
        api_by_entity = {
            str(e.id): api_partition[entity_graph_id(e)]
            for e in entities
            if entity_graph_id(e) in api_partition
        }

    # The CLI mapping must actually populate (proves entity_graph_id aligns with
    # the builder's node ids — a silent drift here would empty the partition).
    assert cli_partition, "CLI partition unexpectedly empty"
    assert set(cli_partition) == set(api_by_entity)
    assert _groups_by_entity(cli_partition) == _groups_by_entity(api_by_entity)
