"""
extractor/identity.py — The single source of truth for entity identity strings.

There are three distinct questions the rest of the codebase asks about an
entity, and historically each was answered independently in six-plus places
with subtly different rules.  Those answers disagreed — most visibly the STIX
export bug where the graph builder keyed nodes by the raw-case value while the
exporter looked them up by a lowercased canonical value, silently dropping
every threat-actor relationship.  This module collapses all three questions
into three functions so nothing downstream can drift:

    entity_graph_id(entity)     → the key used to identify this entity as a
                                  node in the relationship graph.  Exporters
                                  use this to resolve "which graph node does
                                  this entity correspond to."

    entity_canonical_id(entity) → the deduplication-safe canonical form used
                                  for "are these two entities the same thing",
                                  DB uniqueness, and cross-source matching.

    entity_display_id(entity)   → the string a human should see, preserving
                                  original casing/formatting.

Every function accepts either representation of an entity in use in this
codebase — the DB-backed ``Entity`` ORM object or the in-pipeline
``NormalizedEntity`` dataclass — and returns the identical, correct answer for
either, regardless of source.  They rely only on ``entity_type`` and ``value``
(the raw value), plus a best-effort source URL, so they never depend on the
``canonical_value`` attribute (which historically meant different things on the
two representations).

NOTE (Phase 1): no existing caller is migrated to these functions yet.  This
module is produced and proven correct in isolation; the migration of the graph
builder, STIX/MISP/Sigma/IOC exporters and the entity lookup API is Phase 2.
"""

from __future__ import annotations

from urllib.parse import urlparse

from extractor.normalizer import canonicalize_entity_value

# Entity types that are disambiguated by their source forum in the graph.  The
# same handle seen on two different forums produces two distinct nodes, which
# is what enables the LIKELY_SAME_ACTOR inference pass.  This mirrors the
# type-specific handling that already lives in ``graph.builder._make_node_id``.
_FORUM_DISAMBIGUATED_TYPES = frozenset({"THREAT_ACTOR_HANDLE"})


def _extract_domain(url: str) -> str:
    """Return the netloc (hostname) of *url*, or "" on failure.

    Matches ``graph.builder._extract_domain`` exactly so the graph id produced
    here is byte-for-byte compatible with the graph builder's node ids when
    Phase 2 wires the builder to call this module.
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc or ""
    except Exception:
        return ""


def _entity_source_url(entity) -> str:
    """Best-effort source URL for either entity representation.

    ``NormalizedEntity`` carries ``source_url`` directly.  The DB-backed
    ``Entity`` ORM object carries it indirectly via ``entity.page.url``.  Only
    the forum-disambiguated types actually consult this, so a missing/detached
    page degrades gracefully to "" (an un-disambiguated graph id) rather than
    raising.
    """
    url = getattr(entity, "source_url", None)
    if url:
        return url
    try:
        page = getattr(entity, "page", None)
        if page is not None:
            page_url = getattr(page, "url", None)
            if page_url:
                return page_url
    except Exception:
        # A detached ORM object can raise on lazy-loading page; treat as no URL.
        pass
    return ""


def _identity_entity_type(entity) -> str:
    """Read and normalize the type from either a dict or entity object."""
    if isinstance(entity, dict):
        return str(entity.get("entity_type") or entity.get("type") or "").strip().upper()
    return str(getattr(entity, "entity_type", "") or "").strip().upper()


def _identity_raw_value(entity) -> str:
    if isinstance(entity, dict):
        return str(entity.get("value") or entity.get("raw_value") or "")
    return str(getattr(entity, "value", "") or "")


def entity_canonical_id(entity) -> str:
    """Return the canonical, deduplication-safe form of *entity*'s value.

    This is the form used for identity comparisons ("are these the same
    thing"), database uniqueness, and cross-source corroboration.  It calls
    ``canonicalize_entity_value()`` directly on the *raw* value rather than
    trusting any ``canonical_value`` attribute, so it produces the identical
    result whether handed a DB ``Entity`` or an in-pipeline ``NormalizedEntity``
    — even when the two were created with different casing.
    """
    return canonicalize_entity_value(
        _identity_entity_type(entity), _identity_raw_value(entity)
    )


def entity_graph_id(entity) -> str:
    """Return the string used to key *entity* as a node in the relationship graph.

    This is the single function the graph builder should use to generate node
    ids, and the single function every exporter should use to resolve which
    graph node an entity corresponds to.

    The identity basis is the *canonical* value (via ``entity_canonical_id``),
    not the raw value.  That is the fix for the original class of bug: keying
    on the raw value meant "LockBit" and "lockbit" produced two different graph
    nodes, so an exporter that resolved by canonical value could never find the
    node the builder created.  Canonicalising here guarantees the same entity
    always maps to the same node id regardless of the casing it was observed in.

    The forum-disambiguation special case for threat-actor handles is preserved:
    a handle is keyed as ``"<canonical>@<domain>"`` so the same handle on two
    forums yields two nodes.  All other types are keyed by canonical value alone.
    """
    canonical = entity_canonical_id(entity)
    if _identity_entity_type(entity) in _FORUM_DISAMBIGUATED_TYPES:
        domain = _extract_domain(_entity_source_url(entity))
        if domain:
            return f"{canonical}@{domain.lower()}"
    return canonical


def entity_display_id(entity) -> str:
    """Return the string a human should see for *entity*.

    Distinct from both the graph key and the canonical dedup key: it preserves
    the original casing and formatting of the observed value (stripped of
    surrounding whitespace only).  Conflating this with the lookup keys is the
    direct cause of the IOC-package casing inconsistency, so it is deliberately
    kept separate.
    """
    return _identity_raw_value(entity).strip()
