"""
export/_entity_loading.py — one shared DB-row → NormalizedEntity mapping for
every exporter.

Previously STIX, MISP, and Sigma each reconstructed a ``NormalizedEntity`` from
a DB ``Entity`` row independently, and populated *different* fields — STIX set
``source_quality`` and ``extraction_method``, MISP and Sigma did not.  A future
consumer reading ``entity.source_quality`` therefore got different behaviour
depending on which export path produced the entity (audit finding: STIX/MISP
field divergence).  Centralising the construction here closes that drift: all
three exporters now produce identically-populated entities.

The value mapping is preserved exactly as it was in all three call sites
(``canonical_value or value``) so export outputs are unchanged; only the
previously-inconsistent auxiliary fields are now uniform.
"""

from __future__ import annotations

from typing import Any

from extractor.normalizer import NormalizedEntity


def normalized_entity_from_db_row(e: Any) -> NormalizedEntity:
    """Build a NormalizedEntity from a DB Entity row with consistent fields.

    Used by every exporter (STIX / MISP / Sigma) so field population can never
    drift between export paths again.
    """
    source_url = ""
    try:
        if e.page:
            source_url = e.page.url or ""
    except Exception:
        pass
    return NormalizedEntity(
        entity_type=e.entity_type,
        value=e.canonical_value or e.value,
        confidence=e.confidence,
        source_url=source_url,
        page_id=e.page_id,
        context_snippet=e.context_snippet or "",
        extraction_method="db",
        source_quality=getattr(e, "source_quality", 1.0),
    )
