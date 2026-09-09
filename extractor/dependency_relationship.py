"""Conservative, dependency-parser relationship extraction for no-LLM runs.

This module deliberately handles only a small, high-confidence slice of
subject/verb/object prose.  Entity candidates are supplied by the existing
regex/NER/gazetteer tiers; spaCy is used for syntax, not for inventing a new
entity vocabulary.  The result is value-based because the scraper runs before
database entity IDs exist.  The pipeline resolves those values back to its
normalized entities before persisting anything.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

from extractor.relationship_extract import (
    _PASSIVE_REL_VOCAB,
    _is_compatible_relationship,
)
from graph.model import RELATIONSHIP_TYPE_COMPATIBILITY

logger = logging.getLogger(__name__)

_SPACY_MODEL = "en_core_web_sm"
_NLP = None
_NLP_ATTEMPTED = False

# These are observed lemmas, but a lemma is never sufficient by itself.  The
# endpoint types below are consulted at the same time as the dependency
# structure and then passed through the canonical compatibility gate.
_VERB_LEMMAS: dict[str, tuple[str, ...]] = {
    "use": ("USES",),
    "control": ("USES", "CONTROLS"),
    "operate": ("USES",),
    "leverage": ("USES", "EXPLOITS"),
    "rely": ("USES",),
    "run": ("USES",),
    "execute": ("DROPS",),
    "download": ("DROPS",),
    "inject": ("DROPS",),
    "install": ("DROPS",),
    "drop": ("DROPS",),
    "deploy": ("DROPS",),
    "target": ("TARGETS",),
    "compromise": ("TARGETS",),
    "attack": ("TARGETS",),
    "infect": ("TARGETS",),
    "exploit": ("EXPLOITS",),
    "manipulate": ("EXPLOITS",),
    "bypass": ("EXPLOITS",),
    "establish": ("COMMUNICATES_WITH",),
    "signal": ("COMMUNICATES_WITH",),
    "connect": ("COMMUNICATES_WITH",),
    "send": ("COMMUNICATES_WITH",),
    "call": ("COMMUNICATES_WITH",),
    "contact": ("COMMUNICATES_WITH",),
}

# Passive syntax is directionally inverted: ``Acme was targeted by LockBit``
# is stored as LockBit TARGETS Acme.  The two existing serialized labels are
# retained, and base lemmas are added for ordinary prose parsed by spaCy.
_PASSIVE_BASE_RELATIONSHIPS: dict[str, str] = {
    "target": "TARGETS",
    "control": "CONTROLS",
    "use": "USES",
    "drop": "DROPS",
    "execute": "DROPS",
    "download": "DROPS",
    "inject": "DROPS",
    "install": "DROPS",
    "deploy": "DROPS",
    "exploit": "EXPLOITS",
    "manipulate": "EXPLOITS",
    "bypass": "EXPLOITS",
    "establish": "COMMUNICATES_WITH",
    "signal": "COMMUNICATES_WITH",
    "connect": "COMMUNICATES_WITH",
    "send": "COMMUNICATES_WITH",
    "call": "COMMUNICATES_WITH",
    "contact": "COMMUNICATES_WITH",
}


def _load_nlp():
    """Load spaCy lazily so scraping still works without its model."""
    global _NLP, _NLP_ATTEMPTED
    if _NLP_ATTEMPTED:
        return _NLP
    _NLP_ATTEMPTED = True
    try:
        import spacy

        _NLP = spacy.load(_SPACY_MODEL)
        return _NLP
    except Exception as exc:  # model/package absence is an optional degrade
        logger.debug("Dependency relationship extraction unavailable: %s", exc)
        return None


def _entity_type(entity: dict[str, Any]) -> str:
    return str(entity.get("type", "") or "").strip().upper()


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def _find_entity_spans(doc, entities: Iterable[dict[str, Any]]) -> list[tuple[Any, dict[str, Any]]]:
    """Find supplied entity values in the parsed text, preferring long spans."""
    text = doc.text
    found: list[tuple[Any, dict[str, Any]]] = []
    occupied: list[tuple[int, int]] = []
    candidates = sorted(
        (e for e in entities if e.get("value") and _entity_type(e)),
        key=lambda e: len(str(e.get("value", ""))),
        reverse=True,
    )
    for entity in candidates:
        value = str(entity["value"])
        pattern = re.compile(r"(?<!\w)" + re.escape(value) + r"(?!\w)", re.IGNORECASE)
        for match in pattern.finditer(text):
            if any(
                match.start() < end
                and match.end() > start
                and (match.start(), match.end()) != (start, end)
                for start, end in occupied
            ):
                continue
            span = doc.char_span(match.start(), match.end(), alignment_mode="expand")
            if span is None or span.start == span.end:
                continue
            occupied.append((match.start(), match.end()))
            found.append((span, entity))
    return found


def _entities_for_token(token_index: int, spans: list[tuple[Any, dict[str, Any]]]) -> list[dict[str, Any]]:
    return [
        entity
        for span, entity in spans
        if span.start <= token_index < span.end
    ]


def _pobj_entities(verb, spans: list[tuple[Any, dict[str, Any]]]) -> list[dict[str, Any]]:
    """Return entities under a relationship-bearing prepositional object."""
    allowed_preps = {"with", "to", "on", "against", "into", "at", "for", "of"}
    result: list[dict[str, Any]] = []
    for child in verb.children:
        if child.dep_ not in {"prep", "agent"}:
            continue
        if child.dep_ == "prep" and child.lower_ not in allowed_preps:
            continue
        for descendant in child.subtree:
            result.extend(_entities_for_token(descendant.i, spans))
    return result


def _object_entities(verb, spans: list[tuple[Any, dict[str, Any]]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for child in verb.children:
        if child.dep_ in {"obj", "dobj", "attr", "oprd"}:
            for descendant in child.subtree:
                result.extend(_entities_for_token(descendant.i, spans))
    result.extend(_pobj_entities(verb, spans))
    return result


def _agent_entities(verb, spans: list[tuple[Any, dict[str, Any]]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for child in verb.children:
        if child.dep_ == "agent" or (child.dep_ == "prep" and child.lower_ == "by"):
            for descendant in child.subtree:
                result.extend(_entities_for_token(descendant.i, spans))
    return result


def _relationship_for_types(lemma: str, source: dict[str, Any], target: dict[str, Any]) -> str | None:
    """Choose a relationship using lemma + endpoint types, never lemma alone."""
    source_type = _entity_type(source)
    target_type = _entity_type(target)
    for rel_type in _VERB_LEMMAS.get(lemma, ()):
        source_types, target_types = RELATIONSHIP_TYPE_COMPATIBILITY.get(rel_type, (frozenset(), frozenset()))
        if source_type in source_types and target_type in target_types:
            # Keep the same post-selection gate used by the LLM extractor.
            if _is_compatible_relationship(rel_type, source, target):
                return rel_type
    return None


def _passive_relationship(lemma: str) -> str | None:
    if lemma in _PASSIVE_BASE_RELATIONSHIPS:
        return _PASSIVE_BASE_RELATIONSHIPS[lemma]
    return _PASSIVE_REL_VOCAB.get(lemma)


def extract_dependency_relationships(page_text: str, entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract conservative typed claims from full page text.

    Each claim contains source/target values and normalized Ezio types;
    IDs are intentionally absent until the entity pipeline has persisted them.
    """
    if not page_text or len(entities) < 2:
        return []
    nlp = _load_nlp()
    if nlp is None:
        return []
    try:
        doc = nlp(page_text)
        spans = _find_entity_spans(doc, entities)
    except Exception as exc:
        logger.debug("Dependency relationship parse failed: %s", exc)
        return []
    if len(spans) < 2:
        return []

    seen: set[tuple[str, str, str]] = set()
    output: list[dict[str, Any]] = []
    for verb in doc:
        if getattr(verb, "pos_", "") not in {"VERB", "AUX"}:
            continue
        lemma = str(getattr(verb, "lemma_", "") or verb.text).casefold()
        subjects: list[dict[str, Any]] = []
        for child in verb.children:
            if child.dep_ in {"nsubj", "nsubjpass", "nsubj:pass"}:
                for descendant in child.subtree:
                    subjects.extend(_entities_for_token(descendant.i, spans))
        if not subjects:
            continue

        passive = any(child.dep_ in {"nsubjpass", "nsubj:pass"} for child in verb.children)
        if passive:
            # Patient is the syntactic subject; the explicit agent is the
            # semantic source.  Abstain when the prose omits the agent.
            targets = subjects
            sources = _agent_entities(verb, spans)
            rel_type = _passive_relationship(lemma)
            if not rel_type:
                continue
            confidence = 0.85
        else:
            sources = subjects
            targets = _object_entities(verb, spans)
            rel_type = None
            confidence = 0.9

        for source in sources:
            for target in targets:
                if source is target or _norm(source.get("value")) == _norm(target.get("value")):
                    continue
                if passive:
                    source, target = source, target
                    # Passive relation type is fixed by the verb, but endpoint
                    # compatibility still decides whether it is admissible.
                    if not _is_compatible_relationship(rel_type, source, target):
                        continue
                else:
                    rel_type = _relationship_for_types(lemma, source, target)
                    if not rel_type:
                        continue
                sentence = verb.sent.text.strip() if getattr(verb, "sent", None) is not None else ""
                key = (_norm(source.get("value")), _norm(target.get("value")), rel_type)
                if key in seen:
                    continue
                seen.add(key)
                output.append(
                    {
                        "source_value": source.get("value"),
                        "source_type": _entity_type(source),
                        "target_value": target.get("value"),
                        "target_type": _entity_type(target),
                        "relationship_type": rel_type,
                        "confidence": confidence,
                        "sentence": sentence,
                    }
                )
    return output


def extract_dependency_relationships_from_page(page_text: str) -> list[dict[str, Any]]:
    """Run the same existing regex/NER candidate tiers used by the scraper.

    This adapter is for source connectors that already fetched page text and
    therefore do not pass through ``scraper._fetch_one_impl``.  It intentionally
    does not add a second entity recognizer or an LLM tier.
    """
    if not page_text:
        return []
    from extractor.ner import extract_named_entities
    from extractor.regex_patterns import extract_all

    candidates_by_type = extract_all(page_text)
    ner_candidates = extract_named_entities(page_text)
    for entity_type, values in ner_candidates.items():
        candidates_by_type.setdefault(entity_type, [])
        candidates_by_type[entity_type].extend(values)

    candidate_entities: list[dict[str, Any]] = []
    seen_candidates: set[tuple[str, str]] = set()
    for entity_type, values in candidates_by_type.items():
        for value in values:
            key = (str(entity_type).upper(), str(value).casefold())
            if key in seen_candidates or not value:
                continue
            seen_candidates.add(key)
            candidate_entities.append({"type": entity_type, "value": value})
    return extract_dependency_relationships(page_text, candidate_entities)


__all__ = [
    "extract_dependency_relationships",
    "extract_dependency_relationships_from_page",
]
