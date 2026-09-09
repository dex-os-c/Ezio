"""
extractor/confidence.py — Computed, continuous entity confidence.

Confidence used to be a lookup table: an entity got ~1.0 / 0.9 / 0.82 based only
on which tier (regex / NER / LLM) produced it and its type.  Two entities of the
same type from the same method scored identically no matter how much evidence
actually backed each one, so ranking in the UI and exports effectively just
sorted by extraction method.

This module computes confidence from the real signals available at extraction
time, with extraction method as *one* input rather than the sole determinant:

  * validation strength — did the value pass a real check?  A checksum-verified
    wallet outranks a shape-only match; a format-verified IOC (CVE, hash, onion)
    outranks an unvalidated guess; a name matched in the known-good gazetteer
    outranks one accepted on shape alone.
  * shape plausibility — the continuous [0,1] score from ``entity_shape`` for
    name-type entities.
  * context support — does the surrounding text carry keywords consistent with
    the entity type being claimed.
  * method reliability — a modest prior per tier.

Corroboration (how many independent sources observed the same value) is folded
in later, at the batch cap stage, because it isn't known per-page — see
``extractor.pipeline.apply_entity_cap``.

The result is a genuinely differentiated value per extraction, not a category.
Every function is total and never raises.

Confidence is monotonic after extraction: new evidence may raise an entity's
stored confidence, but never lowers it.  ``get_entity_confidence`` is the
single read/merge helper for persisted or in-memory entity objects.
"""

from __future__ import annotations

# Method reliability prior — one input among several, deliberately modest so it
# never dominates a strong/weak validation signal.
_METHOD_PRIOR = {
    "regex": 0.86,
    "NER": 0.74,
    "LLM": 0.75,
}
_DEFAULT_PRIOR = 0.74

# Validation-strength adjustment.  "checksum"/"format" apply to regex IOCs;
# the gazetteer/shape_* tiers come straight from entity_shape.ShapeVerdict.tier.
_VALIDATION_BONUS = {
    "checksum_verified": 0.12,
    "format_verified": 0.08,
    "gazetteer": 0.10,
    "shape_strong": 0.06,
    "shape_ok": -0.02,
    "shape_weak": -0.14,
    # Non-shape NER/LLM types (PERSON_NAME, LOCATION, DATE) that passed the
    # light structural check — modest positive so a clean extraction lands just
    # above the retention floor, matching their prior tier-3 treatment.
    "heuristic_ok": 0.07,
    "unvalidated": 0.0,
}

# Type-appropriate context keywords — presence near the entity is weak positive
# evidence that the claimed type is correct.
_CONTEXT_KEYWORDS = {
    "THREAT_ACTOR_HANDLE": (
        "posted", "user", "alias", "handle", "nick", "author", "operator",
        "group", "gang", "actor", "member", "admin of", "aka", "known as",
        "ransom", "leak", "forum", "thread", "seller", "vendor",
    ),
    "ORGANIZATION_NAME": (
        "breach", "breached", "hacked", "victim", "leaked", "compromised",
        "ransom", "extorted", "encrypted", "data of", "customer", "employees",
        "attack on", "targeting", "stolen from",
    ),
    "MALWARE_FAMILY": (
        "malware", "payload", "sample", "c2", "command and control", "infection",
        "dropper", "loader", "trojan", "backdoor", "stealer", "ransomware",
        "variant", "family", "campaign",
    ),
    "RANSOMWARE_GROUP": (
        "ransom", "ransomware", "leak site", "victim", "encrypted", "decryptor",
        "double extortion", "affiliate", "raas", "gang", "group",
    ),
}

_SHAPE_VALIDATED_TYPES = frozenset(_CONTEXT_KEYWORDS.keys())


def context_supports(entity_type: str, context_text: str | None) -> bool:
    """True if *context_text* contains a keyword consistent with *entity_type*."""
    if not context_text:
        return False
    kws = _CONTEXT_KEYWORDS.get(entity_type)
    if not kws:
        return False
    low = context_text.lower()
    return any(kw in low for kw in kws)


def compute_confidence(
    entity_type: str,
    extraction_method: str,
    validation: str = "unvalidated",
    shape_score: float | None = None,
    context_support: bool = False,
) -> float:
    """Compute a continuous confidence in [0.05, 0.99].

    Args:
        entity_type: the entity type.
        extraction_method: "regex" | "NER" | "LLM".
        validation: one of the keys in ``_VALIDATION_BONUS`` — for regex IOCs
            pass "checksum_verified"/"format_verified"; for shape-validated name
            types pass the ShapeVerdict.tier ("gazetteer"/"shape_strong"/...).
        shape_score: the continuous plausibility from entity_shape (name types).
        context_support: whether surrounding text supports the claimed type.
    """
    try:
        score = _METHOD_PRIOR.get(extraction_method, _DEFAULT_PRIOR)
        score += _VALIDATION_BONUS.get(validation, 0.0)
        if shape_score is not None:
            # Centre on 0.6 so a middling shape is neutral; strong shape lifts,
            # weak shape drags — a continuous contribution, not a step.
            score += (float(shape_score) - 0.6) * 0.15
        if context_support:
            score += 0.04
        return max(0.05, min(0.99, score))
    except Exception:  # noqa: BLE001
        return 0.6


def get_entity_confidence(entity, candidate: float | None = None) -> float:
    """Return the canonical confidence, optionally merging new evidence.

    The monotonic max rule is shared by extraction batches, database upserts,
    and downstream consumers.  Values are always clamped to ``[0.0, 1.0]``.
    """
    try:
        current = float(getattr(entity, "confidence", entity) or 0.0)
        current = max(0.0, min(1.0, current))
        if candidate is None:
            return current
        return max(current, max(0.0, min(1.0, float(candidate))))
    except (TypeError, ValueError, AttributeError):
        return 0.0


def apply_evidence(entity, *signals: float) -> float:
    """Raise an entity confidence from additive evidence without compounding."""
    try:
        evidence = sum(max(0.0, float(signal)) for signal in signals)
    except (TypeError, ValueError):
        evidence = 0.0
    value = min(1.0, get_entity_confidence(entity) + evidence)
    entity.confidence = get_entity_confidence(entity, value)
    return entity.confidence


def corroboration_boost(distinct_sources: int) -> float:
    """Confidence lift from independent corroboration.

    A single-source observation gets nothing; each additional independent source
    adds evidence, saturating so a flood of one repeated value can't max out
    confidence on its own.  Applied at the batch cap stage where the cross-page
    source count is known.
    """
    try:
        n = max(1, int(distinct_sources))
    except Exception:  # noqa: BLE001
        n = 1
    return min(0.04 * (n - 1), 0.12)


def regex_validation_tier(entity_type: str, checksum_verified: bool = False) -> str:
    """Map a regex-extracted IOC type to a validation tier.

    Regex IOC patterns enforce a precise structural format, so they are at least
    "format_verified"; a genuine cryptographic/checksum verification (e.g. an
    EIP-55 Ethereum address) is stronger still.
    """
    if checksum_verified:
        return "checksum_verified"
    return "format_verified"


def is_shape_validated_type(entity_type: str) -> bool:
    return entity_type in _SHAPE_VALIDATED_TYPES
