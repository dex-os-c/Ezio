"""Conservative software/product suppression for organization candidates.

Option A deliberately does not create a software entity type.  This module only
answers whether an ``ORGANIZATION_NAME`` candidate is too likely to be a
software/product mention to persist in that bucket.

The deterministic set is intentionally small and high precision.  CPE-backed
suppression is implemented separately and remains a partial, best-effort signal
because CPE is a product/version catalog rather than an informal-name gazetteer.
"""

from __future__ import annotations

import re
import unicodedata
import asyncio
from collections.abc import Iterable, Mapping
from typing import Any


# High-confidence names observed in real investigations or commonly emitted by
# security prose.  These are suppression names, not a positive software
# taxonomy; organization context always wins over this set.
_CURATED_SOFTWARE_PRODUCTS = frozenset({
    "amazon aws govcloud",
    "aws",
    "cisco ios software",
    "clamav",
    "cubepilot",
    "github",
    "headlesschrome",
    "log4j",
    "metasploit",
    "powershell",
    "pypi",
    "snort",
    "vbulletin",
    "vmware",
    "wordpress",
    "xe software",
    "zcs",
    "zimbra collaboration suite",
    "zimbraaccount",
    "zimbraweb",
})

# Exact names which are unambiguously organizations in the threat-intel prose
# this project handles.  This is deliberately not a general organization
# gazetteer; it protects well-known agency/company names while the structural
# gate becomes stricter for unknown acronyms.
_RECOGNIZED_ORGANIZATIONS = frozenset({
    "aisi",
    "anssi",
    "asd",
    "at&t",
    "cisa",
    "cse",
    "cybersecurity & infrastructure security agency",
    "dcsa",
    "epa",
    "fbi",
    "federal bureau of investigation",
    "french national cybersecurity agency",
    "gitguardian",
    "krebs on security",
    "nato",
    "nsa",
    "nukib",
    "openai",
    "sis rm",
    "skw",
})

_ORG_CONTEXT_TERMS = (
    "agency",
    "association",
    "authority",
    "bureau",
    "company",
    "corporation",
    "department",
    "directorate",
    "firm",
    "foundation",
    "government",
    "group",
    "institute",
    "laboratory",
    "ministry",
    "organization",
    "organisation",
    "service",
    "university",
    "inc.",
    "incorporated",
    "ltd.",
    "limited",
    "corp.",
    "vendor",
)
_STRONG_ORG_CONTEXT_TERMS = tuple(
    term for term in _ORG_CONTEXT_TERMS
    if term not in {
        "group",
        "organization",
        "organisation",
        "service",
        "vendor",
        "limited",
    }
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+(?:['’][A-Za-z]+)?")
_SHORT_ACRONYM_RE = re.compile(r"^[A-Z0-9]{2,6}$")
_INTERNAL_CAPS_RE = re.compile(r".[A-Z]")
_MIXED_DIGIT_RE = re.compile(r"[A-Za-z]\d[A-Za-z]|\d[A-Za-z]")
_PRODUCT_WORD_RE = re.compile(
    r"\b(?:software|suite|server|desktop|browser|shell|cloud|platform|framework|"
    r"protocol|core|client|studio|editor|tool|application|app)\b",
    re.IGNORECASE,
)


def canonical_name(value: str) -> str:
    """Return a comparison key without changing the persisted value."""
    value = re.sub(r"[\u2019']s\b", "", value or "")
    value = unicodedata.normalize("NFKD", value or "")
    value = value.encode("ascii", "ignore").decode("ascii")
    return " ".join(value.casefold().split())


def is_bare_short_acronym(value: str) -> bool:
    """Return True for a standalone 2–6 character all-caps token."""
    return bool(_SHORT_ACRONYM_RE.fullmatch((value or "").strip()))


def _context_windows(value: str, context_text: str, radius: int = 180) -> Iterable[str]:
    """Yield local context windows around each occurrence of *value*."""
    if not value or not context_text:
        return
    lower_text = context_text.casefold()
    lower_value = value.casefold()
    start = 0
    while True:
        idx = lower_text.find(lower_value, start)
        if idx < 0:
            break
        yield lower_text[max(0, idx - radius): min(len(context_text), idx + len(value) + radius)]
        start = idx + max(1, len(lower_value))


def has_organization_context(value: str, context_text: str | None = None) -> bool:
    """Return whether a candidate has nearby evidence of an organization sense."""
    key = canonical_name(value)
    if key in _RECOGNIZED_ORGANIZATIONS:
        return True
    if not context_text:
        return False

    org_terms = "|".join(
        re.escape(term.rstrip(".")) for term in _STRONG_ORG_CONTEXT_TERMS
    )
    value_pattern = re.escape(value.casefold())
    for window in _context_windows(value, context_text):
        # A generic word such as "organization" elsewhere in a page is not
        # corroboration for an acronym. Require it to be close to the value,
        # in either the ``ABC is an agency`` or ``agency ABC`` direction.
        if re.search(
            rf"\b{value_pattern}\b(?:\W+\w+){{0,6}}\W+(?:{org_terms})\b",
            window,
        ) or re.search(
            rf"\b(?:{org_terms})\b(?:\W+\w+){{0,6}}\W+{value_pattern}\b",
            window,
        ):
            return True
        # Explicit abbreviation/expansion forms are stronger than a nearby
        # generic word: ``Agency Name (ABC)`` or ``ABC (Agency Name)``.
        if re.search(
            rf"\([^)]*(?:{org_terms})[^)]*\b{value_pattern}\b[^)]*\)",
            window,
        ):
            return True
        if re.search(
            rf"\b{value_pattern}\b\s*\([^)]*(?:{org_terms})\b",
            window,
        ):
            return True
    return False


def is_curated_software_product(value: str, context_text: str | None = None) -> bool:
    """Return True only for a high-confidence product name without org context."""
    return (
        canonical_name(value) in _CURATED_SOFTWARE_PRODUCTS
        and not has_organization_context(value, context_text)
    )


def should_suppress_organization(value: str, context_text: str | None = None) -> bool:
    """Apply deterministic Option A suppression rules."""
    if has_organization_context(value, context_text):
        return False
    if is_bare_short_acronym(value):
        return True
    return is_curated_software_product(value, context_text)


def is_cpe_candidate(value: str, context_text: str | None = None) -> bool:
    """Limit CPE calls to product-shaped candidates, not every organization."""
    if has_organization_context(value, context_text) or len((value or '').strip()) < 4:
        return False
    if canonical_name(value) in _CURATED_SOFTWARE_PRODUCTS:
        return False  # deterministic suppression already handles it
    tokens = _TOKEN_RE.findall(value or "")
    product_context = any(
        _PRODUCT_WORD_RE.search(window)
        for window in _context_windows(value, context_text or "", radius=100)
    )
    return (
        len(tokens) <= 4
        and (
            bool(_INTERNAL_CAPS_RE.search(value or ""))
            or bool(_MIXED_DIGIT_RE.search(value or ""))
            or bool(_PRODUCT_WORD_RE.search(value or ""))
            or product_context
        )
    )


async def suppress_cpe_matched_organizations(
    entities: list[Any],
    page_text_by_url: Mapping[str, str] | None = None,
    max_lookups: int = 5,
) -> tuple[list[Any], int]:
    """Drop organization entities with a strong NVD CPE product match.

    The CPE lookup is deliberately bounded and best-effort.  A failed or
    unavailable CPE request leaves the candidate untouched; deterministic
    suppression remains effective offline.
    """
    from sources.nvd import fetch_nvd_cpe  # local import avoids extractor/source cycles

    page_text_by_url = page_text_by_url or {}
    kept: list[Any] = []
    candidates: list[tuple[int, str, str, str]] = []
    seen: set[str] = set()

    for index, entity in enumerate(entities):
        if getattr(entity, "entity_type", "") != "ORGANIZATION_NAME":
            kept.append(entity)
            continue
        value = str(getattr(entity, "value", "") or "")
        context = page_text_by_url.get(str(getattr(entity, "source_url", "") or ""), "")
        if should_suppress_organization(value, context):
            continue
        if is_cpe_candidate(value, context):
            key = canonical_name(value)
            if key not in seen and len(candidates) < max_lookups:
                seen.add(key)
                candidates.append((
                    index,
                    value,
                    context,
                    str(getattr(entity, "source_url", "") or ""),
                ))
        kept.append(entity)

    if not candidates:
        return kept, 0

    results = await asyncio.gather(
        *(fetch_nvd_cpe(value) for _, value, _, _ in candidates),
        return_exceptions=True,
    )
    matched_values: set[str] = set()
    for (_, value, _, _), result in zip(candidates, results):
        if isinstance(result, dict) and result.get("matched") is True:
            matched_values.add(canonical_name(value))

    if not matched_values:
        return kept, 0
    filtered = [
        entity for entity in kept
        if not (
            getattr(entity, "entity_type", "") == "ORGANIZATION_NAME"
            and canonical_name(str(getattr(entity, "value", "") or "")) in matched_values
            and not has_organization_context(
                str(getattr(entity, "value", "") or ""),
                page_text_by_url.get(str(getattr(entity, "source_url", "") or ""), ""),
            )
        )
    ]
    return filtered, len(entities) - len(filtered)
