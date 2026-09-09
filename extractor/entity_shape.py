"""
extractor/entity_shape.py — Shape-aware validation for name-type entities.

The historical failure mode of this project was suppressing NER false positives
with an ever-growing denylist: every audit found a new batch of generic words
that had been extracted as THREAT_ACTOR_HANDLE / ORGANIZATION_NAME, someone
added them to a list, and the next investigation surfaced a *different* batch of
never-before-seen words.  A static denylist can only ever cover strings someone
already saw.

This module flips the test: instead of "reject if on the known-bad list", a
candidate is accepted only if it *plausibly has the shape of the entity type
being claimed* — or matches the maintained known-good gazetteer
(``extractor.gazetteer``).  The shape signals are structural and language-based,
so a brand-new generic word is rejected the first time it appears, with nobody
having to have seen it before:

  * ordinary dictionary words used in their normal sense (via a bundled common-
    word frequency list) are not entity-shaped;
  * real handles / malware / group names tend to have unusual capitalisation
    (CamelCase, ALLCAPS acronyms), embedded digits, leetspeak, or separators,
    or read as multi-word proper nouns / carry an org suffix;
  * a run of common lowercase words (page boilerplate, sentence fragments) is
    rejected regardless of which specific words it contains.

Every function is total and never raises.

Public interface
----------------
evaluate(entity_type, value) -> ShapeVerdict
looks_like_common_language(value) -> bool
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field

from extractor import gazetteer
from extractor.software_suppression import has_organization_context

logger = logging.getLogger(__name__)

_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"
)
_COMMON_WORDS_PATH = os.path.join(_DATA_DIR, "common_words_en.txt")
# Closed linguistic lexicon of security/cybercrime common nouns ("payload",
# "loader", "dropzone", ...).  These are ordinary *domain* vocabulary that the
# general-English frequency list doesn't cover, so a candidate that is just one
# of these words is language, not an entity.  This is a bundled reference
# lexicon (the negative counterpart to the common-word list), NOT a running tally
# of specific observed false positives — that distinction is the whole point of
# this rework.
_DOMAIN_STOPWORDS_PATH = os.path.join(_DATA_DIR, "domain_stopwords_en.txt")

_common_words: frozenset[str] = frozenset()
_domain_stopwords: frozenset[str] = frozenset()
_words_loaded = False


def _load_words() -> None:
    global _common_words, _domain_stopwords, _words_loaded
    if _words_loaded:
        return
    _words_loaded = True
    try:
        with open(_COMMON_WORDS_PATH, encoding="utf-8") as fh:
            words = [w.strip().lower() for w in fh if w.strip()]
        domain: list[str] = []
        try:
            with open(_DOMAIN_STOPWORDS_PATH, encoding="utf-8") as fh:
                domain = [w.strip().lower() for w in fh if w.strip()]
        except FileNotFoundError:
            logger.warning("Domain stopword lexicon not found at %s", _DOMAIN_STOPWORDS_PATH)
        # The English dictionary + the security-domain lexicon together define
        # "ordinary language" — a token in either is not, on its own, entity-shaped.
        _domain_stopwords = frozenset(domain)
        _common_words = frozenset(words) | _domain_stopwords
        logger.info(
            "Ordinary-language lexicon loaded: %d dictionary words (+%d domain stopwords)",
            len(words), len(domain),
        )
    except FileNotFoundError:
        logger.warning(
            "Common-word list not found at %s — shape checks will rely on "
            "structural signals only. Regenerate with scripts/update_gazetteer.py.",
            _COMMON_WORDS_PATH,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load common-word list (non-fatal): %s", exc)


# Organisation suffixes that strongly signal a real org name.
_ORG_SUFFIXES = gazetteer.ORG_SUFFIXES

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+(?:['’][A-Za-z]+)?")
_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*")


@dataclass
class ShapeVerdict:
    """Result of a shape evaluation.

    tier is one of: "gazetteer" (matched the known-good reference set),
    "shape_strong", "shape_ok", "shape_weak", "reject".  ``accept`` is True for
    every tier except "reject".  ``score`` is a continuous [0,1] plausibility
    used as one input to the confidence computation.
    """
    accept: bool
    tier: str
    score: float
    signals: dict = field(default_factory=dict)


def _tokens(value: str) -> list[str]:
    return _TOKEN_RE.findall(value or "")


def _has_internal_caps(token: str) -> bool:
    """CamelCase / PascalCase-with-second-cap / studly caps — an uppercase
    letter somewhere other than a single leading capital.  'LockBit',
    'BlackCat', 'REvil', 'xDedic' → True.  'Bitcoin', 'Google' → False."""
    if len(token) < 2:
        return False
    if token.isupper():
        return False  # handled by _is_acronym
    return bool(re.search(r".[A-Z]", token))


def _is_acronym(token: str) -> bool:
    """2-6 char all-caps or all-caps-with-digits token: 'ALPHV', 'APT', 'FIN7'."""
    return bool(re.fullmatch(r"[A-Z0-9]{2,6}", token)) and any(c.isalpha() for c in token)


def _has_leet_or_mixed(token: str) -> bool:
    """A digit embedded among letters (not a trailing version): 'Gh0st',
    'APT28', 'w0rm', 'Cl0p'."""
    if not any(c.isdigit() for c in token):
        return False
    if not any(c.isalpha() for c in token):
        return False
    # digit not merely trailing (version-like 'tool2') → interior mix
    return bool(re.search(r"\d[A-Za-z]", token) or re.search(r"[A-Za-z]\d[A-Za-z]", token))


def _is_common(token: str) -> bool:
    return token.lower() in _common_words


def looks_like_common_language(value: str) -> bool:
    """True when *value* reads as ordinary English (a common word or a run of
    common words), rather than an entity-shaped token.  Capitalisation-blind:
    boilerplate is boilerplate whether or not it was title-cased."""
    _load_words()
    toks = _tokens(value)
    if not toks:
        return True
    word_toks = [t for t in toks if _WORD_RE.fullmatch(t)]
    if not word_toks:
        return False
    # Any token with entity shape means it's not plain language.
    for t in word_toks:
        if _has_internal_caps(t) or _is_acronym(t) or _has_leet_or_mixed(t):
            return False
    # Single token: common-word → language.
    if len(word_toks) == 1:
        return _is_common(word_toks[0])
    # Multi-token: if (almost) every token is a common word, it's a fragment.
    common_count = sum(1 for t in word_toks if _is_common(t))
    return common_count >= len(word_toks) - 0  # all tokens common → fragment


def _base_signals(value: str, context_text: str | None = None) -> dict:
    _load_words()
    toks = _tokens(value)
    word_toks = [t for t in toks if _WORD_RE.fullmatch(t)]
    return {
        "tokens": toks,
        "word_tokens": word_toks,
        "has_internal_caps": any(_has_internal_caps(t) for t in toks),
        "has_acronym": any(_is_acronym(t) for t in toks),
        "has_leet_or_mixed": any(_has_leet_or_mixed(t) for t in toks),
        "has_separator": bool(re.search(r"[._\-]", value or "")),
        "single_common_word": len(word_toks) == 1 and _is_common(word_toks[0]),
        "single_domain_stopword": len(word_toks) == 1 and word_toks[0].lower() in _domain_stopwords,
        "all_tokens_common": bool(word_toks) and all(_is_common(t) for t in word_toks),
        "common_fraction": (
            sum(1 for t in word_toks if _is_common(t)) / len(word_toks)
            if word_toks else 1.0
        ),
        "has_org_suffix": any(t.lower() in _ORG_SUFFIXES for t in toks),
        "multiword_proper": (
            len(word_toks) >= 2
            and sum(1 for t in word_toks if t[:1].isupper()) >= max(2, len(word_toks) - 1)
        ),
        "n_word_tokens": len(word_toks),
        "organization_context": has_organization_context(value, context_text),
    }


def _tier_from_score(score: float) -> str:
    if score >= 0.72:
        return "shape_strong"
    if score >= 0.55:
        return "shape_ok"
    if score >= 0.42:
        return "shape_weak"
    return "reject"


def _has_entity_casing(sig: dict) -> bool:
    """A token in CamelCase / ALLCAPS / leet is not ordinary language even if
    its lowercased form is a dictionary word ("RedLine", "BlackCat"), so the
    common-word penalties must not fire in that case."""
    return sig["has_internal_caps"] or sig["has_leet_or_mixed"] or sig["has_acronym"]


def _evaluate_handle(value: str, sig: dict) -> float:
    score = 0.5
    entity_casing = _has_entity_casing(sig)
    if sig["has_internal_caps"]:
        score += 0.25
    if sig["has_leet_or_mixed"]:
        score += 0.22
    if sig["has_acronym"]:
        score += 0.18
    if sig["has_separator"] and not sig["all_tokens_common"]:
        score += 0.12
    if not entity_casing:
        if sig["single_common_word"]:
            score -= 0.4
        elif sig["all_tokens_common"]:
            score -= 0.3
        elif sig["common_fraction"] >= 0.5:
            score -= 0.15
    # A lone lowercase non-dictionary token ("xdedic", "revil") is plausibly a
    # handle even without other signals.
    if (
        sig["n_word_tokens"] == 1
        and not sig["single_common_word"]
        and not sig["has_internal_caps"]
    ):
        score += 0.08
    return score


def _evaluate_org(value: str, sig: dict) -> float:
    # Organisation names are open-ended (no bounded gazetteer), so precision
    # rests on *distinctive* structure: a real threat-intel org name almost
    # always carries an org suffix ("Corp", "Ltd", "Lab", "Group", ...), brand
    # casing ("CrowdStrike"), or an acronym ("NCC", "IBM").  A plain Title-Case
    # phrase built from dictionary words ("Synergy Report", "Governance
    # Committee") is far more likely a heading / boilerplate than an org, so
    # capitalisation alone is deliberately weak evidence here.
    score = 0.5
    has_strong_signal = (
        sig["has_org_suffix"] or sig["has_internal_caps"] or sig["has_acronym"]
    )
    if sig["has_org_suffix"]:
        score += 0.35
    if sig["has_internal_caps"]:
        score += 0.30
    if sig["has_acronym"]:
        score += 0.20
    # Multi-word proper-noun shape is only a mild bump, and only when it isn't
    # just a run of dictionary words.
    if sig["multiword_proper"] and not sig["all_tokens_common"]:
        score += 0.08
    if not _has_entity_casing(sig):
        if sig["single_common_word"]:
            score -= 0.45
        elif sig["all_tokens_common"]:
            score -= 0.40
        elif sig["common_fraction"] >= 0.5 and not has_strong_signal:
            # A phrase that's mostly ordinary words with no distinctive org signal.
            score -= 0.18
    # Very long token runs read as a sentence, not a name.
    if sig["n_word_tokens"] > 5:
        score -= 0.3
    # A 3+ digit run signals an identifier code (CVE-2023-34362, MS08-067,
    # tracking numbers), not an organisation name.
    if re.search(r"\d{3,}", value):
        score -= 0.5
    # A short all-caps token is not organization evidence by itself.  This is
    # intentionally stricter than the generic shape score: product/protocol
    # acronyms such as ZCS, AWS, EDR and SCADA otherwise pass the old 2-6
    # character acronym shortcut and bypass the normal length floor.
    if (
        sig["n_word_tokens"] == 1
        and sig["has_acronym"]
        and not sig["organization_context"]
    ):
        return 0.2
    return score


def _evaluate_malware(value: str, sig: dict) -> float:
    # Malware/ransomware candidates are generated from a curated pattern set, so
    # shape is a light secondary gate: reject only obvious plain-language.
    score = 0.55
    if _has_entity_casing(sig):
        score += 0.2
    else:
        # Only penalise plain-language when there's no entity-shape casing —
        # "RedLine"/"BlackCat" are dictionary words in lowercase but their
        # CamelCase form is clearly a name, not ordinary usage.
        if sig["single_common_word"]:
            score -= 0.3
        elif sig["all_tokens_common"]:
            score -= 0.25
    return score


def evaluate(
    entity_type: str,
    value: str,
    context_text: str | None = None,
) -> ShapeVerdict:
    """Evaluate whether *value* plausibly has the shape of *entity_type*.

    Gazetteer membership short-circuits to the strongest tier; otherwise a
    structural/linguistic score decides.  Returns a ShapeVerdict; never raises.
    """
    try:
        value = (value or "").strip()
        if not value:
            return ShapeVerdict(False, "reject", 0.0, {})

        sig = _base_signals(value, context_text)

        # Known-good reference set wins outright — with one guard.  Malware /
        # ransomware candidates are generated only by a curated precise pattern
        # set, so a gazetteer confirmation is fully trusted (this is what lets
        # legitimately common-word group names like "Play"/"Royal"/"Fog"
        # through).  Handle / org candidates come from loose context regex /
        # spaCy, so a bare, unmistakably-ordinary dictionary word (e.g.
        # "payload", which happens to exist in the malware taxonomy) must not
        # ride a gazetteer hit — it falls through to the shape score, which
        # rejects plain language.
        gaz_hit = gazetteer.is_known(value, entity_type)
        sig["gazetteer"] = gaz_hit
        if gaz_hit:
            _no_shape = not (
                sig["has_internal_caps"] or sig["has_acronym"]
                or sig["has_leet_or_mixed"] or sig["has_separator"]
            )
            # A bare security-domain stopword ("payload", "loader", "beacon")
            # is never an entity, even when the taxonomy happens to list it —
            # this guard applies to every type.  General dictionary words are
            # NOT guarded for malware/ransomware, so legitimately common-word
            # group names ("Play", "Fog", "Royal") still ride their gazetteer
            # entry.
            _domain_noise = sig["single_domain_stopword"] and _no_shape
            # For the loose handle/org candidate sources, a bare ordinary word
            # or all-common phrase must not ride a gazetteer hit either.
            _bare_ordinary = (
                entity_type in ("THREAT_ACTOR_HANDLE", "ORGANIZATION_NAME")
                and (sig["single_common_word"] or sig["all_tokens_common"])
                and _no_shape
            )
            # A title-cased, multi-word actor name ending in an organisation
            # suffix is still a valid known actor even when every token is in
            # the ordinary-language lexicon (for example, Lazarus Group).
            # Keep the ordinary-language guard for bare/common candidates, but
            # do not discard a confirmed gazetteer cluster on that basis.
            if (
                entity_type == "THREAT_ACTOR_HANDLE"
                and sig["multiword_proper"]
                and sig["has_org_suffix"]
                and sig["n_word_tokens"] >= 2
            ):
                _bare_ordinary = False
            if not (_domain_noise or _bare_ordinary):
                return ShapeVerdict(True, "gazetteer", 0.97, sig)

        if entity_type == "THREAT_ACTOR_HANDLE":
            score = _evaluate_handle(value, sig)
        elif entity_type == "ORGANIZATION_NAME":
            score = _evaluate_org(value, sig)
        elif entity_type in ("MALWARE_FAMILY", "RANSOMWARE_GROUP"):
            score = _evaluate_malware(value, sig)
        else:
            # Not a shape-validated type — accept with neutral score.
            return ShapeVerdict(True, "shape_ok", 0.6, sig)

        score = max(0.0, min(1.0, score))
        tier = _tier_from_score(score)
        return ShapeVerdict(tier != "reject", tier, score, sig)
    except Exception:  # noqa: BLE001
        logger.exception("entity_shape.evaluate failed for %r", value)
        # Fail open with a neutral-low verdict so a bug never silently drops all
        # entities, but also never blesses noise with high confidence.
        return ShapeVerdict(True, "shape_weak", 0.45, {})
