"""
export/yara_export.py — Generates production-quality YARA rules from 
Ezio investigation entities.

YARA rules are grouped by detection type into a single .yar file with a
header block describing the investigation.  All rule names are sanitised
to be YARA-identifier safe: ``[A-Za-z0-9_]``, max 128 chars, must start
with a letter.

Rule categories generated
-------------------------
1. Hash rules  — one per FILE_HASH_SHA256 / SHA1 / MD5 (uses ``import "hash"``)
2. String rules — one per MALWARE_FAMILY / RANSOMWARE_GROUP (case-insensitive
   exact + lowercase variants)
3. Network IOC rules — one per ONION_URL / high-confidence DOMAIN, with the
   IOC as a string match
4. Credential leak rules — pattern-based detection for AWS, GitHub, GitLab,
   Stripe, Slack, JWT, generic API keys, and private-key markers

Public interface
----------------
generate_yara_rules(entities, investigation, tlp) -> str
    Returns a YARA rules file as a single string.  The string is always
    syntactically valid YARA: a leading comment header, an ``import``
    block (when needed), then ``rule <name> { ... }`` blocks.

The module is intentionally decoupled from the rest of Ezio — entities
are accepted as plain dicts (or any object exposing ``entity_type`` /
``value`` / ``confidence``) so it can be unit-tested without a database.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from extractor.identity import entity_canonical_id

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Cap for the identifier (YARA itself allows longer, but 128 keeps diffs sane).
_MAX_RULE_NAME = 128

#: Identifier-safe character class.
_SAFE_IDENT = re.compile(r"[^A-Za-z0-9_]")

#: Entity type aliases.  Match ioc_package._TYPE_NORMALISATION.
_TYPE_NORMALISATION: dict[str, str] = {
    "ip_address": "IP_ADDRESS",
    "domain": "DOMAIN",
    "email": "EMAIL_ADDRESS",
    "onion_url": "ONION_URL",
    "cve": "CVE_NUMBER",
    "file_hash_md5": "FILE_HASH_MD5",
    "file_hash_sha1": "FILE_HASH_SHA1",
    "file_hash_sha256": "FILE_HASH_SHA256",
    "mitre_technique": "MITRE_TECHNIQUE",
    "malware": "MALWARE_FAMILY",
    "ransomware_group": "RANSOMWARE_GROUP",
    "handle": "THREAT_ACTOR_HANDLE",
    "crypto_wallet": "CRYPTO_WALLET",
    "phone": "PHONE",
    "pgp_key": "PGP_KEY",
    "other": "OTHER",
    "aws_access_key": "AWS_ACCESS_KEY",
    "github_token": "GITHUB_TOKEN",
    "gitlab_token": "GITLAB_TOKEN",
    "stripe_key": "STRIPE_KEY",
    "jwt_token": "JWT_TOKEN",
    "slack_token": "SLACK_TOKEN",
    "generic_api_key": "GENERIC_API_KEY",
    "api_key": "API_KEY",
    "private_key": "PRIVATE_KEY",
}

#: Entity type groupings for hash rules
_HASH_TYPES = {"FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"}
#: Entity type groupings for malware-family string rules
_MALWARE_TYPES = {"MALWARE_FAMILY", "RANSOMWARE_GROUP", "MALWARE"}
#: Entity type groupings for network IOC rules
_NETWORK_TYPES = {"ONION_URL", "DOMAIN", "URL"}
#: Entity types we generate credential-leak rules for
_CREDENTIAL_TYPES = {
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "STRIPE_KEY",
    "JWT_TOKEN",
    "SLACK_TOKEN",
    "GENERIC_API_KEY",
    "API_KEY",
    "PRIVATE_KEY",
}


# ---------------------------------------------------------------------------
# Entity attribute accessors — work for dicts, NormalizedEntity, and DB Entity
# ---------------------------------------------------------------------------


def _entity_type(e: Any) -> str:
    """Return the upper-cased entity type for an entity (dict | object)."""
    if isinstance(e, dict):
        raw = e.get("entity_type") or e.get("type") or ""
    else:
        raw = getattr(e, "entity_type", "") or ""
    raw = str(raw).strip()
    if not raw:
        return ""
    if raw == raw.upper():
        return raw
    return _TYPE_NORMALISATION.get(raw.lower(), raw.upper())


def _entity_value(e: Any) -> str:
    return entity_canonical_id(e)


def _entity_confidence(e: Any) -> float:
    try:
        if isinstance(e, dict):
            return float(e.get("confidence") or 0.0)
        return float(getattr(e, "confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# Identifier sanitisation
# ---------------------------------------------------------------------------


def _safe_rule_name(text: str, fallback: str = "IOC", max_len: int = _MAX_RULE_NAME) -> str:
    """Return a YARA-safe identifier (letters / digits / underscores).

    Rules:
      * Strips anything outside ``[A-Za-z0-9_]`` and replaces with ``_``
      * Collapses runs of consecutive underscores into a single ``_``
        (so ``"a  b"`` → ``"a_b"`` rather than ``"a__b"``)
      * Must start with a letter (YARA identifier rule).  A leading digit
        is replaced with ``V_`` prefix.
      * Truncated to ``max_len`` characters.
      * Empty / all-special input falls back to ``fallback``.
    """
    if not text:
        text = fallback
    s = _SAFE_IDENT.sub("_", text)
    # Collapse runs of underscores
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = fallback
    if not s[0].isalpha():
        # YARA identifiers must start with a letter or ``_`` is not
        # actually a valid first char for the *rule name* position.  Use
        # ``V_`` prefix instead — keeps the rest of the name intact.
        s = "V_" + s
    if len(s) > max_len:
        s = s[:max_len].rstrip("_")
        if not s:
            s = fallback
    return s


# ---------------------------------------------------------------------------
# String escaping
# ---------------------------------------------------------------------------


def _escape_yara_string(s: str) -> str:
    """Escape a string for use inside a YARA double-quoted literal."""
    if s is None:
        return ""
    s = str(s)
    return s.replace("\\", "\\\\").replace("\"", "\\\"")


# ---------------------------------------------------------------------------
# Meta field formatting
# ---------------------------------------------------------------------------


def _meta_value(value: Any) -> str:
    """Render a Python value as a YARA string literal in a ``meta:`` block."""
    return _escape_yara_string(str(value) if value is not None else "")


# ---------------------------------------------------------------------------
# Hash rule builders
# ---------------------------------------------------------------------------

_HASH_RULES = {
    "FILE_HASH_SHA256": {
        "import": "hash",
        "prefix": "Hash_SHA256",
        "length": 64,
        "condition": 'hash.sha256(0, filesize) == "{hash}"',
    },
    "FILE_HASH_SHA1": {
        "import": "hash",
        "prefix": "Hash_SHA1",
        "length": 40,
        "condition": 'hash.sha1(0, filesize) == "{hash}"',
    },
    "FILE_HASH_MD5": {
        "import": "hash",
        "prefix": "Hash_MD5",
        "length": 32,
        "condition": 'hash.md5(0, filesize) == "{hash}"',
    },
}


def _build_hash_rule(
    entity: Any,
    etype: str,
    query: str,
    date_str: str,
    tlp: str,
) -> Optional[str]:
    spec = _HASH_RULES.get(etype)
    if spec is None:
        return None
    value = _entity_value(entity).strip()
    if not value:
        return None
    if not re.match(rf"^[A-Fa-f0-9]{{{spec['length']}}}$", value):
        return None
    normalised = value.lower()
    short = normalised[:8]
    rule_name = _safe_rule_name(f"Ezio_{spec['prefix']}_{short}")
    confidence = _entity_confidence(entity)
    condition = spec["condition"].format(hash=normalised)
    rule = (
        f"rule {rule_name} {{\n"
        f"    meta:\n"
        f"        description = \"File hash IOC from Ezio investigation\"\n"
        f"        query = \"{_meta_value(query)}\"\n"
        f"        hash_{etype.split('_')[-1].lower()} = \"{normalised}\"\n"
        f"        confidence = \"{confidence:.2f}\"\n"
        f"        generated = \"{date_str}\"\n"
        f"        tlp = \"{_meta_value(tlp)}\"\n"
        f"    condition:\n"
        f"        {condition}\n"
        f"}}\n"
    )
    return rule


# ---------------------------------------------------------------------------
# Malware string rule builder
# ---------------------------------------------------------------------------


def _build_malware_string_rule(
    entity: Any,
    value: str,
    query: str,
    date_str: str,
    tlp: str,
) -> Optional[str]:
    confidence = _entity_confidence(entity)
    ident = _safe_rule_name(value, fallback="Malware")
    rule_name = f"Ezio_Malware_{ident}"
    # Avoid pathological names that exceed YARA's 128-char identifier cap
    if len(rule_name) > _MAX_RULE_NAME:
        rule_name = rule_name[: _MAX_RULE_NAME].rstrip("_")
        if not rule_name:
            rule_name = "Ezio_Malware_IOC"
    safe_value = _escape_yara_string(value)
    safe_lower = _escape_yara_string(value.lower())
    rule = (
        f"rule {rule_name} {{\n"
        f"    meta:\n"
        f"        description = \"Malware family string detection\"\n"
        f"        query = \"{_meta_value(query)}\"\n"
        f"        malware_family = \"{safe_value}\"\n"
        f"        confidence = \"{confidence:.2f}\"\n"
        f"        generated = \"{date_str}\"\n"
        f"        tlp = \"{_meta_value(tlp)}\"\n"
        f"    strings:\n"
        f"        $name_exact = \"{safe_value}\" fullword nocase\n"
        f"        $name_lower = \"{safe_lower}\" fullword nocase\n"
        f"    condition:\n"
        f"        any of them\n"
        f"}}\n"
    )
    return rule


# ---------------------------------------------------------------------------
# Network IOC rule builder
# ---------------------------------------------------------------------------


def _build_network_rule(
    entity: Any,
    etype: str,
    value: str,
    query: str,
    date_str: str,
    tlp: str,
) -> Optional[str]:
    confidence = _entity_confidence(entity)
    # Determine ioc_type label for the rule metadata
    if etype == "ONION_URL":
        ioc_type = "onion_url"
    elif etype == "DOMAIN":
        ioc_type = "domain"
    else:
        ioc_type = "url"
    ident = _safe_rule_name(value, fallback="Network")
    rule_name = f"Ezio_Network_{ident}"
    if len(rule_name) > _MAX_RULE_NAME:
        rule_name = rule_name[: _MAX_RULE_NAME].rstrip("_")
        if not rule_name:
            rule_name = "Ezio_Network_IOC"
    safe_value = _escape_yara_string(value)
    rule = (
        f"rule {rule_name} {{\n"
        f"    meta:\n"
        f"        description = \"Network IOC string\"\n"
        f"        query = \"{_meta_value(query)}\"\n"
        f"        ioc_type = \"{ioc_type}\"\n"
        f"        ioc_value = \"{safe_value}\"\n"
        f"        confidence = \"{confidence:.2f}\"\n"
        f"        generated = \"{date_str}\"\n"
        f"        tlp = \"{_meta_value(tlp)}\"\n"
        f"    strings:\n"
        f"        $ioc = \"{safe_value}\" nocase\n"
        f"    condition:\n"
        f"        $ioc\n"
        f"}}\n"
    )
    return rule


# ---------------------------------------------------------------------------
# Credential leak rules
# ---------------------------------------------------------------------------


# One per credential *category* — we generate pattern rules that detect
# the *shape* of credentials, since the original values shouldn't be
# embedded in the rule.  Each pattern uses a regex in YARA syntax.
_CRED_RULES: list[dict[str, str]] = [
    {
        "name": "CredLeak_AWS_AccessKey",
        "description": "AWS access key ID pattern detection",
        "patterns": [
            ('$aws_key = /AKIA[0-9A-Z]{16}/', "matches AKIA[0-9A-Z]{16}"),
            ('$aws_label = "aws_access_key_id" nocase', "matches the aws_access_key_id label"),
        ],
        "condition": "$aws_key or $aws_label",
    },
    {
        "name": "CredLeak_AWS_SecretKey",
        "description": "AWS secret access key pattern detection",
        "patterns": [
            ('$aws_secret_label = "aws_secret_access_key" nocase', "matches the aws_secret_access_key label"),
        ],
        "condition": "$aws_secret_label and filesize < 1MB",
    },
    {
        "name": "CredLeak_GitHub_Token",
        "description": "GitHub personal access token pattern detection",
        "patterns": [
            ('$ghp = /gh[pousr]_[A-Za-z0-9]{30,}/', "matches ghp_/gho_/ghu_/ghs_/ghr_ prefixes"),
            ('$ghpat = /github_pat_[A-Za-z0-9_]{30,}/', "matches github_pat_ prefix"),
        ],
        "condition": "$ghp or $ghpat",
    },
    {
        "name": "CredLeak_GitLab_Token",
        "description": "GitLab personal access token pattern detection",
        "patterns": [
            ('$glpat = /glpat-[A-Za-z0-9_\\-]{20,}/', "matches glpat- prefix"),
        ],
        "condition": "$glpat",
    },
    {
        "name": "CredLeak_Stripe_Key",
        "description": "Stripe API key pattern detection",
        "patterns": [
            ('$stripe = /[srpk]k_(live|test)_[A-Za-z0-9]{16,}/', "matches sk_live_, sk_test_, pk_live_, pk_test_, rk_live_"),
        ],
        "condition": "$stripe",
    },
    {
        "name": "CredLeak_Slack_Token",
        "description": "Slack API token pattern detection",
        "patterns": [
            ('$slack = /xox[bpars]-[0-9]+-[0-9]+-[A-Za-z0-9]+/', "matches xoxb/xoxp/xoxa/xoxr/xoxs prefixes"),
        ],
        "condition": "$slack",
    },
    {
        "name": "CredLeak_JWT",
        "description": "JSON Web Token pattern detection",
        "patterns": [
            (
                "$jwt = /eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}/",
                "matches three base64url segments separated by dots",
            ),
        ],
        "condition": "$jwt",
    },
    {
        "name": "CredLeak_PrivateKey",
        "description": "PEM private-key header detection",
        "patterns": [
            ('$rsa_priv = "-----BEGIN RSA PRIVATE KEY-----"', "RSA private key header"),
            ('$openssh_priv = "-----BEGIN OPENSSH PRIVATE KEY-----"', "OpenSSH private key header"),
            ('$ec_priv = "-----BEGIN EC PRIVATE KEY-----"', "EC private key header"),
            ('$dsa_priv = "-----BEGIN DSA PRIVATE KEY-----"', "DSA private key header"),
            ('$pgp_priv = "-----BEGIN PGP PRIVATE KEY BLOCK-----"', "PGP private key block"),
        ],
        "condition": "any of them",
    },
    {
        "name": "CredLeak_GenericAPIKey",
        "description": "Generic high-entropy API-key label detection",
        "patterns": [
            ('$api_key_label = /["'']?(api[_-]?key|access[_-]?token|secret[_-]?key)["'']?\\s*[:=]/ nocase', "common secret-label prefixes"),
        ],
        "condition": "$api_key_label and filesize < 1MB",
    },
]


def _build_credential_rules(
    present_types: set[str],
    query: str,
    date_str: str,
    tlp: str,
) -> list[str]:
    """Generate the credential-leak pattern rules.

    ``present_types`` is the set of credential entity types that actually
    appear in the investigation — we still emit a few canonical pattern
    rules because the *goal* is to detect future credential leaks of these
    shapes anywhere on disk, not to fingerprint the specific leaked values.
    """
    # We always emit the canonical pattern rules.  The ``present_types``
    # set is used to add a meta note that flags the relevant entity types.
    out: list[str] = []
    for spec in _CRED_RULES:
        rule_name = _safe_rule_name(f"Ezio_{spec['name']}", fallback="Ezio_CredLeak")
        patterns_block = "\n".join(f"        {p}" for p, _ in spec["patterns"])
        rule = (
            f"rule {rule_name} {{\n"
            f"    meta:\n"
            f"        description = \"{_escape_yara_string(spec['description'])}\"\n"
            f"        query = \"{_meta_value(query)}\"\n"
            f"        category = \"credential_leak\"\n"
            f"        present_types = \"{_meta_value(','.join(sorted(present_types)) or 'n/a')}\"\n"
            f"        generated = \"{date_str}\"\n"
            f"        tlp = \"{_meta_value(tlp)}\"\n"
            f"    strings:\n"
            f"{patterns_block}\n"
            f"    condition:\n"
            f"        {spec['condition']}\n"
            f"}}\n"
        )
        out.append(rule)
    return out


# ---------------------------------------------------------------------------
# Header / file assembly
# ---------------------------------------------------------------------------


def _build_header(
    investigation: dict,
    tlp: str,
    date_str: str,
    rule_count: int,
) -> str:
    query = investigation.get("query") or "(unknown query)"
    inv_id = investigation.get("id") or "n/a"
    lines: list[str] = [
        "// Ezio YARA rules",
        "// -----------------------------------------------",
        f"// Investigation query : {_escape_yara_string(query)}",
        f"// Investigation ID    : {inv_id}",
        f"// Generated           : {date_str}",
        f"// TLP                 : {_escape_yara_string(tlp)}",
        f"// Total rules         : {rule_count}",
        "// Review and tune before deploying to EDR / file-scanning pipelines.",
        "",
    ]
    return "\n".join(lines)


def _section_header(title: str) -> str:
    return f"\n// ===============================================================\n// {title}\n// ===============================================================\n"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def generate_yara_rules(
    entities: list,
    investigation: dict,
    tlp: str = "TLP:WHITE",
) -> str:
    """
    Generate a YARA rules file as a string.

    Parameters
    ----------
    entities : list
        Entities as dicts, NormalizedEntity instances, or DB Entity instances.
        Must expose ``entity_type`` and ``canonical_value`` / ``value``.
    investigation : dict
        Investigation metadata (query, id, summary, created_at, ...).
    tlp : str
        Traffic Light Protocol marker (TLP:WHITE by default).  Stored as a
        meta field on every emitted rule.

    Returns
    -------
    str
        A single string containing a syntactically valid YARA rules file.
        Always at least returns a header comment block — for empty input
        the file is valid (empty) YARA.
    """
    entities = list(entities or [])
    query = (investigation or {}).get("query") or ""
    inv_id = (investigation or {}).get("id") or "n/a"
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Normalise the TLP marker.  Accept "WHITE" or "TLP:WHITE" or "white".
    tlp_norm = tlp.strip().upper()
    if not tlp_norm.startswith("TLP:"):
        tlp_norm = f"TLP:{tlp_norm}"
    if tlp_norm not in {"TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"}:
        # Default to TLP:WHITE for unknown values
        tlp_norm = "TLP:WHITE"

    # Bucket entities by category.  We dedupe per category so we don't
    # emit duplicate rules.
    hash_rules: list[str] = []
    seen_hash_keys: set[str] = set()

    malware_rules: list[str] = []
    seen_malware: set[str] = set()

    network_rules: list[str] = []
    seen_network: set[str] = set()

    cred_types_present: set[str] = set()

    for entity in entities:
        etype = _entity_type(entity)
        value = _entity_value(entity).strip()
        if not value or not etype:
            continue
        if etype in _HASH_TYPES:
            normalised = value.lower()
            key = f"{etype}:{normalised}"
            if key in seen_hash_keys:
                continue
            seen_hash_keys.add(key)
            rule = _build_hash_rule(entity, etype, query, date_str, tlp_norm)
            if rule:
                hash_rules.append(rule)
        elif etype in _MALWARE_TYPES:
            if value in seen_malware:
                continue
            seen_malware.add(value)
            rule = _build_malware_string_rule(
                entity, value, query, date_str, tlp_norm
            )
            if rule:
                malware_rules.append(rule)
        elif etype in _NETWORK_TYPES:
            # Only emit network string rules for ONION_URL and high-confidence
            # DOMAIN — we don't want to pollute the ruleset with speculative
            # domains.  Caller can always use the IOC package for raw
            # domain feeds.
            confidence = _entity_confidence(entity)
            if etype == "DOMAIN" and confidence < 0.7:
                continue
            if etype == "URL" and ".onion" not in value.lower():
                # Plain clearnet URLs need not be YARA string matches
                continue
            if value in seen_network:
                continue
            seen_network.add(value)
            rule = _build_network_rule(
                entity, etype, value, query, date_str, tlp_norm
            )
            if rule:
                network_rules.append(rule)
        elif etype in _CREDENTIAL_TYPES:
            cred_types_present.add(etype)

    # Build credential rules from the pattern set
    cred_rules = _build_credential_rules(
        cred_types_present, query, date_str, tlp_norm
    )

    # Need the "hash" import only if we actually emitted hash rules
    imports_block: list[str] = []
    if hash_rules:
        imports_block.append('import "hash"')
    if imports_block:
        imports_block.append("")  # trailing blank line

    # Assemble sections
    body: list[str] = []
    body.append(_section_header("Hash-based detections").rstrip() + "\n")
    body.extend(hash_rules)

    if malware_rules:
        body.append(_section_header("Malware family string detections").rstrip() + "\n")
        body.extend(malware_rules)

    if network_rules:
        body.append(_section_header("Network IOC string detections").rstrip() + "\n")
        body.extend(network_rules)

    if cred_rules:
        body.append(_section_header("Credential leak pattern detections").rstrip() + "\n")
        body.extend(cred_rules)

    # Count rules (each emitted rule starts with "rule " at column 0)
    rule_count = (
        len(hash_rules) + len(malware_rules) + len(network_rules) + len(cred_rules)
    )

    header = _build_header(
        investigation={
            "query": query,
            "id": inv_id,
        },
        tlp=tlp_norm,
        date_str=date_str,
        rule_count=rule_count,
    )

    parts: list[str] = [header]
    parts.extend(imports_block)
    parts.extend(body)

    # Always end with a trailing newline so the file is well-formed.
    return "\n".join(parts).rstrip() + "\n"
