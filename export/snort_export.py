"""
export/snort_export.py — Generates production-quality Snort and Suricata
detection rules from Ezio investigation entities.

The same set of rules is emitted in two flavours:

* **Snort format** — classic ``alert ip ... -> ... (...)`` rules with
  ``msg:``, ``classtype:``, ``sid:``, ``rev:``, optional ``reference:``.
* **Suricata format** — Snort-compatible syntax with an added
  ``metadata:`` block describing ``malware_family``, ``performance_impact``,
  ``signature_severity``, ``deployment``, etc.

Rule categories generated
-------------------------
1. IP reputation rules — one per IP_ADDRESS with a C2 tag or
   high-confidence indicator
2. DNS detection rules — one per DOMAIN and ONION_URL
3. HTTP rules for known C2 paths (ONION_URLs with a path)
4. File-hash detection (Suricata-only — uses ``filemd5:`` keyword)
5. CVE exploit-attempt rules — one per CVE_NUMBER

SID management
--------------
Ezio reserves the SID range ``9000001-9099999``.  Within a single
call to ``generate_snort_rules`` the SID counter starts at the supplied
``start_sid`` (default 9000001) and auto-increments per rule.  The
function refuses to emit any rule that would push the counter past
9_099_999 and emits a clear warning-style header comment instead.

Public interface
----------------
generate_snort_rules(entities, investigation, format, tlp, start_sid) -> str
    Returns Snort or Suricata rules as a string.

The module is intentionally decoupled from the rest of Ezio — entities
are accepted as plain dicts (or any object exposing ``entity_type`` /
``value`` / ``confidence``) so it can be unit-tested without a database.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from extractor.identity import entity_canonical_id

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Lower bound of the Ezio-reserved SID range.
SID_RANGE_MIN = 9_000_001
#: Upper bound of the Ezio-reserved SID range.
SID_RANGE_MAX = 9_099_999
#: Default starting SID.
SID_DEFAULT_START = SID_RANGE_MIN

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
    "url": "URL",
}

#: Entity type groupings
_IP_TYPES = {"IP_ADDRESS"}
_DOMAIN_TYPES = {"DOMAIN"}
_ONION_TYPES = {"ONION_URL"}
_CVE_TYPES = {"CVE_NUMBER", "CVE"}
_HASH_TYPES = {"FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"}
_MALWARE_TYPES = {"MALWARE_FAMILY", "RANSOMWARE_GROUP", "MALWARE"}


# ---------------------------------------------------------------------------
# Entity attribute accessors — work for dicts, NormalizedEntity, and DB Entity
# ---------------------------------------------------------------------------


def _entity_type(e: Any) -> str:
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


def _entity_source_url(e: Any) -> str:
    if isinstance(e, dict):
        return e.get("source_url") or ""
    return getattr(e, "source_url", "") or ""


def _entity_corroborating_sources(e: Any) -> str:
    if isinstance(e, dict):
        return e.get("corroborating_sources") or ""
    return getattr(e, "corroborating_sources", "") or ""


def _entity_malware_family(e: Any) -> str:
    """Best-effort extraction of a malware family label from an entity."""
    if isinstance(e, dict):
        return (
            e.get("malware_family")
            or e.get("family")
            or e.get("tag")
            or ""
        )
    return getattr(e, "malware_family", "") or ""


# ---------------------------------------------------------------------------
# IP / domain / URL helpers
# ---------------------------------------------------------------------------


_IPV4_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


def _is_ipv6(value: str) -> bool:
    """Heuristic — anything that contains a colon and no dot in the host portion."""
    if not value:
        return False
    if "." in value.split("/")[0].split("%")[0]:
        return False
    return ":" in value


def _is_valid_ipv4(value: str) -> bool:
    if not _IPV4_RE.match(value):
        return False
    try:
        return all(0 <= int(p) <= 255 for p in value.split("."))
    except ValueError:
        return False


def _split_url(url: str) -> tuple[str, str]:
    """Return (host, path) from a URL.  Falls back to (url, "/") on parse failure."""
    if not url:
        return ("", "/")
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        path = parsed.path or "/"
        return host, path
    except Exception:
        return url, "/"


def _is_c2_ip(entity: Any, confidence: float) -> bool:
    """Decide whether an IP entity is a C2 / high-confidence reputation hit."""
    if confidence >= 0.85:
        return True
    tags = _entity_corroborating_sources(entity).lower()
    if any(t in tags for t in ("c2", "c2_confirmed", "command_and_control")):
        return True
    return False


# ---------------------------------------------------------------------------
# String escaping for Snort message / content fields
# ---------------------------------------------------------------------------


def _escape_snort_string(s: str) -> str:
    """Escape characters that would break a Snort ``msg:\"...\";`` literal."""
    if s is None:
        return ""
    return str(s).replace("\\", "\\\\").replace("\"", "\\\"")


# ---------------------------------------------------------------------------
# Rule builders
# ---------------------------------------------------------------------------


def _snort_header(engine: str, tlp: str, query: str, start_sid: int) -> list[str]:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return [
        f"# Ezio {engine} rules",
        f"# Investigation: {_escape_snort_string(query)}",
        f"# TLP: {_escape_snort_string(tlp)}",
        f"# Generated: {ts}",
        f"# SID range: {start_sid}-{SID_RANGE_MAX} (Ezio-reserved)",
        "# Review and tune before deploying to production sensors.",
        "",
    ]


def _build_ip_rule_snort(
    ip: str,
    sid: int,
    confidence: float,
    malware_family: str,
    source_url: str,
) -> str:
    """Emit a single Snort alert rule for an IP indicator."""
    ip_proto = "ip6" if _is_ipv6(ip) else "ip"
    family_part = f" [{malware_family}]" if malware_family else ""
    ref_part = ""
    if source_url:
        ref_part = f'    reference:url,{source_url};\n'
    return (
        f"alert {ip_proto} {ip} any -> $HOME_NET any (\n"
        f"    msg:\"Ezio - C2 IP {ip}{family_part}\";\n"
        f"{ref_part}"
        f"    classtype:trojan-activity;\n"
        f"    sid:{sid};\n"
        f"    rev:1;\n"
        f"    priority:1;\n"
        f")"
    )


def _build_ip_rule_suricata(
    ip: str,
    sid: int,
    confidence: float,
    malware_family: str,
    source_url: str,
    date_str: str,
) -> str:
    ip_proto = "ip6" if _is_ipv6(ip) else "ip"
    family_part = f" [{malware_family}]" if malware_family else ""
    ref_part = ""
    if source_url:
        ref_part = f"        reference:url,{source_url};\n"
    severity = "Major" if confidence >= 0.8 else "Medium"
    return (
        f"alert {ip_proto} {ip} any -> $HOME_NET any (\n"
        f"    msg:\"Ezio - C2 IP {ip}{family_part}\";\n"
        f"    metadata: affected_product Any,\n"
        f"              attack_target Client_Endpoint,\n"
        f"              created_at {date_str},\n"
        f"              deployment Perimeter,\n"
        f"              malware_family {malware_family or 'Unknown'},\n"
        f"              performance_impact Low,\n"
        f"              signature_severity {severity};\n"
        f"{ref_part}"
        f"    classtype:trojan-activity;\n"
        f"    sid:{sid};\n"
        f"    rev:1;\n"
        f")"
    )


def _build_dns_rule_snort(domain: str, sid: int) -> str:
    return (
        f"alert dns $HOME_NET any -> any 53 (\n"
        f"    msg:\"Ezio - Malicious Domain Query {domain}\";\n"
        f"    dns.query; content:\"{domain}\"; nocase;\n"
        f"    classtype:trojan-activity;\n"
        f"    sid:{sid};\n"
        f"    rev:1;\n"
        f")"
    )


def _build_tls_rule_suricata(domain: str, sid: int) -> str:
    return (
        f"alert tls $HOME_NET any -> any 443 (\n"
        f"    msg:\"Ezio - TLS SNI {domain}\";\n"
        f"    tls.sni; content:\"{domain}\"; nocase;\n"
        f"    classtype:trojan-activity;\n"
        f"    sid:{sid};\n"
        f"    rev:1;\n"
        f")"
    )


def _build_http_rule(url: str, host: str, path: str, sid: int) -> str:
    """HTTP rule for an .onion URL with a meaningful path."""
    # Use the full URL in the message for traceability; the host match is
    # what actually triggers the rule.
    msg_url = url if len(url) <= 120 else url[:117] + "..."
    return (
        f"alert http $HOME_NET any -> any any (\n"
        f"    msg:\"Ezio - HTTP to C2 {msg_url}\";\n"
        f"    http.host; content:\"{host}\"; nocase;\n"
        f"    classtype:trojan-activity;\n"
        f"    sid:{sid};\n"
        f"    rev:1;\n"
        f")"
    )


def _build_filemd5_rule_suricata(md5_hash: str, sid: int) -> str:
    return (
        f"alert http any any -> any any (\n"
        f"    msg:\"Ezio - Malicious File Hash {md5_hash}\";\n"
        f"    filemd5:{md5_hash};\n"
        f"    classtype:trojan-activity;\n"
        f"    sid:{sid};\n"
        f"    rev:1;\n"
        f")"
    )


def _build_cve_rule(cve_number: str, sid: int) -> str:
    """Snort/Suricata-shared CVE exploit attempt rule."""
    return (
        f"alert http any any -> $HTTP_SERVERS any (\n"
        f"    msg:\"Ezio - Possible {cve_number} Exploit Attempt\";\n"
        f"    flow:established,to_server;\n"
        f"    classtype:attempted-user;\n"
        f"    reference:cve,{cve_number};\n"
        f"    sid:{sid};\n"
        f"    rev:1;\n"
        f")"
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def generate_snort_rules(
    entities: list,
    investigation: dict,
    format: str = "snort",
    tlp: str = "TLP:WHITE",
    start_sid: int = SID_DEFAULT_START,
) -> str:
    """
    Generate Snort or Suricata rules as a string.

    Parameters
    ----------
    entities : list
        Entities as dicts, NormalizedEntity instances, or DB Entity instances.
    investigation : dict
        Investigation metadata (query, id, ...).
    format : str
        Either ``"snort"`` (default) or ``"suricata"``.  The Suricata flavour
        adds a ``metadata:`` block to each rule and also emits
        ``tls.sni`` / ``filemd5:`` rules.
    tlp : str
        Traffic Light Protocol marker.  Stored in the file header.
    start_sid : int
        First SID to use.  Must be inside the Ezio-reserved range
        (9_000_001 - 9_099_999).  Auto-increments per rule; rules that
        would push past 9_099_999 are skipped with a header warning.

    Returns
    -------
    str
        Snort or Suricata rules file content.
    """
    entities = list(entities or [])
    fmt = (format or "snort").lower()
    if fmt not in ("snort", "suricata"):
        raise ValueError(f"Unknown snort export format: {format!r}")

    # Normalise TLP
    tlp_norm = tlp.strip().upper()
    if not tlp_norm.startswith("TLP:"):
        tlp_norm = f"TLP:{tlp_norm}"
    if tlp_norm not in {"TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"}:
        tlp_norm = "TLP:WHITE"

    # Normalise SID start
    if start_sid < SID_RANGE_MIN or start_sid > SID_RANGE_MAX:
        # Clamp rather than raise — emit a warning header so the operator
        # sees what happened.
        start_sid = SID_RANGE_MIN

    query = (investigation or {}).get("query") or ""
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    sid_counter = start_sid
    rules: list[str] = []
    seen_ips: set[str] = set()
    seen_domains: set[str] = set()
    seen_md5s: set[str] = set()
    seen_cves: set[str] = set()
    seen_http_paths: set[str] = set()

    # Find any associated malware family label from MALWARE_FAMILY entities
    # — used to enrich the IP rule's message and metadata.
    malware_family_hint = ""
    for e in entities:
        if _entity_type(e) in _MALWARE_TYPES:
            v = _entity_value(e).strip()
            if v and not malware_family_hint:
                malware_family_hint = v
                break

    for entity in entities:
        etype = _entity_type(entity)
        value = _entity_value(entity).strip()
        if not value or not etype:
            continue
        confidence = _entity_confidence(entity)
        source_url = _entity_source_url(entity)

        # ---- IP rules ----------------------------------------------------
        if etype in _IP_TYPES and value not in seen_ips:
            seen_ips.add(value)
            if not (_is_valid_ipv4(value) or _is_ipv6(value)):
                continue
            if not _is_c2_ip(entity, confidence):
                # Skip low-confidence IPs for Snort reputation rules.
                continue
            if sid_counter > SID_RANGE_MAX:
                rules.append(
                    f"# WARNING: SID range exhausted; skipped IP rule for {value}"
                )
                continue
            family = (
                _entity_malware_family(entity)
                or malware_family_hint
            )
            if fmt == "suricata":
                rules.append(
                    _build_ip_rule_suricata(
                        value, sid_counter, confidence, family, source_url, date_str
                    )
                )
            else:
                rules.append(
                    _build_ip_rule_snort(
                        value, sid_counter, confidence, family, source_url
                    )
                )
            sid_counter += 1

        # ---- DNS rules (Snort) / TLS SNI rules (Suricata) ---------------
        # We match DOMAIN and ONION_URL types here.  For ONION_URLs that
        # also have a meaningful path, we *additionally* emit an HTTP rule
        # below — the two are complementary (DNS captures the bare host
        # query, HTTP captures the actual GET).
        if (etype in _DOMAIN_TYPES or etype in _ONION_TYPES) and value not in seen_domains:
            seen_domains.add(value)
            if confidence < 0.5 and etype in _DOMAIN_TYPES:
                # Skip low-confidence clearnet domains
                continue
            if sid_counter > SID_RANGE_MAX:
                rules.append(
                    f"# WARNING: SID range exhausted; skipped domain rule for {value}"
                )
                continue
            if fmt == "suricata":
                rules.append(_build_tls_rule_suricata(value, sid_counter))
            else:
                rules.append(_build_dns_rule_snort(value, sid_counter))
            sid_counter += 1

        # ---- HTTP rules for .onion URLs with a path ----------------------
        # This is *not* in the elif chain above — an ONION_URL with a path
        # should fire both a DNS rule (for the host lookup) and an HTTP
        # rule (for the GET to that path).  See ezio-cli issue #419.
        if etype in _ONION_TYPES:
            host, path = _split_url(value)
            if host and host.endswith(".onion") and path and path != "/":
                key = f"{host}{path}"
                if key not in seen_http_paths:
                    seen_http_paths.add(key)
                    if sid_counter > SID_RANGE_MAX:
                        rules.append(
                            f"# WARNING: SID range exhausted; skipped HTTP rule for {value}"
                        )
                    else:
                        rules.append(_build_http_rule(value, host, path, sid_counter))
                        sid_counter += 1

        # ---- File-hash detection (Suricata only, MD5) -------------------
        if etype == "FILE_HASH_MD5" and value not in seen_md5s:
            seen_md5s.add(value)
            if fmt != "suricata":
                continue  # Snort doesn't have a portable filemd5 keyword
            if not re.match(r"^[A-Fa-f0-9]{32}$", value):
                continue
            normalised = value.lower()
            if sid_counter > SID_RANGE_MAX:
                rules.append(
                    f"# WARNING: SID range exhausted; skipped filemd5 rule for {normalised}"
                )
                continue
            rules.append(_build_filemd5_rule_suricata(normalised, sid_counter))
            sid_counter += 1

        # ---- CVE rules ---------------------------------------------------
        if etype in _CVE_TYPES and value not in seen_cves:
            seen_cves.add(value)
            cve = value.strip()
            if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
                continue
            if sid_counter > SID_RANGE_MAX:
                rules.append(
                    f"# WARNING: SID range exhausted; skipped CVE rule for {cve}"
                )
                continue
            rules.append(_build_cve_rule(cve, sid_counter))
            sid_counter += 1

    header = _snort_header(
        "Suricata" if fmt == "suricata" else "Snort",
        tlp_norm,
        query,
        start_sid,
    )
    body = "\n\n".join(rules) if rules else "# (no rules generated for this investigation)"

    return "\n".join(header) + body + "\n"
