#!/usr/bin/env python3
"""
scripts/update_gazetteer.py — Regenerate the bundled threat-intel gazetteer.

The extractor validates candidate THREAT_ACTOR_HANDLE / MALWARE_FAMILY /
RANSOMWARE_GROUP strings against a *maintained external reference set* (a
gazetteer of known threat-actor names, malware families and ransomware groups)
rather than a hand-grown denylist of known-bad strings.  This is the tool that
refreshes that reference set from authoritative public taxonomies.

Sources (all public, clearnet):
  * MISP galaxy clusters — threat-actor, ransomware, malpedia (malware),
    mitre-intrusion-set, mitre-malware, mitre-tool, tool, rat, stealer, banker.
    Each cluster ships a `value`, `uuid`, and (when available) `meta.synonyms`.
  * A common-English-word frequency list (google-10000-english) — used by the
    shape checker to tell "ordinary dictionary word used in its normal sense"
    apart from an entity-shaped token.

Output (committed to the repo so extraction stays offline + deterministic):
  * data/threat_gazetteer.json   — {threat_actors, malware, ransomware, ...},
    with each category containing structured `{canonical, synonyms, uuid}`
    records rather than a flattened list of names.
  * data/common_words_en.txt     — one lowercase common word per line

Run:  python scripts/update_gazetteer.py
Extraction never fetches anything at runtime; it only reads these snapshots.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import requests

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

_MISP_BASE = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters"

# cluster file -> logical category in our gazetteer
_MISP_CLUSTERS = {
    "threat-actor.json": "threat_actors",
    "mitre-intrusion-set.json": "threat_actors",
    "ransomware.json": "ransomware",
    "malpedia.json": "malware",
    "mitre-malware.json": "malware",
    "mitre-tool.json": "malware",
    "tool.json": "malware",
    "rat.json": "malware",
    "stealer.json": "malware",
    "banker.json": "malware",
}

# Comprehensive English dictionary (~370k lowercase words).  Used by the shape
# checker to recognise "ordinary English word" — a large dictionary is what
# makes the open-ended ORGANIZATION_NAME case robust: business/boilerplate
# vocabulary ("synergy", "compliance", "governance", "stakeholder", ...) is in
# it, while entity names ("LockBit", "CrowdStrike", "ALPHV") are not, so a
# candidate built only from dictionary words is rejected as language.
_COMMON_WORDS_URL = (
    "https://raw.githubusercontent.com/dwyl/"
    "english-words/master/words_alpha.txt"
)

# Closed linguistic lexicon of security/cybercrime common nouns.  This is
# ordinary *domain* vocabulary the general-English frequency list omits — the
# negative counterpart to the common-word list used by the shape checker.  It is
# curated (a fixed lexicon of the field's vocabulary), NOT a growing denylist of
# specific observed false positives.  Regenerated here so it lives alongside the
# other reference data; extend the base list when the field's vocabulary grows.
_DOMAIN_STOPWORD_BASE = [
    "payload", "loader", "dropper", "stager", "beacon", "implant", "exploit",
    "malware", "ransomware", "backdoor", "botnet", "phishing", "keylogger",
    "rootkit", "trojan", "stealer", "wiper", "downloader", "injector",
    "shellcode", "obfuscator", "packer", "crypter", "webshell", "credential",
    "exfiltration", "persistence", "lateral", "binary", "dumper", "cracker",
    "bruteforcer", "scanner", "sniffer", "spoofer", "flooder", "booter",
    "stresser", "phisher", "spammer", "carder", "skimmer", "clipper", "grabber",
    "logger", "miner", "cryptor", "builder", "panel", "gate", "checker",
    "validator", "combolist", "dork", "proxy", "socks", "c2", "rat", "apt",
    "ioc", "ttp", "cve", "vulnerability", "malspam", "dropzone", "dropsite",
    "mule", "escrow", "vendor", "marketplace", "listing", "subscription",
    "license", "crypto", "wallet", "mixer", "tumbler", "laundering", "ransom",
    "decryptor", "encryptor", "leaksite", "leak", "dump", "breach", "database",
    "credentials", "cookie", "session", "token", "hash", "command", "control",
    "affiliate", "operator", "initial", "access", "broker",
]


def _fetch_json(url: str) -> dict:
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.json()


def _collect_names(cluster: dict) -> list[dict[str, object]]:
    """Return cluster-identity-preserving records from a MISP cluster file."""
    out: list[dict[str, object]] = []
    for entry in cluster.get("values", []):
        canonical = (entry.get("canonical") or entry.get("value") or "").strip()
        uuid = (entry.get("uuid") or "").strip()
        if not canonical or not uuid:
            continue
        meta = entry.get("meta") or {}
        synonyms = entry.get("synonyms")
        if synonyms is None:
            synonyms = meta.get("synonyms", [])
        if isinstance(synonyms, str):
            synonyms = [synonyms]
        cleaned_synonyms = [
            syn.strip()
            for syn in (synonyms or [])
            if isinstance(syn, str) and syn.strip()
        ]
        out.append({
            "canonical": canonical,
            "synonyms": cleaned_synonyms,
            "uuid": uuid,
        })
    return out


def _merge_record(existing: dict[str, object], incoming: dict[str, object]) -> None:
    """Merge aliases for a UUID seen in more than one source cluster file."""
    known = list(existing.get("synonyms", []))
    for synonym in incoming.get("synonyms", []):
        if synonym not in known:
            known.append(synonym)
    existing["synonyms"] = known


def _coverage(records: list[dict[str, object]]) -> dict[str, object]:
    with_synonyms = sum(bool(record["synonyms"]) for record in records)
    entries = len(records)
    return {
        "entries": entries,
        "with_synonyms": with_synonyms,
        "synonym_coverage_pct": round(with_synonyms / entries * 100, 1)
        if entries else 0.0,
    }


def build_gazetteer() -> dict:
    categories: dict[str, dict[str, dict[str, object]]] = {
        "threat_actors": {},
        "malware": {},
        "ransomware": {},
    }
    used_sources: list[str] = []
    source_coverage: dict[str, dict[str, object]] = {}

    for filename, category in _MISP_CLUSTERS.items():
        url = f"{_MISP_BASE}/{filename}"
        try:
            cluster = _fetch_json(url)
        except Exception as exc:  # noqa: BLE001
            print(f"  ! skipped {filename}: {exc}", file=sys.stderr)
            continue
        records = _collect_names(cluster)
        for record in records:
            uuid = record["uuid"]
            existing = categories[category].get(uuid)
            if existing is None:
                categories[category][uuid] = record
            else:
                _merge_record(existing, record)
        used_sources.append(url)
        source_coverage[filename] = _coverage(records)
        print(
            f"  + {filename}: {len(records)} entries, "
            f"{source_coverage[filename]['with_synonyms']} with synonyms -> {category}"
        )

    # Ransomware groups are also threat actors; make the actor set a superset so
    # a ransomware brand still validates as an actor handle.
    for uuid, record in categories["ransomware"].items():
        existing = categories["threat_actors"].get(uuid)
        if existing is None:
            categories["threat_actors"][uuid] = dict(record)
            categories["threat_actors"][uuid]["synonyms"] = list(record["synonyms"])
        else:
            _merge_record(existing, record)

    category_records = {
        category: sorted(records.values(), key=lambda record: record["canonical"].casefold())
        for category, records in categories.items()
    }
    source_entries = sum(item["entries"] for item in source_coverage.values())
    source_synonyms = sum(item["with_synonyms"] for item in source_coverage.values())

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": used_sources,
        "note": (
            "Regenerate with scripts/update_gazetteer.py. Entries preserve MISP "
            "cluster identity; names are matched case-insensitively after "
            "canonicalisation in extractor/gazetteer.py."
        ),
        "coverage": {
            "source_entries": source_entries,
            "source_entries_with_synonyms": source_synonyms,
            "source_synonym_coverage_pct": round(source_synonyms / source_entries * 100, 1)
            if source_entries else 0.0,
            "categories": {
                category: _coverage(records)
                for category, records in category_records.items()
            },
            "sources": source_coverage,
        },
        "threat_actors": category_records["threat_actors"],
        "malware": category_records["malware"],
        "ransomware": category_records["ransomware"],
    }


def build_common_words() -> list[str]:
    resp = requests.get(_COMMON_WORDS_URL, timeout=120)
    resp.raise_for_status()
    # Dictionary word list — sorted, deduplicated, single-letter words dropped
    # (they carry no signal and would over-match).
    words = {
        w.strip().lower()
        for w in resp.text.splitlines()
        if len(w.strip()) >= 2
    }
    return sorted(words)


def main() -> int:
    os.makedirs(DATA_DIR, exist_ok=True)

    print("Fetching MISP galaxy clusters...")
    gaz = build_gazetteer()
    gaz_path = os.path.join(DATA_DIR, "threat_gazetteer.json")
    with open(gaz_path, "w", encoding="utf-8") as fh:
        json.dump(gaz, fh, ensure_ascii=False, indent=1, sort_keys=False)
    print(
        f"Wrote {gaz_path}: "
        f"{len(gaz['threat_actors'])} actors, "
        f"{len(gaz['malware'])} malware, "
        f"{len(gaz['ransomware'])} ransomware"
    )

    print("Fetching common-words frequency list...")
    words = build_common_words()
    words_path = os.path.join(DATA_DIR, "common_words_en.txt")
    with open(words_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(words) + "\n")
    print(f"Wrote {words_path}: {len(words)} words")

    # Domain stopword lexicon (singulars + plurals), curated + deterministic.
    domain = set(_DOMAIN_STOPWORD_BASE)
    domain |= {w + "s" for w in _DOMAIN_STOPWORD_BASE if not w.endswith("s")}
    domain_path = os.path.join(DATA_DIR, "domain_stopwords_en.txt")
    with open(domain_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(sorted(domain)) + "\n")
    print(f"Wrote {domain_path}: {len(domain)} terms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
