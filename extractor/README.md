# extractor — Phase 2 Entity Extraction Pipeline

Converts raw scraped text into structured, queryable intelligence records.

## Architecture

```
raw page text
      │
      ▼
┌─────────────────┐
│ regex_patterns  │  Fast, precise extraction of fixed-format entities
│                 │  (wallets, CVEs, IPs, emails, PGP keys, paste URLs)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     ner.py      │  Dictionary + heuristic *candidate generation* for named
│                 │  entities (malware, ransomware, threat actors; spaCy ORG).
│                 │  Acceptance is delegated to entity_shape (not a denylist).
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  llm_extract    │  LLM-assisted extraction (optional, runs only when
│                 │  regex/NER already found entities on the page)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  normalizer     │  Canonical normalisation + per-call dedup.  Name-type
│                 │  candidates pass the entity_shape gate; confidence is
│                 │  computed per entity (see confidence.py).  Upserts to DB.
└────────┬────────┘
         │
         ▼
   ExtractionResult
```

## Entity identity strings (`identity.py`)

`identity.py` is the single source of truth for the three distinct identity
strings the rest of the codebase asks about an entity — replacing the six-plus
places that each derived their own (subtly disagreeing) answer:

- **`entity_graph_id(entity)`** — the key used to identify the entity as a node
  in the relationship graph. Based on the *canonical* value (so `LockBit` and
  `lockbit` resolve to the same node), with the `handle@domain` disambiguation
  preserved for `THREAT_ACTOR_HANDLE`.
- **`entity_canonical_id(entity)`** — the deduplication-safe canonical form used
  for identity comparison, DB uniqueness, and cross-source corroboration. Calls
  `canonicalize_entity_value()` directly on the raw value.
- **`entity_display_id(entity)`** — the human-readable form, preserving original
  casing (whitespace-stripped only).

All three accept either the DB `Entity` ORM object or the in-pipeline
`NormalizedEntity` dataclass and return the identical answer for the same
conceptual entity regardless of source or casing.

## Shape-aware validation & the gazetteer (not a denylist)

Name-type candidates (`THREAT_ACTOR_HANDLE`, `ORGANIZATION_NAME`,
`MALWARE_FAMILY`, `RANSOMWARE_GROUP`) are accepted only if they *plausibly have
the shape of the claimed entity type* or match a maintained known-good reference
set — the opposite of the old "reject if on an ever-growing denylist" approach,
which could only ever suppress strings someone had already seen.

- **`gazetteer.py`** — loads a bundled snapshot of public taxonomies (MITRE
  ATT&CK via MISP galaxy + MISP threat-actor / ransomware / malware clusters)
  from `data/threat_gazetteer.json`.  Each category is stored as structured
  MISP cluster records (`canonical`, `synonyms`, and `uuid`); the loader builds
  an alias index so a known alias can resolve to its canonical name and full
  cluster record without a linear scan.  A match is a strong known-good signal.
- **`entity_shape.py`** — structural + linguistic checks: unusual capitalisation
  (CamelCase / ALLCAPS), embedded digits / leetspeak, separators, org suffixes,
  proper-noun structure, and a comprehensive English dictionary
  (`data/common_words_en.txt`) plus a security-domain lexicon
  (`data/domain_stopwords_en.txt`) to recognise ordinary language.  Returns a
  tier (`gazetteer` / `shape_strong` / `shape_ok` / `shape_weak` / `reject`) and
  a continuous plausibility score.
- **`confidence.py`** — computes a continuous per-entity confidence from real
  signals (validation strength, shape plausibility, context support, method
  prior); corroboration across independent sources is folded in at the batch cap
  stage (`pipeline.apply_entity_cap`).

Refresh the reference data with `python scripts/update_gazetteer.py` (clearnet
fetch of the public taxonomies + dictionary).  Extraction itself never fetches
anything at runtime — it reads only the committed snapshots, so results stay
offline and deterministic.  If a snapshot is missing, the shape checks degrade
gracefully rather than failing.

### Gazetteer synonym coverage

The synonym fields reflect upstream MISP data; the generator does not invent
aliases or backfill missing ones.  Coverage is therefore uneven: the current
source snapshot has 99.0% coverage for MITRE intrusion sets, 96.7% for MITRE
malware, 9.7% for ransomware clusters, and 22.8% for Malpedia.  Across all
8,933 source entries, 2,757 have at least one synonym.  Ransomware and Malpedia
queries will consequently get less alias coverage in the later expansion
phase; a missing synonym is an upstream data-quality characteristic, not a
query-time lookup bug.

Regeneration remains network-dependent: `scripts/update_gazetteer.py` fetches
the ten live MISP cluster files and the English dictionary from GitHub.  There
is no vendored fallback in this phase; improving regeneration reliability is a
separate backlog item.
## Typed relationship extraction (`relationship_extract.py`)

A **distinct** pass from entity extraction. Entity extraction answers *"what
things are on this page"*; this pass answers *"how are those already-identified
things related"*. For the entities already found on a page it asks the LLM which
specific typed relationship (if any) connects each pair, returning a
relationship type, the two entities, and a **claim-specific confidence** that is
separate from the entities' own confidence.

It runs inside `extract_entities_from_pages` after entities are persisted and
before the graph is built, writing `EntityRelationship` rows that the graph
builder's persisted-relationship pass then picks up as typed edges alongside the
co-occurrence edges it generates itself.

- **Additive.** Co-occurrence edges are never removed; typed edges sit beside
  them. A page with no confident typed relationship simply keeps co-occurrence.
- **Bounded vocabulary.** Only `USES`, `DROPS`, `CONTROLS`, `TARGETS`,
  `EXPLOITS`, `COMMUNICATES_WITH`. Anything the LLM cannot map cleanly is
  dropped — no free-text types are invented.
- **Bounded cost.** One LLM call per selected page, at most
  `MAX_REL_PAGES_PER_INV` pages per investigation (default 10). Set
  `ENABLE_RELATIONSHIP_EXTRACTION=false` to disable.

## Entity Types

| Type | Source | Example |
|---|---|---|
| `BITCOIN_ADDRESS` | regex | `bc1qxy2k...`, `1A1z...`, `3J98t...` |
| `ETHEREUM_ADDRESS` | regex | `0x742d35Cc...` |
| `MONERO_ADDRESS` | regex | `4...` (95 chars) |
| `ONION_URL` | regex | `http://xyz.onion/path` |
| `EMAIL_ADDRESS` | regex | `user@example.com` |
| `PGP_KEY_BLOCK` | regex | Full armored block or fingerprint |
| `CVE_NUMBER` | regex | `CVE-2024-12345` |
| `IP_ADDRESS` | regex | Public IPv4 only (RFC1918 excluded) |
| `PHONE_NUMBER` | regex | `+14155552671` |
| `PASTE_URL` | regex | `https://pastebin.com/abc123` |
| `THREAT_ACTOR_HANDLE` | NER | Context-detected username/alias |
| `MALWARE_FAMILY` | NER | `LockBit`, `Emotet`, `RedLine` |
| `RANSOMWARE_GROUP` | NER | `BlackCat`, `REvil`, `Conti` |
| `ORGANIZATION_NAME` | NER | orgs in threat context (spaCy) |

## Usage

```python
from extractor import extract_entities_from_page, extract_entities_from_pages

# Single page
result = await extract_entities_from_page(
    page_text="...",
    page_url="http://example.onion/page",
    page_id=42,
    investigation_id=7,
    llm=my_llm,           # optional
    run_llm_extraction=True,
)
print(result.entity_count, result.entities_by_type)

# Multiple pages (concurrent, semaphore-limited)
results = await extract_entities_from_pages(
    pages=[{"url": "...", "text": "..."}],
    max_concurrent=5,
)
```

## Dependencies

- `spacy` + `en_core_web_sm` model for organisation-name extraction
  - Install model: `python -m spacy download en_core_web_sm`
  - If the model is absent, NER falls back to dictionary + heuristics only
- `eth-utils` (+ `eth-hash[pycryptodome]`) for genuine EIP-55 Ethereum address
  checksum validation — an address written in valid checksummed form reaches the
  `checksum_verified` confidence tier, above `format_verified` for a shape-only
  (e.g. all-lowercase) match.  Full `web3` is accepted as a fallback if present;
  without any checksum library, ETH addresses degrade to `format_verified`.
- Reference data in `data/`: `threat_gazetteer.json`, `common_words_en.txt`,
  `domain_stopwords_en.txt` — regenerated by `scripts/update_gazetteer.py`
- All DB operations require `DATABASE_URL` to be set; without it, entities are
  extracted but not persisted

## Configuration

No new environment variables.  Uses the same `DATABASE_URL` and LLM
configuration (via `llm.py` / `llm_utils.py`) already present from Phase 1.
