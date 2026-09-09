"""
sources/seed_manager.py — Curated .onion seed list manager.

Maintains a JSON-backed catalogue of known-active dark-web addresses
organized by category (ransomware leak sites, hacker forums, carding shops,
search engines, etc.).

At investigation time, get_relevant_seeds(query) scores each seed against
the user query using tag and name matching, and returns the top-N most
relevant entries.  Those seed URLs are injected into the scrape queue
ahead of the search-engine fan-out so that known intelligence sources are
always visited for an applicable query.

Seed file resolution (v1.6.2):
The seed JSON ships INSIDE the installed Python package under
``sources/data/onion_seeds.json`` so it's present after
``pip install ezio``.  We resolve the file via ``importlib.resources``
which works in BOTH pip-installed and local-git-checkout environments:

  - pip-installed: ``sources.data.onion_seeds.json`` (a sub-package whose
    __init__ is empty and whose only file is onion_seeds.json).  Resolved
    by importlib without touching the filesystem path.
  - local checkout: importlib finds the same package via sys.path, and
    the file is served straight from the working tree.  No separate
    "dev mode" code path needed.

The previous implementation used
``Path(__file__).resolve().parent.parent / "data" / "onion_seeds.json"``
which works in a git checkout but silently fails in a pip install
because ``<site-packages>/data/`` does not exist.  That produced the
"Seed file not found: .../site-packages/data/onion_seeds.json" WARNING
every CLI user saw in v1.6.2.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import aiohttp

import pacing
from scraper import tor_pool
from utils.content_safety import is_blocked_url

# Timing baseline (`normal` pacing profile); scaled at call time.
SEED_CHECK_TIMEOUT = 15  # seconds, seed reachability probe

logger = logging.getLogger(__name__)

# Back-compat shim — pre-v1.6.2 callers (and the seed_manager's own
# legacy code) sometimes reference SEED_FILE directly.  We populate it
# lazily so any module that reads it during import gets the correct,
# installed-package-aware path on first access (not the import-time
# v1.6.2-broken sibling-of-sources/ path).
def _resolve_seed_file() -> Path:
    """Return the on-disk path to data/onion_seeds.json, robust to both
    pip-installed and local-checkout invocations.

    Order of resolution:
      1. ``importlib.resources`` against the ``sources.data`` sub-package
         that ships inside the installed wheel.  Works for pip installs.
      2. Walk up from this file looking for ``data/onion_seeds.json`` in
         any parent directory.  Works for local git checkouts where the
         ``sources.data`` sub-package is not importable (it only exists
         when the wheel was built with the new package-data layout).
      3. Fall back to the original v1.6.2-broken sibling-of-sources/
         path so we still get a clear WARNING rather than a hard crash
         if neither path resolves (developer-mode, half-installed env, …).
    """
    # 1. importlib.resources against the installed sub-package.
    try:
        from importlib.resources import files as _files
        candidate = _files("sources").joinpath("data", "onion_seeds.json")
        if candidate.is_file():
            # Convert Traversable to a real Path so callers that
            # expect a Path (file open, .read_text, etc.) work.
            return Path(str(candidate))
    except Exception as exc:
        logger.debug("importlib.resources lookup for sources.data.onion_seeds failed: %s", exc)

    # 2. Walk up from this file's directory looking for data/onion_seeds.json.
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / "data" / "onion_seeds.json"
        if candidate.is_file():
            return candidate

    # 3. Original v1.6.2 path — sibling of sources/.  Will not exist in
    # a clean pip install, but we surface a clear WARNING rather than
    # raising so callers can degrade gracefully.
    legacy = here.parent.parent / "data" / "onion_seeds.json"
    return legacy


def _get_seed_file() -> Path:
    """Memoized accessor for SEED_FILE — keeps SEED_FILE semantics for
    any caller that imports the symbol, but resolves it on first access
    so the resolution logic above has a chance to find the installed
    file instead of the legacy sibling-of-sources/ path.
    """
    global SEED_FILE
    if SEED_FILE is None:
        SEED_FILE = _resolve_seed_file()
    return SEED_FILE


SEED_FILE: Optional[Path] = None


def _read_seed_bytes() -> bytes:
    """Read the seed JSON from whichever install location it's in."""
    # Try the installed package first (importlib.resources).
    try:
        from importlib.resources import files as _files
        candidate = _files("sources").joinpath("data", "onion_seeds.json")
        if candidate.is_file():
            return candidate.read_bytes()
    except Exception:
        pass
    # Fall back to the resolved Path.  Use the memoized accessor so any
    # caller-visible SEED_FILE reflects the correct path on first read.
    path = _get_seed_file()
    return path.read_bytes()


class SeedManager:
    """
    Manages the curated .onion seed list.
    Provides relevance matching and availability checking.
    """

    def __init__(self) -> None:
        self._seeds: list[dict] = []
        self._loaded: bool = False

    def load(self) -> None:
        """Load seeds from JSON file."""
        seed_path = _get_seed_file()
        if not seed_path.exists():
            logger.warning("Seed file not found: %s", seed_path)
            self._seeds = []
            self._loaded = True
            return

        try:
            data = json.loads(_read_seed_bytes().decode("utf-8"))
            self._seeds = []

            for category, cat_data in data.get("categories", {}).items():
                for seed in cat_data.get("seeds", []):
                    self._seeds.append({
                        **seed,
                        "category": category,
                        "category_tags": cat_data.get("tags", []),
                    })

            logger.info(
                "Loaded %d seeds from %s",
                len(self._seeds),
                seed_path,
            )
            self._loaded = True

        except Exception as e:
            logger.error("Failed to load seeds: %s", e)
            self._seeds = []
            self._loaded = True

    def get_relevant_seeds(
        self,
        query: str,
        refined_query: str = "",
        max_seeds: int = 10,
    ) -> list[dict]:
        """
        Return seeds relevant to a query.
        Uses tag matching and keyword scoring.
        """
        if not self._loaded:
            self.load()

        if not self._seeds:
            return []

        search_text = f"{query} {refined_query}".lower()

        scored: list[tuple[int, dict]] = []
        for seed in self._seeds:
            # Skip content-safety blocked URLs
            blocked, _ = is_blocked_url(seed.get("url", ""))
            if blocked:
                continue

            score = 0
            all_tags = list(seed.get("tags", [])) + list(seed.get("category_tags", []))

            # Score by tag matches
            for tag in all_tags:
                if tag.lower() in search_text:
                    score += 3

            # Score by name match (only words longer than 3 chars)
            name = seed.get("name", "").lower()
            for word in search_text.split():
                if len(word) > 3 and word in name:
                    score += 2

            # Boost known-active seeds
            if seed.get("status") == "active":
                score += 1

            # Always include search engines with a base score so generic
            # queries still get a directory to crawl.
            category = seed.get("category", "")
            if "search" in category or "search" in [t.lower() for t in all_tags]:
                score = max(score, 1)

            if score > 0:
                scored.append((score, seed))

        scored.sort(key=lambda x: x[0], reverse=True)
        results = [s for _, s in scored[:max_seeds]]

        logger.info(
            "Seed matching: %d relevant seeds for query '%s'",
            len(results),
            query[:50],
        )

        return results

    async def check_seed_availability(
        self,
        url: str,
        timeout: int = SEED_CHECK_TIMEOUT,
    ) -> bool:
        """
        Check if a seed URL is reachable over Tor.
        Returns True if reachable, False otherwise.
        """
        # Borrowed from the shared Tor pool, keyed on this seed's hostname.
        # This used to build its own credential-less connector per probe, which
        # meant `validate_seeds()` put its 5 concurrent onion probes on one
        # circuit — and it hardcoded 127.0.0.1:9050, so it could never reach the
        # `tor` service under Docker and every seed silently read as dead.  The
        # pool fixes both: it takes the proxy address from config, and each
        # distinct seed host gets its own circuit.
        session, iso_key = tor_pool.acquire_tor_session(url)
        try:
            async with session.get(
                url,
                # Per-request: a reachability probe is allowed to be more
                # patient than the pool's session-level default.
                timeout=aiohttp.ClientTimeout(total=pacing.scale_timeout(timeout)),
                headers={"User-Agent": "Mozilla/5.0 (compatible)"},
                ssl=False,
            ) as resp:
                return resp.status < 500
        except Exception:
            return False
        finally:
            tor_pool.release_tor_session(iso_key)

    async def validate_seeds(self, concurrency: int = 5) -> dict:
        """
        Check which seeds are currently reachable.
        Updates status in the JSON file.
        Returns summary of results.
        """
        if not self._loaded:
            self.load()

        if not self._seeds:
            return {"checked": 0, "active": 0, "dead": 0}

        sem = asyncio.Semaphore(concurrency)
        results = {"active": 0, "dead": 0, "checked": 0}

        async def check_one(seed: dict) -> None:
            async with sem:
                url = seed.get("url", "")
                if not url:
                    return

                is_up = await self.check_seed_availability(url)

                results["checked"] += 1
                if is_up:
                    results["active"] += 1
                    seed["status"] = "active"
                    seed["last_seen"] = datetime.now(timezone.utc).isoformat()
                else:
                    results["dead"] += 1
                    seed["status"] = "unreachable"

                logger.debug(
                    "Seed %s %s",
                    "ok" if is_up else "down",
                    seed.get("name", url[:30]),
                )

        await asyncio.gather(*[check_one(s) for s in self._seeds])

        # Persist status updates back to disk
        self._save_status_updates()

        logger.info(
            "Seed validation: %d/%d active",
            results["active"],
            results["checked"],
        )

        return results

    def add_discovered_seed(
        self,
        url: str,
        name: Optional[str] = None,
        tags: Optional[list[str]] = None,
        category: str = "discovered",
        source_url: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> bool:
        """
        Add a newly discovered onion URL to seeds.
        Called by the pipeline when new onions are found in scraped content.

        No liveness check is performed here — discovery is fast, validation
        is async (handled by the weekly validate_seeds() job). Newly added
        seeds start with status="discovered" and are not promoted to
        "active" until validate_seeds() confirms reachability.

        Optional tracking kwargs:
          source_url       — the page the .onion was found on (provenance)
          investigation_id — the investigation that surfaced it (provenance)

        Returns True if added, False if duplicate or blocked.
        """
        if not self._loaded:
            self.load()

        existing_urls = {s.get("url") for s in self._seeds}
        if url in existing_urls:
            return False

        blocked, _ = is_blocked_url(url)
        if blocked:
            return False

        # Derive a name from hostname when caller did not supply one.
        if not name:
            try:
                from urllib.parse import urlparse
                host = (urlparse(url).hostname or "").lower()
                if host:
                    name = host.split(".")[0][:32] or "discovered-onion"
                else:
                    name = "discovered-onion"
            except Exception:
                name = "discovered-onion"

        new_seed: dict = {
            "name": name,
            "url": url,
            "tags": list(tags or []),
            "category": category,
            "category_tags": [category],
            "status": "discovered",
            "added": datetime.now(timezone.utc).date().isoformat(),
            "added_at": datetime.now(timezone.utc).isoformat(),
        }
        if source_url:
            new_seed["source_url"] = source_url
        if investigation_id:
            new_seed["investigation_id"] = investigation_id

        self._seeds.append(new_seed)
        self._save()

        logger.info("Added new seed: %s", url[:50])
        return True

    async def add_discovered_seed_async(
        self,
        url: str,
        name: Optional[str] = None,
        tags: Optional[list[str]] = None,
        category: str = "discovered",
        source_url: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> bool:
        """
        Async wrapper around add_discovered_seed() — runs the (sync) JSON
        write off the event loop so callers can `await` it without
        stalling the asyncio loop during a heavy scrape fan-out.

        Behavior is identical to the sync method; failures are swallowed
        and logged because seed discovery is fire-and-forget.
        """
        try:
            return await asyncio.to_thread(
                self.add_discovered_seed,
                url,
                name,
                tags,
                category,
                source_url,
                investigation_id,
            )
        except Exception as exc:
            logger.debug(
                "add_discovered_seed_async failed (non-fatal) for %s: %s",
                url[:50] if url else "",
                exc,
            )
            return False

    def summary(self) -> dict:
        """Return counts grouped by category and status."""
        if not self._loaded:
            self.load()

        by_category: dict[str, int] = {}
        by_status: dict[str, int] = {}
        last_validated: Optional[str] = None

        for seed in self._seeds:
            cat = seed.get("category", "unknown")
            by_category[cat] = by_category.get(cat, 0) + 1
            status = seed.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            seen = seed.get("last_seen")
            if seen and (last_validated is None or seen > last_validated):
                last_validated = seen

        return {
            "total": len(self._seeds),
            "by_category": by_category,
            "by_status": by_status,
            "last_validated": last_validated,
        }

    def list_seeds(self) -> list[dict]:
        """Return a snapshot of every seed (admin view)."""
        if not self._loaded:
            self.load()
        return [dict(s) for s in self._seeds]

    def list_discovered_seeds(
        self,
        only_pending: bool = False,
        limit: Optional[int] = None,
    ) -> list[dict]:
        """
        Return auto-discovered seeds (category == "discovered").

        Args:
            only_pending: when True, restrict to seeds still awaiting
                validation (status == "discovered").  Use this for the
                admin endpoint that surfaces work-in-progress.
            limit: optional cap on result count (preserves insertion order).
        """
        if not self._loaded:
            self.load()

        results: list[dict] = []
        for s in self._seeds:
            if s.get("category") != "discovered":
                continue
            if only_pending and s.get("status") != "discovered":
                continue
            results.append(dict(s))
            if limit is not None and len(results) >= limit:
                break
        return results

    def count_by_type(self) -> dict:
        """
        Return permanent-vs-discovered breakdown used by `ezio status --seeds`.
        """
        if not self._loaded:
            self.load()

        permanent = 0
        discovered = 0
        discovered_pending = 0
        discovered_validated = 0
        for s in self._seeds:
            if s.get("category") == "discovered":
                discovered += 1
                if s.get("status") == "discovered":
                    discovered_pending += 1
                elif s.get("status") in ("active", "inactive"):
                    discovered_validated += 1
            else:
                permanent += 1
        return {
            "permanent": permanent,
            "discovered_total": discovered,
            "discovered_pending": discovered_pending,
            "discovered_validated": discovered_validated,
        }

    def list_pending_validation(self) -> list[dict]:
        """Convenience wrapper — discovered seeds still awaiting validate_seeds()."""
        return self.list_discovered_seeds(only_pending=True)

    def _load_raw(self) -> dict:
        """Load the on-disk file structure (preserving category metadata)."""
        seed_path = _get_seed_file()
        if seed_path.exists():
            try:
                return json.loads(_read_seed_bytes().decode("utf-8"))
            except Exception as e:
                logger.warning("Could not parse existing seed file: %s", e)
        return {
            "version": "1.0.0",
            "last_updated": datetime.now(timezone.utc).date().isoformat(),
            "description": "Curated list of known dark web addresses for Ezio intelligence seeding",
            "categories": {},
        }

    def _save_status_updates(self) -> None:
        """Persist status/last_seen changes for known seeds back to disk."""
        try:
            data = self._load_raw()
            categories = data.setdefault("categories", {})

            # Build a (category, url) → in-memory seed map
            updates = {(s.get("category"), s.get("url")): s for s in self._seeds}

            for cat_name, cat_data in categories.items():
                for seed in cat_data.get("seeds", []):
                    key = (cat_name, seed.get("url"))
                    in_mem = updates.get(key)
                    if in_mem is None:
                        continue
                    if "status" in in_mem:
                        seed["status"] = in_mem["status"]
                    if "last_seen" in in_mem:
                        seed["last_seen"] = in_mem["last_seen"]

            data["last_updated"] = datetime.now(timezone.utc).date().isoformat()
            seed_path = _get_seed_file()
            seed_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error("Failed to save seed status updates: %s", e)

    def _save(self) -> None:
        """Save current seeds (including discovered ones) back to JSON."""
        try:
            data = self._load_raw()
            categories = data.setdefault("categories", {})

            # Add discovered seeds to their category bucket
            discovered = [s for s in self._seeds if s.get("category") == "discovered"]
            if discovered:
                bucket = categories.setdefault(
                    "discovered",
                    {
                        "description": "Auto-discovered during investigations",
                        "tags": ["discovered"],
                        "seeds": [],
                    },
                )
                existing_urls = {s["url"] for s in bucket.get("seeds", [])}
                for s in discovered:
                    if s["url"] not in existing_urls:
                        entry: dict = {
                            "name": s["name"],
                            "url": s["url"],
                            "tags": s["tags"],
                            "status": s["status"],
                            "added": s["added"],
                        }
                        # Persist provenance metadata when present so admins can
                        # see where each discovered seed came from.
                        if s.get("source_url"):
                            entry["source_url"] = s["source_url"]
                        if s.get("investigation_id"):
                            entry["investigation_id"] = s["investigation_id"]
                        if s.get("added_at"):
                            entry["added_at"] = s["added_at"]
                        bucket["seeds"].append(entry)
                        existing_urls.add(s["url"])

            data["last_updated"] = datetime.now(timezone.utc).date().isoformat()
            seed_path = _get_seed_file()
            seed_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error("Failed to save seeds: %s", e)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

# Match v3 onion addresses (56 chars) — current standard.
# Match legacy v2 onion addresses (16 chars) — mostly dead since Tor disabled v2
# in Oct 2021 but still useful for archive/forensic content.
_V3_PATTERN = re.compile(r"\b([a-z2-7]{56}\.onion)\b", re.IGNORECASE)
_V2_PATTERN = re.compile(r"\b([a-z2-7]{16}\.onion)\b", re.IGNORECASE)

# Known example/placeholder onion addresses used in tutorials and the Tor
# project docs.  These appear all over the clearnet and are not real
# intelligence targets — filter them out so they don't pollute the seed pool.
_EXAMPLE_PATTERNS = (
    "facebookwkhpilnemx",   # Facebook's official .onion (tutorial example)
    "expyuzz4wqqyqhjn",     # Tor Project example in docs
)

# Cap per-page extraction so a single bloated page can't dump hundreds of
# .onion URLs into the seed pool.  Combined with the per-investigation cap
# (enforced by the caller) this bounds memory and write I/O.
EXTRACT_MAX_PER_PAGE = 20


def extract_onion_urls_from_content(
    content: str,
    max_per_page: int = EXTRACT_MAX_PER_PAGE,
    extra_examples: Optional[Iterable[str]] = None,
) -> list[str]:
    """
    Extract .onion hostnames from arbitrary page content (HTML, plain text,
    forum posts, paste dumps).

    Returns a deduplicated, lowercased list of .onion hostnames capped at
    ``max_per_page``.  Known example/placeholder addresses are filtered
    out automatically; pass ``extra_examples`` to extend the filter.

    No URL scheme is prepended — callers compose ``http://{hostname}`` when
    handing the result to the seed manager.  This keeps the extractor
    independent of HTTP scheme decisions.
    """
    if not content:
        return []

    found: set[str] = set()
    for match in _V3_PATTERN.finditer(content):
        found.add(match.group(1).lower())
    for match in _V2_PATTERN.finditer(content):
        found.add(match.group(1).lower())

    examples = _EXAMPLE_PATTERNS
    if extra_examples:
        examples = examples + tuple(extra_examples)

    filtered = [
        host for host in found
        if not any(p in host for p in examples)
    ]

    return filtered[: max(0, int(max_per_page))]


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_seed_manager: Optional[SeedManager] = None


def get_seed_manager() -> SeedManager:
    """Return the process-wide SeedManager, loading on first access."""
    global _seed_manager
    if _seed_manager is None:
        _seed_manager = SeedManager()
        _seed_manager.load()
    return _seed_manager
