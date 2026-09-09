"""
utils/enrichment_cache.py — Cross-investigation enrichment result cache.

Caches external API responses (AbuseIPDB, GreyNoise, HIBP, URLScan, etc.) by
``(entity_type, value, source)`` so repeated investigations don't re-query
the same indicators. Lives behind a small, async-safe ``EnrichmentCache``
class with three backends:

  1. Redis (preferred when REDIS_URL is set) — key prefix ``va:enrich:``,
     values JSON-encoded, TTL via SETEX.
  2. SQLite (CLI fallback) — table ``enrichment_cache`` in the existing
     investigations DB (``~/.ezio/investigations.db`` by default).
  3. In-memory dict (last resort) — per-process, lost on restart.

Cache misses ALWAYS fall through to the real API call. Cache errors are
logged at DEBUG and never raised to the caller — the cache is a
performance optimization, not a correctness requirement.

Public interface
----------------
EnrichmentCache                — backend-specific implementation
get_enrichment_cache()         — module-level singleton accessor (async)
DEFAULT_TTL                    — per-source TTL map (seconds)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-source TTL defaults (seconds)
# ---------------------------------------------------------------------------

DEFAULT_TTL: dict[str, int] = {
    "abuseipdb":        86400,    # 24 h
    "greynoise":        21600,    # 6 h
    "feodo_tracker":    86400,    # 24 h — but Feodo has its own feed cache; skip
    "c2intelfeeds":     86400,    # 24 h — but C2IntelFeeds has its own feed cache; skip
    "crt_sh":           259200,   # 72 h
    "urlscan":          43200,    # 12 h
    "wayback":          604800,   # 7 days
    "hybrid_analysis":  604800,   # 7 days
    "malwarebazaar":    172800,   # 48 h
    "threatfox":        86400,    # 24 h
    "hibp":             172800,   # 48 h
    "emailrep":         86400,    # 24 h
    "circl_pdns":       86400,    # 24 h
    "circl_pssl":       86400,    # 24 h
    "rdap_whois":       259200,   # 72 h
    "virustotal":       86400,    # 24 h (best-effort; VT has its own response cache)
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ttl_for(source: str, fallback: int = 86400) -> int:
    """Return the recommended TTL (in seconds) for *source*."""
    return DEFAULT_TTL.get(source.lower(), fallback)


def _make_key(entity_type: str, value: str, source: str) -> str:
    """
    Build the canonical cache key.

    Format: ``enrichment:{entity_type}:{source}:{sha256(value)}``.
    SHA-256 keeps keys bounded and avoids quoting issues with special chars
    (emails, IPv6, .onion addresses).
    """
    h = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    et = (entity_type or "").lower().strip()
    src = (source or "").lower().strip()
    return f"enrichment:{et}:{src}:{h}"


# ---------------------------------------------------------------------------
# Backend: in-memory dict
# ---------------------------------------------------------------------------

class _MemoryBackend:
    """Process-local TTL cache. Thread-safe; survives until process exit."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # key → (result_dict, expires_at_monotonic)
        self._data: dict[str, tuple[dict, float]] = {}
        # Lazy cleanup bookkeeping
        self._writes_since_cleanup = 0
        self._cleanup_every = 100

    @property
    def name(self) -> str:
        return "memory"

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            result, expires_at = entry
            if time.monotonic() > expires_at:
                # Expired — evict and report miss
                self._data.pop(key, None)
                return None
            return result

    def set(self, key: str, value: dict, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        with self._lock:
            self._data[key] = (value, time.monotonic() + ttl_seconds)
            self._writes_since_cleanup += 1
            if self._writes_since_cleanup >= self._cleanup_every:
                self._cleanup_expired_locked()

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def size(self) -> int:
        with self._lock:
            self._cleanup_expired_locked()
            return len(self._data)

    def _cleanup_expired_locked(self) -> None:
        now = time.monotonic()
        expired = [k for k, (_, exp) in self._data.items() if now > exp]
        for k in expired:
            self._data.pop(k, None)
        self._writes_since_cleanup = 0

    async def aget(self, key: str) -> Optional[dict]:
        return self.get(key)

    async def aset(self, key: str, value: dict, ttl_seconds: int) -> None:
        self.set(key, value, ttl_seconds)

    async def adelete(self, key: str) -> None:
        self.delete(key)

    async def asize(self) -> int:
        return self.size()


# ---------------------------------------------------------------------------
# Backend: SQLite
# ---------------------------------------------------------------------------

_SQLITE_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS enrichment_cache (
    cache_key    TEXT PRIMARY KEY,
    entity_type  TEXT,
    source       TEXT,
    result_json  TEXT NOT NULL,
    cached_at    TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL
)
"""

_SQLITE_INDEX_EXPIRES = (
    "CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires "
    "ON enrichment_cache(expires_at)"
)


class _SqliteBackend:
    """SQLite-backed cache stored in the existing CLI investigations DB."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._lock = threading.RLock()
        self._db_path = db_path
        self._writes_since_cleanup = 0
        self._cleanup_every = 100
        # Lazy connection — created on first access so that import-time is cheap
        self._init_lock = threading.Lock()
        self._initialised = False

    @property
    def name(self) -> str:
        return "sqlite"

    def _connect(self):
        """Return a sqlite3 connection to the cache DB, creating it if needed."""
        import sqlite3

        if self._db_path is None:
            # Default to ~/.ezio/cache.db — keeps the cache separate
            # from the main investigations DB so a cleanup of one doesn't
            # blow away the other.
            try:
                home = os.path.expanduser("~/.ezio")
                os.makedirs(home, exist_ok=True)
                self._db_path = os.path.join(home, "cache.db")
            except Exception:
                # Last-resort: tmp dir
                import tempfile
                self._db_path = os.path.join(
                    tempfile.gettempdir(), "ezio_cache.db"
                )

        conn = sqlite3.connect(self._db_path, timeout=5, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        if not self._initialised:
            with self._init_lock:
                if not self._initialised:
                    conn.execute(_SQLITE_CREATE_TABLE)
                    conn.execute(_SQLITE_INDEX_EXPIRES)
                    self._initialised = True
        return conn

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def get(self, key: str) -> Optional[dict]:
        try:
            conn = self._connect()
            row = conn.execute(
                "SELECT result_json, expires_at FROM enrichment_cache "
                "WHERE cache_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                return None
            result_json, expires_at = row
            # SQLite returns ISO string for TIMESTAMP text columns
            try:
                exp_dt = datetime.fromisoformat(expires_at)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            except Exception:
                return None
            if exp_dt <= self._now():
                # Expired — best-effort delete (don't fail if it errors)
                try:
                    conn.execute(
                        "DELETE FROM enrichment_cache WHERE cache_key = ?",
                        (key,),
                    )
                except Exception:
                    pass
                return None
            try:
                return json.loads(result_json)
            except Exception:
                return None
        except Exception as exc:
            logger.debug("enrichment_cache: SQLite get failed: %s", exc)
            return None

    def set(self, key: str, value: dict, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        try:
            conn = self._connect()
            now = self._now()
            expires = now.timestamp() + ttl_seconds
            now_s = now.isoformat()
            exp_s = datetime.fromtimestamp(expires, tz=timezone.utc).isoformat()
            payload = json.dumps(value, default=str, separators=(",", ":"))

            # Parse the cache_key for entity_type and source so the table
            # remains queryable for stats / debugging.
            parts = key.split(":")
            entity_type = parts[1] if len(parts) >= 4 else ""
            source = parts[2] if len(parts) >= 4 else ""

            with self._lock:
                conn.execute(
                    "INSERT OR REPLACE INTO enrichment_cache "
                    "(cache_key, entity_type, source, result_json, "
                    " cached_at, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (key, entity_type, source, payload, now_s, exp_s),
                )
                self._writes_since_cleanup += 1
                if self._writes_since_cleanup >= self._cleanup_every:
                    self._cleanup_expired_locked(conn)
        except Exception as exc:
            logger.debug("enrichment_cache: SQLite set failed: %s", exc)

    def delete(self, key: str) -> None:
        try:
            conn = self._connect()
            conn.execute(
                "DELETE FROM enrichment_cache WHERE cache_key = ?",
                (key,),
            )
        except Exception as exc:
            logger.debug("enrichment_cache: SQLite delete failed: %s", exc)

    def size(self) -> int:
        try:
            conn = self._connect()
            self._cleanup_expired(conn)
            row = conn.execute(
                "SELECT COUNT(*) FROM enrichment_cache"
            ).fetchone()
            return int(row[0]) if row else 0
        except Exception as exc:
            logger.debug("enrichment_cache: SQLite size failed: %s", exc)
            return 0

    def _cleanup_expired_locked(self, conn) -> None:
        try:
            now_s = self._now().isoformat()
            conn.execute(
                "DELETE FROM enrichment_cache WHERE expires_at < ?",
                (now_s,),
            )
            self._writes_since_cleanup = 0
        except Exception as exc:
            logger.debug("enrichment_cache: SQLite cleanup failed: %s", exc)

    def _cleanup_expired(self, conn) -> None:
        self._cleanup_expired_locked(conn)

    async def aget(self, key: str) -> Optional[dict]:
        # SQLite ops are blocking but fast — run them off-loop for safety
        return await asyncio.to_thread(self.get, key)

    async def aset(self, key: str, value: dict, ttl_seconds: int) -> None:
        await asyncio.to_thread(self.set, key, value, ttl_seconds)

    async def adelete(self, key: str) -> None:
        await asyncio.to_thread(self.delete, key)

    async def asize(self) -> int:
        return await asyncio.to_thread(self.size)


# ---------------------------------------------------------------------------
# Backend: Redis
# ---------------------------------------------------------------------------

class _RedisBackend:
    """Redis-backed cache using SETEX with JSON-encoded values."""

    KEY_PREFIX = "va:enrich:"

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._client: Any = None
        self._init_lock = asyncio.Lock()
        self._init_failed = False

    @property
    def name(self) -> str:
        return "redis"

    async def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if self._init_failed:
            return None
        async with self._init_lock:
            if self._client is not None:
                return self._client
            try:
                import redis.asyncio as redis  # type: ignore
                self._client = redis.from_url(
                    self._redis_url,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                )
                # Verify connection
                await self._client.ping()
                logger.info(
                    "enrichment_cache: Redis backend ready (%s)",
                    self._redis_url,
                )
            except Exception as exc:
                logger.debug(
                    "enrichment_cache: Redis unavailable (%s) — falling back",
                    exc,
                )
                self._init_failed = True
                self._client = None
        return self._client

    def _full_key(self, key: str) -> str:
        return f"{self.KEY_PREFIX}{key}"

    async def aget(self, key: str) -> Optional[dict]:
        client = await self._get_client()
        if client is None:
            return None
        try:
            raw = await client.get(self._full_key(key))
            if raw is None:
                return None
            try:
                return json.loads(raw)
            except Exception:
                return None
        except Exception as exc:
            logger.debug("enrichment_cache: Redis get failed: %s", exc)
            return None

    async def aset(self, key: str, value: dict, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        client = await self._get_client()
        if client is None:
            return
        try:
            payload = json.dumps(value, default=str, separators=(",", ":"))
            await client.setex(self._full_key(key), ttl_seconds, payload)
        except Exception as exc:
            logger.debug("enrichment_cache: Redis set failed: %s", exc)

    async def adelete(self, key: str) -> None:
        client = await self._get_client()
        if client is None:
            return
        try:
            await client.delete(self._full_key(key))
        except Exception as exc:
            logger.debug("enrichment_cache: Redis delete failed: %s", exc)

    async def asize(self) -> int:
        client = await self._get_client()
        if client is None:
            return 0
        try:
            # SCAN is cheaper than KEYS on large keyspaces
            cursor = 0
            count = 0
            while True:
                cursor, keys = await client.scan(
                    cursor=cursor,
                    match=f"{self.KEY_PREFIX}*",
                    count=200,
                )
                count += len(keys)
                if cursor == 0:
                    break
            return count
        except Exception as exc:
            logger.debug("enrichment_cache: Redis size failed: %s", exc)
            return 0

    # Sync shims (unused, kept for symmetry / future use)
    def get(self, key: str) -> Optional[dict]:  # pragma: no cover
        return None

    def set(self, key: str, value: dict, ttl_seconds: int) -> None:  # pragma: no cover
        return None

    def delete(self, key: str) -> None:  # pragma: no cover
        return None

    def size(self) -> int:  # pragma: no cover
        return 0


# ---------------------------------------------------------------------------
# Public facade
# ---------------------------------------------------------------------------

class EnrichmentCache:
    """
    Async-safe facade over Redis / SQLite / in-memory backends.

    Typical use::

        cache = await get_enrichment_cache()
        cached = await cache.get("IP_ADDRESS", ip, "abuseipdb")
        if cached is not None:
            return cached
        result = await _fetch_abuseipdb(ip)
        await cache.set("IP_ADDRESS", ip, "abuseipdb", result, ttl_seconds=86400)
        return result

    Errors during get/set are swallowed at DEBUG — a failed cache must
    never break an investigation.
    """

    def __init__(self, backend: str = "auto") -> None:
        """
        Parameters
        ----------
        backend : str
            "auto"   — try Redis → SQLite → memory (default)
            "redis"  — force Redis; fall back silently if unavailable
            "sqlite" — force SQLite (uses ~/.ezio/cache.db by default)
            "memory" — force in-memory dict
        """
        self._backend_name = backend.lower().strip()
        self._backend: Any = None
        self._hits = 0
        self._misses = 0
        self._stats_lock = threading.Lock()
        self._resolved = False
        self._resolve_lock = asyncio.Lock()

    @property
    def backend(self) -> str:
        """Name of the active backend ("redis", "sqlite", "memory", or "auto")."""
        if self._backend is None:
            return self._backend_name or "auto"
        return self._backend.name

    async def _resolve_backend(self) -> None:
        """Pick the first backend that initialises, in priority order."""
        if self._resolved:
            return
        async with self._resolve_lock:
            if self._resolved:
                return

            if self._backend_name in ("auto", "redis"):
                redis_url = os.getenv("REDIS_URL") or os.getenv("ENRICHMENT_REDIS_URL")
                if redis_url:
                    candidate = _RedisBackend(redis_url)
                    client = await candidate._get_client()
                    if client is not None:
                        self._backend = candidate
                        self._resolved = True
                        return
                if self._backend_name == "redis":
                    # Explicitly forced — don't fall through
                    self._backend = _MemoryBackend()
                    self._resolved = True
                    return

            if self._backend_name in ("auto", "sqlite"):
                try:
                    self._backend = _SqliteBackend()
                    self._resolved = True
                    return
                except Exception as exc:
                    logger.debug(
                        "enrichment_cache: SQLite backend init failed: %s", exc
                    )

            # Last resort
            self._backend = _MemoryBackend()
            self._resolved = True

    async def _ensure_backend(self) -> Any:
        if not self._resolved or self._backend is None:
            await self._resolve_backend()
        return self._backend

    def _record_hit(self) -> None:
        with self._stats_lock:
            self._hits += 1

    def _record_miss(self) -> None:
        with self._stats_lock:
            self._misses += 1

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(self, entity_type: str, value: str, source: str) -> Optional[dict]:
        """
        Return a previously cached result, or None on miss / error / expiry.
        """
        try:
            backend = await self._ensure_backend()
            key = _make_key(entity_type, value, source)
            result = await backend.aget(key)
            if result is None:
                self._record_miss()
                return None
            self._record_hit()
            return result
        except Exception as exc:
            # Never let cache errors propagate to the caller
            logger.debug("enrichment_cache.get failed: %s", exc)
            self._record_miss()
            return None

    async def set(
        self,
        entity_type: str,
        value: str,
        source: str,
        result: dict,
        ttl_seconds: int,
    ) -> None:
        """
        Store *result* under (entity_type, value, source) for *ttl_seconds*.
        Errors are swallowed at DEBUG.
        """
        try:
            backend = await self._ensure_backend()
            key = _make_key(entity_type, value, source)
            await backend.aset(key, result, ttl_seconds)
        except Exception as exc:
            logger.debug("enrichment_cache.set failed: %s", exc)

    async def invalidate(self, entity_type: str, value: str, source: str) -> None:
        """Force-expire a specific cache entry. Errors are swallowed."""
        try:
            backend = await self._ensure_backend()
            key = _make_key(entity_type, value, source)
            await backend.adelete(key)
        except Exception as exc:
            logger.debug("enrichment_cache.invalidate failed: %s", exc)

    async def stats(self) -> dict:
        """Return a dict describing current cache health."""
        try:
            backend = await self._ensure_backend()
            size = await backend.asize()
        except Exception:
            size = -1
        with self._stats_lock:
            hits = self._hits
            misses = self._misses
        total = hits + misses
        hit_rate = round((hits / total) * 100, 1) if total else 0.0
        return {
            "backend": self.backend,
            "hits": hits,
            "misses": misses,
            "hit_rate_pct": hit_rate,
            "size": size,
            "ttl_defaults": dict(DEFAULT_TTL),
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_cache: Optional[EnrichmentCache] = None
_default_cache_lock = asyncio.Lock()


async def get_enrichment_cache(backend: str = "auto") -> EnrichmentCache:
    """
    Return the process-wide EnrichmentCache singleton.

    The first call picks a backend (auto: Redis → SQLite → memory) and
    caches the instance. Subsequent calls reuse it.
    """
    global _default_cache
    if _default_cache is not None:
        return _default_cache
    async with _default_cache_lock:
        if _default_cache is None:
            _default_cache = EnrichmentCache(backend=backend)
        return _default_cache


def reset_default_cache() -> None:
    """Drop the singleton — used by tests and after backend config changes."""
    global _default_cache
    _default_cache = None


__all__ = [
    "EnrichmentCache",
    "get_enrichment_cache",
    "reset_default_cache",
    "DEFAULT_TTL",
]