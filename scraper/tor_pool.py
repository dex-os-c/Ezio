"""
tor_pool.py — the one Tor stream-isolation session pool for the whole codebase.

Extracted verbatim from `scraper/scrape.py` (v1.9.5), where it was proven, so
that every other Tor-fetching call site can share the same circuits instead of
growing its own credential-less connector.  Before this module existed there
were six independent `ProxyConnector` factories — `scraper/scrape.py`,
`crawler/spider.py`, `search/search.py`, `search/__init__.py`,
`sources/engines.py`, `sources/pastes.py` — and only the first was isolated.

WHY A POOL AND NOT A CONNECTOR PER FETCH
----------------------------------------
Tor's `IsolateSOCKSAuth` SocksPort flag — on by default on a stock SocksPort,
which covers system tor, the container built by docker/Dockerfile.tor, and Tor
Browser — refuses to share a circuit between streams that presented different
SOCKS username/password pairs.  Handing a distinct credential per target
therefore buys a distinct circuit with no ControlPort, no NEWNYM, and no
authentication setup: it is a property of how we *connect*.

python_socks binds SOCKS credentials on the ProxyConnector at construction
time (`ProxyConnector.__init__` stores `_proxy_username` / `_proxy_password`
and `_connect_via_proxy()` reads them off `self`), so there is no per-request
credential override.  One session per *isolation unit* is the reconciliation:

  * repeat fetches to one .onion hostname reuse one connector, so we do not pay
    a fresh SOCKS handshake and circuit build per fetch (the v1.8.0 audit
    category 8 win);
  * fetches to different .onion hostnames get different connectors, different
    credentials, and therefore different circuits.

Both invariants are pinned by tests/test_scrape_isolation.py.  That file is the
contract for this module; if you change the pooling logic, it is what tells you
what you broke.

TIMEOUTS ARE A SESSION-LEVEL DEFAULT, NOT A PER-CALLER SETTING
--------------------------------------------------------------
A pooled session bakes its timeout in at construction, and one session is
shared by every caller that targets the same host.  Callers therefore must NOT
expect their own timeout to win by virtue of asking first — whoever creates the
session for a host decides it.  A caller that genuinely needs different
patience (crawler/spider.py wants a 45 s read where the scraper wants 5 s)
passes `timeout=` on its own `session.get()` call; aiohttp lets a per-request
timeout override the session default, which keeps one shared circuit while
letting patience differ.  See `crawler/spider.py::_fetch`.

POLICY INJECTION
----------------
`get_tor_session_cached` accepts an optional *connector_factory* and *pool_max*
rather than only reading this module's globals.  That exists so `scraper.scrape`
can keep exposing its historical, patchable `_tor_aiohttp_connector` /
`TOR_ISOLATION_POOL_MAX` surface (resolved at call time, so
`unittest.mock.patch.object` still intercepts).  Both default to the canonical
values defined here, which is what every other caller gets — there is exactly
one real policy, and the parameters are a test seam, not a per-caller knob.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections import OrderedDict
from typing import Callable, Dict, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp
from aiohttp_socks import ProxyConnector
from python_socks import ProxyType

import pacing
from config import TOR_PROXY_HOST, TOR_PROXY_PORT

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical policy
# ---------------------------------------------------------------------------

# Isolation unit — the .onion hostname.  Deliberately not per-page or
# per-fetch: multiple pages on one onion service already share an identity from
# Tor's point of view, so finer isolation would only churn circuits.
#
# Bound on the pool.  Real investigations touch ~25 hosts across *all* source
# types, so the onion-only count sits well inside this; the cap exists because
# the pool is module-global and, in the long-lived API process, otherwise grows
# without limit across investigations (`close_pool()` is wired to API shutdown,
# not per-investigation).  Exceeding it is pathological, and the degradation is
# graceful — see `evict_idle_tor_session`.
TOR_ISOLATION_POOL_MAX = 32

# Key "" is the shared, deliberately un-isolated bucket: clearnet-through-Tor
# and callers that ask for a session without naming a target.
_TOR_SHARED_KEY = ""

# Session-level timeout defaults for a pooled session.  These are the `normal`
# pacing baseline; the active profile scales them when the session is built.
TOR_CONNECT_TIMEOUT = 3
TOR_READ_TIMEOUT = 5


def tor_isolation_key(url: str) -> str:
    """
    Return the stream-isolation unit for *url* — its `.onion` hostname.

    Non-onion or unparseable URLs return `_TOR_SHARED_KEY`, so clearnet traffic
    is untouched by this feature (it does not route through Tor at all).

    This onion-only behaviour is pinned by
    tests/test_scrape_isolation.py::test_clearnet_is_not_isolated and must not
    change.  A caller that needs to isolate a *clearnet* host it has chosen to
    route over Tor needs its own key function — see
    `search.tor_isolation.search_engine_isolation_key`.
    """
    try:
        hostname = (urlparse(url).hostname or "").strip().lower()
    except Exception:
        return _TOR_SHARED_KEY
    return hostname if hostname.endswith(".onion") else _TOR_SHARED_KEY


def tor_socks_credentials(key: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Map an isolation key to the SOCKS5 credential pair Tor isolates on.

    `(None, None)` for the shared bucket keeps that path on SOCKS5 no-auth,
    i.e. byte-for-byte the pre-isolation behaviour.

    The credential is a digest of the key rather than the key itself.  It
    carries no secret — Tor already learns the destination hostname from the
    CONNECT request, since we resolve remotely (`rdns=True`) — the digest is
    used because it is fixed-width and unambiguous in logs, where a raw
    hostname in a username field reads like a real credential.
    """
    if not key:
        return None, None
    token = hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:16]
    return f"va-{token}", token


def tor_aiohttp_connector(
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> ProxyConnector:
    """
    SOCKS5 with remote DNS (same behaviour as socks5h) for aiohttp-socks.

    Constructed directly rather than via `from_url` because the credentials are
    supplied as arguments; `from_url` would require embedding (and correctly
    percent-encoding) them into the proxy URL for no gain.

    `limit` is per-connector, and a connector serves a single host, so it
    matches `limit_per_host` — otherwise the effective socket ceiling would be
    `limit` x pool size.

    WHY 10, AND NOT SEARCH'S OLD 2.  `search/search.py` and `search/__init__.py`
    each used `limit=10, limit_per_host=2` before they joined this pool, so the
    two values had to be reconciled rather than carried forward.  The connector
    is now shared, so it has to serve the most demanding caller, and the real
    per-host concurrency of each is:

        scraper/scrape.py   up to 16 (`max_workers` is clamped to 16, and a
                            batch whose URLs are all on one onion service puts
                            all of them on that one host's connector)
        crawler/spider.py   3        (`_DOMAIN_MAX_CONCURRENT`)
        search              1        (the fan-out's semaphore bounds concurrent
                                     *engines*; `_fetch_engine` retries
                                     sequentially, so any one engine has a
                                     single request in flight at a time)

    Search is therefore indifferent between 2 and 10 — it never needs a second
    slot — while 2 would serialise the crawler's 3-per-domain and the scraper's
    same-host batches.  Keeping 2 would have optimised for the caller with the
    least need at the other two's expense.  10 covers the crawler outright and
    covers the scraper's realistic fan-out; in the pathological all-16-on-one-
    host case it queues the extra 6 briefly rather than failing, which is the
    right trade against an unbounded socket count.
    """
    return ProxyConnector(
        proxy_type=ProxyType.SOCKS5,
        host=TOR_PROXY_HOST,
        port=int(TOR_PROXY_PORT),
        username=username,
        password=password,
        rdns=True,
        limit=10,
        limit_per_host=10,
    )


# ---------------------------------------------------------------------------
# Pool state
# ---------------------------------------------------------------------------

# Isolation key -> session, in least-recently-used order.
_tor_sessions: "OrderedDict[str, aiohttp.ClientSession]" = OrderedDict()
# Isolation key -> number of fetches currently holding that session.  An entry
# is only ever evicted at zero, so eviction can never kill an in-flight
# request.
_tor_inflight: Dict[str, int] = {}
# Strong refs to pending close() tasks; asyncio only holds weak ones.
_pending_closes: Set["asyncio.Task"] = set()


def _close_session_soon(session: aiohttp.ClientSession) -> None:
    """Close *session* on the running loop, if there is one, without blocking."""
    if session.closed:
        return
    try:
        task = asyncio.get_running_loop().create_task(session.close())
    except RuntimeError:
        return  # no running loop — the session is dropped; nothing to await on
    _pending_closes.add(task)
    task.add_done_callback(_pending_closes.discard)


def evict_idle_tor_session(pool_max: Optional[int] = None) -> None:
    """
    Make room in the pool by closing one idle isolated session (oldest first).

    Never evicts the shared bucket, and never evicts a key with fetches in
    flight.  If every isolated entry is busy — only reachable if concurrency
    somehow exceeds the cap — the pool is allowed to overshoot rather than
    tear a live circuit out from under a running fetch.
    """
    cap = TOR_ISOLATION_POOL_MAX if pool_max is None else pool_max
    for key, session in list(_tor_sessions.items()):
        if key == _TOR_SHARED_KEY or _tor_inflight.get(key, 0) > 0:
            continue
        _tor_sessions.pop(key, None)
        _tor_inflight.pop(key, None)
        _close_session_soon(session)
        _logger.debug("Tor isolation pool at cap — evicted idle session for %s", key)
        return

    _logger.warning(
        "Tor isolation pool at cap (%d) with every entry in flight — "
        "temporarily exceeding it rather than closing a live circuit",
        cap,
    )


def get_tor_session_cached(
    url: Optional[str] = None,
    *,
    key: Optional[str] = None,
    connector_factory: Optional[Callable[..., ProxyConnector]] = None,
    pool_max: Optional[int] = None,
) -> aiohttp.ClientSession:
    """
    Return the cached Tor-proxied session for *url*'s isolation unit.

    Same hostname in, same session (and so the same circuit) out.  Different
    hostname, different session, different SOCKS credential, different circuit.
    Called with no *url* it returns the shared un-isolated session, which is
    what the pre-isolation single-session behaviour was.

    *key* lets a caller supply an already-computed isolation key, for callers
    whose isolation unit is not `tor_isolation_key(url)` (the search fan-out
    keys on engine hostname).  When given it wins over *url*.
    """
    if key is None:
        key = tor_isolation_key(url) if url else _TOR_SHARED_KEY
    factory = connector_factory or tor_aiohttp_connector
    cap = TOR_ISOLATION_POOL_MAX if pool_max is None else pool_max

    session = _tor_sessions.get(key)
    if session is not None and not session.closed:
        _tor_sessions.move_to_end(key)
        return session

    if session is not None:  # present but closed
        _tor_sessions.pop(key, None)

    if len(_tor_sessions) >= cap:
        evict_idle_tor_session(cap)

    username, password = tor_socks_credentials(key)
    session = aiohttp.ClientSession(
        connector=factory(username, password),
        timeout=aiohttp.ClientTimeout(
            connect=pacing.scale_timeout(TOR_CONNECT_TIMEOUT),
            sock_read=pacing.scale_timeout(TOR_READ_TIMEOUT),
        ),
    )
    _tor_sessions[key] = session
    _tor_sessions.move_to_end(key)
    return session


def acquire_tor_session(
    url: str,
    *,
    key: Optional[str] = None,
    connector_factory: Optional[Callable[..., ProxyConnector]] = None,
    pool_max: Optional[int] = None,
) -> Tuple[aiohttp.ClientSession, str]:
    """
    Resolve *url*'s session and mark it in flight.

    Acquisition is synchronous and happens before the first await, so a session
    handed to a not-yet-started fetch can never be chosen as an eviction
    victim.  Every acquire must be paired with `release_tor_session` in a
    `finally`.
    """
    resolved = tor_isolation_key(url) if key is None else key
    session = get_tor_session_cached(
        url,
        key=resolved,
        connector_factory=connector_factory,
        pool_max=pool_max,
    )
    _tor_inflight[resolved] = _tor_inflight.get(resolved, 0) + 1
    return session, resolved


def release_tor_session(key: str) -> None:
    """Release one in-flight hold on *key*, without leaving a zero entry."""
    remaining = _tor_inflight.get(key, 0) - 1
    if remaining > 0:
        _tor_inflight[key] = remaining
    else:
        _tor_inflight.pop(key, None)


async def reset_tor_session_on_error(
    url: Optional[str] = None,
    *,
    key: Optional[str] = None,
) -> None:
    """
    Drop the cached Tor session for *url*'s isolation unit after a circuit error.

    Scoped to the one isolation key rather than the whole pool: the other
    entries are separate circuits to unrelated hosts, and one dead circuit is
    no evidence against them.

    Called with neither argument it resets the shared bucket, matching the old
    single-session behaviour.
    """
    if key is None:
        key = tor_isolation_key(url) if url else _TOR_SHARED_KEY
    session = _tor_sessions.pop(key, None)
    # Deliberately leaves `_tor_inflight[key]` alone.  That counter is owned by
    # the acquire/release pair; zeroing it here while sibling fetches to the
    # same host are still running would let the *replacement* session be
    # evicted out from under them, which is the one thing the counter exists to
    # prevent.  The stale count drains to zero as those fetches finish.
    if session is not None and not session.closed:
        try:
            await session.close()
        except Exception:
            pass


async def close_pool() -> None:
    """Close every pooled Tor session. Call on shutdown."""
    sessions = list(_tor_sessions.values())
    _tor_sessions.clear()
    _tor_inflight.clear()
    for session in sessions:
        if not session.closed:
            try:
                await session.close()
            except Exception:
                pass

    if _pending_closes:
        await asyncio.gather(*list(_pending_closes), return_exceptions=True)
