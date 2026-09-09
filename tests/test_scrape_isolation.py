"""
Tor stream isolation (SOCKS5 auth) + the session-reuse guarantee it must not break.

Two invariants are pinned here, and they pull in opposite directions — which is
the whole reason this file exists:

    1. PERFORMANCE (v1.8.0 audit category 8).  Repeat fetches to one .onion
       host must not rebuild a session/connector, because rebuilding meant
       paying a fresh SOCKS handshake and circuit build on every single fetch.
    2. ISOLATION.  Fetches to *different* .onion hosts must NOT share a
       connector, because python_socks binds SOCKS credentials at connector
       construction time, so a shared connector is necessarily a shared
       credential and therefore (under IsolateSOCKSAuth) a shared circuit.

Satisfying (1) by pooling per batch would break (2).  Satisfying (2) by
building per fetch would break (1).  The pool is keyed per isolation unit so
both hold; if a change makes either of these fail, that trade-off is what is
being lost.

Note: aiohttp connectors bind to the running loop at construction, so every
test that builds one is `async def` (pytest.ini sets asyncio_mode = auto).
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from scraper import scrape


@pytest.fixture(autouse=True)
async def _clean_pool():
    """Each test starts and ends with an empty, properly closed isolation pool."""
    scrape._tor_sessions.clear()
    scrape._tor_inflight.clear()
    yield
    for session in list(scrape._tor_sessions.values()):
        if not session.closed:
            await session.close()
    scrape._tor_sessions.clear()
    scrape._tor_inflight.clear()


A1 = "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/one"
A2 = "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion/two"
A3 = "http://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.onion:80/three"
B1 = "http://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion/one"
CLEAR = "https://example.com/page"


# ---------------------------------------------------------------------------
# Isolation key — the unit of isolation is the hostname, nothing finer
# ---------------------------------------------------------------------------


def test_isolation_key_is_the_onion_hostname_not_the_page():
    """Per-page isolation would churn circuits for no anonymity gain."""
    assert scrape.tor_isolation_key(A1) == scrape.tor_isolation_key(A2)
    assert scrape.tor_isolation_key(A1) != scrape.tor_isolation_key(B1)


def test_isolation_key_ignores_case_and_port():
    assert scrape.tor_isolation_key(A3) == scrape.tor_isolation_key(A1)


def test_clearnet_is_not_isolated():
    """Clearnet does not route through Tor at all — this feature must not touch it."""
    assert scrape.tor_isolation_key(CLEAR) == scrape._TOR_SHARED_KEY
    assert scrape.tor_isolation_key("not a url") == scrape._TOR_SHARED_KEY
    assert scrape.tor_socks_credentials(scrape._TOR_SHARED_KEY) == (None, None)


def test_distinct_hosts_get_distinct_socks_credentials():
    """The credential pair is the thing Tor keys IsolateSOCKSAuth on."""
    cred_a = scrape.tor_socks_credentials(scrape.tor_isolation_key(A1))
    cred_b = scrape.tor_socks_credentials(scrape.tor_isolation_key(B1))

    assert cred_a != cred_b
    assert all(part for part in cred_a)
    # Stable across calls, or a "reused" connector would still change circuits.
    assert cred_a == scrape.tor_socks_credentials(scrape.tor_isolation_key(A2))


# ---------------------------------------------------------------------------
# The reconciliation: same host reuses, different host does not
# ---------------------------------------------------------------------------


async def test_same_host_reuses_one_connector_and_different_hosts_do_not():
    """
    The precise claim this feature needs, replacing category 8's coarser
    "repeated fetch, same connector".
    """
    with patch.object(
        scrape, "_tor_aiohttp_connector", wraps=scrape._tor_aiohttp_connector
    ) as build:
        s_a1 = scrape.get_tor_session_cached(A1)
        s_a2 = scrape.get_tor_session_cached(A2)
        s_a3 = scrape.get_tor_session_cached(A3)
        s_b1 = scrape.get_tor_session_cached(B1)

    # Category 8's win, preserved: 4 fetches did not build 4 connectors.
    assert build.call_count == 2, "one connector per distinct host, not per fetch"
    assert s_a1 is s_a2 is s_a3, "same host must reuse the same session"
    assert s_a1 is not s_b1, "different hosts must not share a session"

    creds = {call.args for call in build.call_args_list}
    assert len(creds) == 2, "each connector must be built with its own credential"


async def test_no_rebuild_on_every_fetch_regardless_of_hostname():
    """Category 8's original regression, restated: never one connector per fetch."""
    urls = [A1, A2, B1, A1, B1, A3] * 5

    with patch.object(
        scrape, "_tor_aiohttp_connector", wraps=scrape._tor_aiohttp_connector
    ) as build:
        for url in urls:
            scrape.get_tor_session_cached(url)

    assert build.call_count == 2
    assert build.call_count < len(urls)


async def test_credentials_actually_reach_the_connector():
    """Guards the binding itself — a pool that drops the credential is silent."""
    session = scrape.get_tor_session_cached(A1)
    expected_user, expected_pass = scrape.tor_socks_credentials(
        scrape.tor_isolation_key(A1)
    )

    assert session.connector._proxy_username == expected_user
    assert session.connector._proxy_password == expected_pass
    assert session.connector._rdns is True, "remote DNS is required for .onion"


async def test_shared_bucket_stays_on_socks_no_auth():
    """No-url callers must behave exactly as they did before isolation existed."""
    session = scrape.get_tor_session_cached()

    assert session.connector._proxy_username is None
    assert session.connector._proxy_password is None


# ---------------------------------------------------------------------------
# Pool bounds and lifecycle
# ---------------------------------------------------------------------------


async def test_pool_is_bounded_and_never_evicts_a_busy_entry():
    """Eviction must not tear a live circuit out from under a running fetch."""
    hosts = [f"http://{chr(ord('a') + i) * 56}.onion/" for i in range(26)]

    for url in hosts[:5]:
        scrape._acquire_tor_session(url)  # held in flight, never released

    with patch.object(scrape, "TOR_ISOLATION_POOL_MAX", 8):
        for url in hosts:
            scrape.get_tor_session_cached(url)

    busy = {scrape.tor_isolation_key(u) for u in hosts[:5]}
    assert busy <= set(scrape._tor_sessions), "an in-flight session was evicted"
    # Idle entries above the cap were reclaimed rather than accumulating.
    assert len(scrape._tor_sessions) < len(hosts)


async def test_release_drains_the_inflight_counter():
    _, key = scrape._acquire_tor_session(A1)
    _, key2 = scrape._acquire_tor_session(A2)
    assert key == key2 and scrape._tor_inflight[key] == 2

    scrape._release_tor_session(key)
    assert scrape._tor_inflight[key] == 1
    scrape._release_tor_session(key)
    assert key not in scrape._tor_inflight, "counter must not leak a zero entry"


async def test_fetch_one_releases_its_slot_even_when_the_fetch_raises():
    session, key = scrape._acquire_tor_session(A1)
    assert scrape._tor_inflight[key] == 1

    async def _boom(*_args, **_kwargs):
        raise RuntimeError("fetch exploded")

    with patch.object(scrape, "_fetch_one_impl", _boom):
        with pytest.raises(RuntimeError):
            await scrape._fetch_one(session, {"link": A1}, asyncio.Semaphore(1), key)

    assert key not in scrape._tor_inflight, "a failed fetch leaked its slot"


async def test_circuit_error_reset_is_scoped_to_the_failing_host():
    """Other hosts are separate circuits; one dead circuit is no evidence against them."""
    s_a = scrape.get_tor_session_cached(A1)
    s_b = scrape.get_tor_session_cached(B1)

    await scrape._reset_tor_session_on_error(A1)

    assert scrape.tor_isolation_key(A1) not in scrape._tor_sessions
    assert scrape._tor_sessions.get(scrape.tor_isolation_key(B1)) is s_b
    assert s_a is not s_b


async def test_reset_preserves_the_inflight_count_of_sibling_fetches():
    """
    Zeroing the counter here would let the *replacement* session be evicted
    while sibling fetches to the same host are still using it.
    """
    _, key = scrape._acquire_tor_session(A1)
    _, _ = scrape._acquire_tor_session(A2)
    assert scrape._tor_inflight[key] == 2

    await scrape._reset_tor_session_on_error(A1)

    assert scrape._tor_inflight.get(key) == 2


async def test_closed_session_is_replaced_rather_than_handed_back():
    session = scrape.get_tor_session_cached(A1)
    await session.close()

    replacement = scrape.get_tor_session_cached(A1)
    assert replacement is not session
    assert not replacement.closed


async def test_close_cached_sessions_drains_the_whole_pool():
    scrape.get_tor_session_cached(A1)
    scrape.get_tor_session_cached(B1)
    scrape.get_tor_session_cached()
    assert len(scrape._tor_sessions) == 3

    await scrape.close_cached_sessions()

    assert not scrape._tor_sessions
    assert not scrape._tor_inflight
