"""
Token blacklist using Redis for JWT revocation.

Provides:
- revoke_token(jti, expires_in_seconds): Add JTI to blacklist with TTL
- is_token_revoked(jti): Check if JTI is in blacklist
- is_blacklist_configured(): Whether REDIS_URL is set (revocation opted in)

Behaviour on Redis availability — a *deliberate* design decision, not an
emergent property (see auth/README.md and SECURITY.md):

  * REDIS_URL is NOT set → the token blacklist is intentionally disabled.
    There is no revocation infrastructure; tokens remain valid until their
    natural expiry. ``is_token_revoked`` returns False. This is documented
    fail-open *by design* for operators who choose not to run Redis.

  * REDIS_URL IS set but Redis is unreachable → revocation was explicitly
    opted into, so it is treated as a required control. We cannot confirm a
    token has not been revoked, so ``is_token_revoked`` raises
    ``BlacklistUnavailableError`` and the caller (auth dependency) FAILS
    CLOSED — rejecting the request with a clear 503 — rather than silently
    accepting a possibly-revoked token. Enforcement resumes automatically
    (per-request retry) once Redis is reachable again.

Rationale: Ezio is a single-operator self-hosted tool with 8-hour
(not short-lived) tokens. Silently accepting revoked tokens during a Redis
outage would make logout / session-invalidation unreliable exactly when it
matters, and an attacker could even induce an outage to bypass revocation.
Configuring REDIS_URL is an explicit opt-in to the control, so honouring it
strictly (fail-closed on outage) is the safe default. An operator who would
rather have availability than revocation can simply unset REDIS_URL to
return to the documented fail-open-by-design mode.
"""

import logging
import redis.asyncio as redis
from typing import Optional

from config import REDIS_URL

logger = logging.getLogger(__name__)

_pool: Optional[redis.ConnectionPool] = None
_redis_client: Optional[redis.Redis] = None
_logged_disabled = False

BLACKLIST_PREFIX = "blacklist:"


class BlacklistUnavailableError(RuntimeError):
    """Raised when the blacklist is configured (REDIS_URL set) but Redis is
    unreachable. Callers must fail closed rather than silently fail open."""


def is_blacklist_configured() -> bool:
    """True when REDIS_URL is set — i.e. revocation enforcement was opted in."""
    return REDIS_URL is not None


def _get_client() -> redis.Redis:
    """Return a lazily-created Redis client.

    ``ConnectionPool.from_url`` does not connect eagerly — the actual TCP
    connection is established on the first command, so a client is always
    returned here and unreachability surfaces on the command (which we wrap
    in ``BlacklistUnavailableError``). Only call when ``REDIS_URL`` is set.

    The client is reused across calls; redis-py reconnects transparently when
    Redis recovers, so enforcement resumes without a process restart.
    """
    global _pool, _redis_client
    if _redis_client is None:
        _pool = redis.ConnectionPool.from_url(REDIS_URL, decode_responses=True)
        _redis_client = redis.Redis(connection_pool=_pool)
    return _redis_client


async def revoke_token(jti: str, expires_in_seconds: int) -> bool:
    """
    Add a JWT ID to the blacklist with TTL matching token expiry.

    Returns True if added, False if the blacklist is disabled (REDIS_URL
    unset) or the write failed (Redis unreachable). The logout route treats
    a False result as a hard error when REDIS_URL is set.
    """
    if not is_blacklist_configured():
        return False

    try:
        client = _get_client()
        key = f"{BLACKLIST_PREFIX}{jti}"
        await client.setex(key, expires_in_seconds, "revoked")
        return True
    except Exception as e:
        logger.error("Failed to revoke token %s (Redis unreachable?): %s", jti, e)
        return False


async def is_token_revoked(jti: str) -> bool:
    """
    Check if a JWT ID has been revoked.

    Returns:
        False if the token is not revoked, True if it is.

    Behaviour:
        * REDIS_URL unset  → returns False (blacklist disabled by design).
        * REDIS_URL set, Redis reachable → returns the real result.
        * REDIS_URL set, Redis unreachable → raises BlacklistUnavailableError
          so the caller fails closed.
    """
    global _logged_disabled
    if not is_blacklist_configured():
        if not _logged_disabled:
            logger.info("REDIS_URL not configured — token blacklist disabled (fail-open by design)")
            _logged_disabled = True
        return False

    try:
        client = _get_client()
        key = f"{BLACKLIST_PREFIX}{jti}"
        result = await client.exists(key)
        return result > 0
    except Exception as e:
        logger.error(
            "Token revocation check failed — Redis unreachable (failing closed): %s", e
        )
        raise BlacklistUnavailableError(str(e)) from e


async def close():
    """Close Redis connection pool."""
    global _pool, _redis_client

    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
    if _pool is not None:
        await _pool.disconnect()
        _pool = None
