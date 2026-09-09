"""
pacing — the single source of truth for how patient Ezio is with a target.

Every timeout, retry count, retry backoff, and politeness delay used when
talking to an external target (Tor, clearnet, search engines, source scrapers,
the Playwright renderer) is derived here from one named profile.

Three tiers, deliberately:

    quiet       — maximum patience and politeness.  Longer timeouts, longer
                  gaps between retries, *fewer* retries (a quiet run would
                  rather wait than hammer), and substantially longer
                  politeness delays between requests to the same host.
    normal      — the baseline.  Every scaled value is defined as the
                  unmodified constant already living at its call site.
    aggressive  — minimum patience.  Short timeouts, fast retries, minimal
                  politeness delay.  Trades completeness for wall-clock.

Design rule — multipliers, not three hand-authored value sets
-------------------------------------------------------------
``normal`` is the single source of truth.  ``quiet`` and ``aggressive`` are
*derived* from it by the scale factors in ``_SCALES`` below.  There is
deliberately no table of absolute per-tier values anywhere in this codebase:
that is exactly how the 15+ scattered timeout constants this module replaces
drifted apart from each other in the first place.  Adding a fourth tier means
adding one row to ``_SCALES``, not auditing 15 files.

Selection
---------
The active profile is transported as the ``EZIO_PACE`` environment
variable, matching the chokepoint pattern already used for the clearnet
transports (``EZIO_USE_PROXIES`` / ``EZIO_USE_PROXY``).  This is
what lets library code under ``scraper/``, ``crawler/``, ``search/`` and
``sources/`` read the profile without importing anything CLI-specific, so the
CLI and the API pipeline share one implementation.

The value is read on *every* call rather than cached at import time.  Call
sites read their profile at request time, so a profile set after those modules
were imported still takes effect — which is what makes the one-shot
``--pace`` flag work, since Typer sets the env var inside ``run()`` long after
``scraper.scrape`` has been imported.

Baselines stay at their call sites
----------------------------------
This module holds no absolute durations.  Callers pass their own ``normal``
constant in and get the scaled value back::

    max_retries, delays = pacing.retry_plan(MAX_RETRIES, RETRY_DELAYS)

That keeps each module's documented baseline visible where a reader expects
it, keeps ``ui.py``'s dependency on those module constants intact, and keeps
the existing tests that monkeypatch them (e.g. ``crawler.spider.RETRY_DELAYS``)
working unchanged.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from collections import deque
from email.utils import parsedate_to_datetime
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple

__all__ = [
    "PROFILES",
    "DEFAULT_PROFILE",
    "ENV_VAR",
    "get_profile",
    "is_valid_profile",
    "normalize_profile",
    "scale_timeout",
    "scale_timeout_ms",
    "scale_delay",
    "scale_delay_range",
    "scale_delay_floor",
    "rate_limit_delay",
    "retry_after_seconds",
    "RollingWindow",
    "scale_retry_delay",
    "retry_plan",
    "scale_adaptive_bounds",
    "describe",
]

PROFILES: Tuple[str, ...] = ("quiet", "normal", "aggressive")
DEFAULT_PROFILE = "normal"
ENV_VAR = "EZIO_PACE"


class _Scale:
    """Scale factors for one profile, all relative to ``normal`` == 1.0."""

    __slots__ = (
        "timeout",
        "delay",
        "retry_delay",
        "retry_delta",
        "adaptive_floor",
    )

    def __init__(
        self,
        timeout: float,
        delay: float,
        retry_delay: float,
        retry_delta: int,
        adaptive_floor: float,
    ) -> None:
        self.timeout = timeout
        # Politeness / rate-limit delays between requests.  Scales harder than
        # `timeout` because politeness is the thing a user actually means when
        # they say "be quiet" — a 2x timeout is barely noticeable on a healthy
        # target, whereas a 2.5x inter-request gap is the real behaviour change.
        self.delay = delay
        self.retry_delay = retry_delay
        # Applied to the retry *count*.  quiet backs off rather than retrying:
        # one fewer attempt, but much longer waits before the ones it does make.
        self.retry_delta = retry_delta
        # Floor of the adaptive per-engine timeout window.  Deliberately a
        # gentler factor than `timeout` — see scale_adaptive_bounds().
        self.adaptive_floor = adaptive_floor


_SCALES = {
    "quiet":      _Scale(timeout=1.75, delay=2.50, retry_delay=2.00, retry_delta=-1, adaptive_floor=1.40),
    "normal":     _Scale(timeout=1.00, delay=1.00, retry_delay=1.00, retry_delta=+0, adaptive_floor=1.00),
    "aggressive": _Scale(timeout=0.55, delay=0.25, retry_delay=0.40, retry_delta=+0, adaptive_floor=0.70),
}

# Absolute floors.  A scaled value must stay physically sane: an aggressive
# profile that computes a 0.4 s connect timeout against a Tor circuit is not
# "fast", it is a guaranteed failure that wastes the whole run.
_MIN_TIMEOUT = 2.0
_MIN_DELAY = 0.0


def is_valid_profile(name: object) -> bool:
    return isinstance(name, str) and name.strip().lower() in PROFILES


def normalize_profile(name: object) -> str:
    """Return *name* as a canonical profile, or DEFAULT_PROFILE if unusable."""
    if isinstance(name, str):
        candidate = name.strip().lower()
        if candidate in PROFILES:
            return candidate
    return DEFAULT_PROFILE


def get_profile() -> str:
    """
    Return the active profile name.

    Read fresh from the environment on every call — never cached.  An
    unset or unrecognised value falls back to ``normal`` silently: a typo in
    a pacing profile must never be able to abort an investigation, matching
    the "missing optional config disables the feature, it does not crash"
    convention used throughout config.py.
    """
    return normalize_profile(os.environ.get(ENV_VAR))


def _scale() -> _Scale:
    return _SCALES[get_profile()]


# ---------------------------------------------------------------------------
# Scaling helpers
# ---------------------------------------------------------------------------


def scale_timeout(seconds: float) -> float:
    """Scale a ``normal``-baseline timeout, in seconds, for the active profile."""
    return max(_MIN_TIMEOUT, float(seconds) * _scale().timeout)


def scale_timeout_ms(milliseconds: float) -> int:
    """Scale a ``normal``-baseline timeout expressed in milliseconds."""
    return int(scale_timeout(float(milliseconds) / 1000.0) * 1000)


def scale_delay(seconds: float) -> float:
    """Scale a politeness / rate-limit delay for the active profile."""
    return max(_MIN_DELAY, float(seconds) * _scale().delay)


def scale_delay_range(low: float, high: float) -> Tuple[float, float]:
    """
    Scale a ``(low, high)`` randomised politeness window.

    Used by the crawler's same-domain / new-domain delays, which pick a
    uniform sample inside the window; scaling both ends preserves the jitter
    the randomisation exists to provide instead of collapsing it to a point.
    """
    scaled_low = scale_delay(low)
    scaled_high = scale_delay(high)
    if scaled_high < scaled_low:
        scaled_low, scaled_high = scaled_high, scaled_low
    return scaled_low, scaled_high


def scale_delay_floor(seconds: float) -> float:
    """
    Scale a *provider-dictated* rate-limit delay, treating it as a hard floor.

    Use this — never ``scale_delay`` — whenever the baseline is a number some
    third party published as their quota.  The defining property is::

        scale_delay_floor(x) >= x      # for EVERY profile

    Concretely: ``quiet`` scales the documented interval upward (more polite
    than the quota requires, which can never trigger a 429), ``normal`` returns
    it unchanged, and ``aggressive`` **clamps at it** rather than shortening it.
    ``aggressive`` therefore buys nothing against a rate-limited provider, and
    that is the intended outcome — the alternative is trading a 429 for a few
    seconds of wall-clock, which loses the data we came for.

    The asymmetry is what makes the quota guarantee *structural* rather than
    procedural.  A reviewer confirms this one function is monotonic
    non-decreasing, instead of re-verifying a dozen providers' published limits
    every time the scale factors in ``_SCALES`` are tuned.
    """
    baseline = float(seconds)
    # max(1.0, ...) is the whole mechanism: a sub-1.0 delay scale (aggressive)
    # collapses to the identity, so the return value can never dip below the
    # documented baseline no matter how the profile factors are retuned later.
    return max(_MIN_DELAY, baseline * max(1.0, _scale().delay))


def rate_limit_delay(min_interval: float, concurrency: int = 1) -> float:
    """
    Per-worker delay that holds an *aggregate* rate of ``1 / min_interval``
    across ``concurrency`` concurrent workers.

    A bounding semaphore and a per-request sleep are two independent
    mechanisms, and left to themselves they multiply: N workers each sleeping
    ``min_interval`` produce ``N / min_interval`` requests per second, N times
    the documented limit.  Both mechanisms claim to represent the same
    real-world quota, so they must be derived from it together rather than
    tuned separately — that derivation is this function.

    *min_interval* is the documented minimum gap between two requests (i.e.
    ``1 / documented_rate``).  The caller must hold its concurrency slot for
    the duration of the returned delay, otherwise the arithmetic does not
    apply: sleep inside the semaphore, not after releasing it.

    Inherits the floor rule from ``scale_delay_floor``, so no profile can push
    the aggregate rate above the documented limit.
    """
    workers = max(1, int(concurrency))
    return scale_delay_floor(float(min_interval) * workers)


# Absolute ceiling on a server-declared wait.  A provider answering "come back
# in an hour" must not block an investigation for an hour — past this we give up
# on that provider for the run instead, which is the same graceful-degradation
# contract used for a missing API key.
MAX_SERVER_DECLARED_WAIT = 120.0


def _parse_retry_after_value(raw: str, now: float) -> Optional[float]:
    """Parse one ``Retry-After`` value: delta-seconds or an HTTP-date."""
    raw = (raw or "").strip()
    if not raw:
        return None
    if re.fullmatch(r"\d+(\.\d+)?", raw):
        return float(raw)
    try:
        return parsedate_to_datetime(raw).timestamp() - now
    except Exception:
        return None


def _parse_reset_value(raw: str, now: float) -> Optional[float]:
    """
    Parse one ``X-RateLimit-Reset`` value.

    Providers disagree on the units, so the digit count decides: 13 digits is
    epoch milliseconds (OpenRouter), 10 is epoch seconds (GitHub, AbuseIPDB),
    and anything shorter is treated as delta-seconds.
    """
    raw = (raw or "").strip()
    if not re.fullmatch(r"\d+", raw):
        return None
    digits = len(raw)
    value = int(raw)
    if digits >= 13:
        return (value / 1000.0) - now
    if digits >= 10:
        return value - now
    return float(value)


def retry_after_seconds(
    source: Any,
    fallback: float = 0.0,
    *,
    floor: Optional[float] = None,
    max_wait: float = MAX_SERVER_DECLARED_WAIT,
    now: Optional[float] = None,
) -> float:
    """
    How long a provider has explicitly told us to wait.

    *source* is either a response-header mapping (``resp.headers``) or an
    arbitrary object whose ``str()`` may contain the headers — the latter covers
    LLM client libraries that bury the 429 headers in an exception message.

    Honours ``Retry-After`` (delta-seconds or HTTP-date) and
    ``X-RateLimit-Reset`` (epoch ms / epoch s / delta-seconds).

    *fallback* applies only when nothing parseable is present — a provider that
    sends no headers still gets its documented static delay.

    *floor* is the minimum returned in **all** cases, and defaults to *fallback*.
    For an enrichment client the two are the same value: a server saying "1
    second" does not license undercutting a documented 15-second interval, since
    both constraints bind and we have to satisfy both.  Callers whose fallback is
    a guess rather than a documented quota (the LLM retry path, where 65 s is
    just "outlast a 1-minute window") should pass a smaller explicit floor so a
    server asking for less is actually honoured.

    Clamped above by *max_wait*.
    """
    reference = time.time() if now is None else now
    candidates: list[float] = []

    if isinstance(source, Mapping):
        for key, parser in (
            ("Retry-After", _parse_retry_after_value),
            ("X-RateLimit-Reset", _parse_reset_value),
        ):
            raw = source.get(key)
            if raw is None:
                # Header names are case-insensitive; aiohttp's CIMultiDict
                # handles that itself, but a plain dict in a test will not.
                for actual, value in source.items():
                    if str(actual).lower() == key.lower():
                        raw = value
                        break
            if raw is not None:
                parsed = parser(str(raw), reference)
                if parsed is not None:
                    candidates.append(parsed)
    else:
        text = str(source)
        match = re.search(
            r"['\"]?X-RateLimit-Reset['\"]?\s*[:=]\s*['\"]?(\d+)", text, re.I
        )
        if match:
            parsed = _parse_reset_value(match.group(1), reference)
            if parsed is not None:
                candidates.append(parsed)
        match = re.search(
            r"['\"]?Retry-After['\"]?\s*[:=]\s*['\"]?([\d.]+)", text, re.I
        )
        if match:
            parsed = _parse_retry_after_value(match.group(1), reference)
            if parsed is not None:
                candidates.append(parsed)

    # A stale or clock-skewed header can compute negative; ignore those rather
    # than letting them drag the result below the documented floor.
    positive = [c for c in candidates if c > 0]
    effective_floor = float(fallback) if floor is None else float(floor)

    if not positive:
        return min(max(float(fallback), effective_floor), float(max_wait))
    return min(max(max(positive), effective_floor), float(max_wait))


class RollingWindow:
    """
    Tracks request timestamps so a *rolling* window limit is honoured exactly.

    A flat per-request delay only approximates a rolling window: it enforces the
    correct mean rate, but a caller that bursts and then idles can still exceed
    ``limit`` requests inside any ``window`` seconds, because the delay has no
    memory of when the earlier requests went out.

    In-process state only — no persistence.  That is sufficient for a limit
    scoped to one investigation running in one process, and deliberately does
    not attempt the cross-process budget tracking that daily/weekly quotas would
    need (a separate, deferred design question).

    Two constraints, one mechanism.  ``limit``/``window`` is the hard guarantee;
    the optional ``min_spacing`` passed to ``acquire()`` additionally keeps
    consecutive requests apart, because a window limit on its own permits
    ``limit`` requests back-to-back and some providers ask for spacing as well
    as a cap (NVD documents both: 5 per rolling 30 s, and "sleep for six seconds
    between requests").  Enforcing them separately is the semaphore-and-delay
    multiplication mistake in another costume.

    Usage::

        window = RollingWindow(limit=5, window=30.0)
        await window.acquire(min_spacing=6.5)
        ...issue the request...
    """

    __slots__ = ("limit", "window", "_times", "_lock")

    def __init__(self, limit: int, window: float) -> None:
        self.limit = max(1, int(limit))
        self.window = float(window)
        self._times: deque[float] = deque()
        self._lock: Optional[asyncio.Lock] = None

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        while self._times and self._times[0] <= cutoff:
            self._times.popleft()

    def wait_time(
        self,
        now: Optional[float] = None,
        min_spacing: float = 0.0,
    ) -> float:
        """Seconds to wait before the next request; 0.0 if clear to send now."""
        reference = time.monotonic() if now is None else now
        self._prune(reference)

        waits = [0.0]
        if len(self._times) >= self.limit:
            # The oldest in-window request is the one whose expiry frees a slot.
            waits.append(self._times[0] + self.window - reference)
        if min_spacing > 0 and self._times:
            waits.append(self._times[-1] + float(min_spacing) - reference)
        return max(waits)

    async def acquire(self, min_spacing: float = 0.0) -> float:
        """
        Reserve a slot, sleeping if the window is full or spacing not yet met.

        Returns the number of seconds actually slept, which is what a
        measurement harness needs in order to assert the window held.
        """
        # Lazily bound so the object survives being created outside a loop.
        if self._lock is None:
            self._lock = asyncio.Lock()

        slept = 0.0
        async with self._lock:
            wait = self.wait_time(min_spacing=min_spacing)
            if wait > 0:
                await asyncio.sleep(wait)
                slept = wait
            self._times.append(time.monotonic())
        return slept

    def __len__(self) -> int:
        """Requests currently inside the window (prunes first)."""
        self._prune(time.monotonic())
        return len(self._times)

    def reset(self) -> None:
        self._times.clear()


def scale_retry_delay(seconds: float) -> float:
    """
    Scale a single retry backoff delay for the active profile.

    Distinct from ``scale_delay``: a retry backoff is a reaction to a target
    that already failed, not routine politeness between successful requests,
    and the two move by different factors.  Use this for callers that compute
    their backoff from an expression rather than indexing a fixed curve, where
    ``retry_plan`` does not fit.
    """
    return max(_MIN_DELAY, float(seconds) * _scale().retry_delay)


def retry_plan(
    max_retries: int,
    retry_delays: Sequence[float] | Iterable[float],
) -> Tuple[int, Tuple[float, ...]]:
    """
    Return ``(max_retries, retry_delays)`` adjusted for the active profile.

    *max_retries* and *retry_delays* are the caller's ``normal`` baseline.

    ``quiet`` makes one fewer attempt but waits substantially longer before
    each; ``aggressive`` keeps the attempt count and shortens the waits. The
    returned delay tuple is always at least ``max_retries`` long so the
    caller's ``retry_delays[attempt - 1]`` indexing can never raise, even if
    a caller supplies a short or mismatched baseline tuple.
    """
    scale = _scale()
    base_delays = tuple(float(d) for d in retry_delays)

    count = max(0, int(max_retries) + scale.retry_delta)
    scaled = tuple(d * scale.retry_delay for d in base_delays)

    if not scaled:
        return 0, ()

    # Pad by extending the last (largest, since these are backoff curves)
    # delay rather than wrapping around to the start.
    if len(scaled) < count:
        scaled = scaled + (scaled[-1],) * (count - len(scaled))

    return count, scaled[:count] if count else ()


def scale_adaptive_bounds(floor: float, ceiling: float) -> Tuple[float, float]:
    """
    Scale the *bounds* of an adaptive, self-tuning timeout window.

    This is deliberately not ``scale_timeout`` applied twice, and it is
    deliberately not applied to the adaptive value itself.

    ``db.search_engine_stats.get_engine_timeout`` already computes a per-engine
    timeout from that engine's own observed average response time.  That
    self-tuning behaviour is good and must survive this module: multiplying its
    *output* by a profile factor would let the profile fight the adaptive
    logic, overriding a measurement with a guess.  Instead the profile moves
    the window the adaptive value is clamped into, so an engine's real observed
    latency still decides the timeout actually used.

    The floor and ceiling therefore move by *different* factors:

    - ``ceiling`` uses the full timeout scale, so ``quiet`` grants a genuinely
      slow engine much more room before giving up.
    - ``floor`` uses a gentler factor in the same direction, so ``quiet`` is
      also slightly less eager to cut off a fast-responding engine, without
      the floor overtaking a value the engine has actually demonstrated.
    """
    scale = _scale()
    scaled_floor = max(_MIN_TIMEOUT, float(floor) * scale.adaptive_floor)
    scaled_ceiling = max(_MIN_TIMEOUT, float(ceiling) * scale.timeout)
    if scaled_ceiling < scaled_floor:
        scaled_ceiling = scaled_floor
    return scaled_floor, scaled_ceiling


def describe(profile: str | None = None) -> str:
    """Return a one-line human summary of *profile* (default: active)."""
    name = normalize_profile(profile) if profile is not None else get_profile()
    scale = _SCALES[name]
    if name == "normal":
        return "normal — baseline timeouts, retries, and politeness delays"
    return (
        f"{name} — timeouts x{scale.timeout:g}, politeness delays x{scale.delay:g}, "
        f"retry backoff x{scale.retry_delay:g}, retries {scale.retry_delta:+d}"
    )


# ---------------------------------------------------------------------------
# TODO (Tor circuit rotation, backlog item 1b)
# ---------------------------------------------------------------------------
# When per-circuit rotation ships, it is the natural next consumer of this
# module: `quiet` should imply less frequent rotation (each new circuit is
# fresh load on the Tor network and a fresh burst of directory traffic),
# `aggressive` more frequent.  Add a `circuit_rotation` factor to _Scale and
# a `scale_rotation_interval()` helper at that point.  Intentionally not
# implemented here — rotation does not exist yet, and a scale factor with no
# consumer is the dead-constant problem this module was written to remove.
#
# ---------------------------------------------------------------------------
# OPEN QUESTION (Tor stream isolation, backlog item 1c) — pace-INDEPENDENT
# ---------------------------------------------------------------------------
# `scraper/scrape.py` now gives each distinct .onion hostname its own SOCKS
# credential, and therefore its own circuit.  That granularity is currently
# fixed: it does NOT consult this module, on purpose.
#
# The unresolved question is whether it should.  `quiet` arguably implies
# coarser isolation (fewer simultaneous circuit builds is a quieter footprint
# on the network) and `aggressive` finer.  The counter-argument is that
# isolation granularity is an anonymity property, not a politeness one, and
# silently coarsening it under `quiet` would trade away a security guarantee
# to buy a performance characteristic the user did not ask to trade — the
# surprising direction for a flag named "quiet".
#
# Left unresolved rather than guessed at, and recorded here so the interaction
# point is visible to whoever picks up 1b — the two decisions are related and
# should be made together, not one at a time.  Deciding it means adding an
# `isolation` factor to _Scale, not editing scrape.py's pooling logic.
