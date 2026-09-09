"""
Tests for pacing applied to the enrichment / reputation API clients
(docs/BACKLOG.md "Class B" — provider-dictated rate-limit delays).

Three distinct guarantees are pinned here, each of which was a real shipped
bug before this suite existed:

  1. Class B sites must route through ``pacing.scale_delay_floor`` /
     ``pacing.rate_limit_delay``, NEVER ``pacing.scale_delay``.  The symmetric
     helper shrinks at 0.25x under ``aggressive``, which pushed GitHub, GitLab
     and Pastebin past their published per-minute limits in production.

  2. The delay must be paid on EVERY response, including non-200.  XposedOrNot,
     LeakCheck and Hudson Rock all returned before their sleep, so a run of
     429s — precisely what a rate limiter emits — made Ezio speed up.

  3. A bounding semaphore and a per-request delay are one mechanism.  N workers
     each sleeping the documented interval produce N times the documented rate.
"""

from __future__ import annotations

import ast
import asyncio
import io
import time

import pytest

import pacing


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set(monkeypatch, profile):
    monkeypatch.setenv(pacing.ENV_VAR, profile)


def _committed_constant(path: str, name: str) -> float:
    """
    Read a module-level numeric constant straight out of the source file.

    Deliberately not ``getattr(module, name)``: tests/conftest.py zeroes these
    intervals so the suite runs fast, which would make an assertion about the
    documented baseline vacuously pass.  This asserts against the value that is
    actually committed.
    """
    tree = ast.parse(io.open(path, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return float(ast.literal_eval(node.value))
    raise AssertionError(f"{name} not found as a module constant in {path}")


class _FakeResponse:
    """Minimal aiohttp response stand-in."""

    def __init__(self, status: int, payload=None, text: str = ""):
        self.status = status
        self._payload = payload if payload is not None else {}
        self._text = text
        self.headers: dict[str, str] = {}

    async def json(self, *args, **kwargs):
        return self._payload

    async def text(self, *args, **kwargs):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    """Returns a scripted sequence of responses and records each call."""

    def __init__(self, responses, calls):
        self._responses = list(responses)
        self._calls = calls

    def get(self, *args, **kwargs):
        self._calls.append(time.perf_counter())
        if self._responses:
            return self._responses.pop(0)
        return _FakeResponse(200, {})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def close(self):
        return None


# ---------------------------------------------------------------------------
# Guarantee 1 — no Class B site uses the symmetric helper
# ---------------------------------------------------------------------------

# (module path, source file) for every module holding a Class B constant.
_CLASS_B_MODULES = [
    "sources/nvd.py",
    "sources/virustotal.py",
    "sources/breach_lookup.py",
    "sources/dns_enrichment.py",
    "sources/infostealer.py",
    "sources/blockchain.py",
    "sources/historical_intel.py",
    "sources/shodan.py",
    "sources/github_scraper.py",
    "sources/gitlab_scraper.py",
    "sources/paste_scraper.py",
]


# The single documented exception: VirusTotal's PREMIUM courtesy delay.  A
# premium key has no published per-minute limit, so that delay is Ezio's
# own choice rather than a quota, and `aggressive` shortening it is correct.  The
# public-tier delay in the same module still uses the floor helper — the test
# below pins both halves so this exception cannot quietly widen.
_SYMMETRIC_DELAY_EXCEPTIONS = {
    "sources/virustotal.py": 1,
}


def _symmetric_delay_callers(path: str) -> list[str]:
    """
    Names of functions in *path* that actually call ``pacing.scale_delay()``.

    Parsed rather than grepped: prose in a docstring or comment legitimately
    names the function while explaining why it is the wrong choice, and a text
    search cannot tell that apart from a real call.
    """
    import ast
    import io as _io

    tree = ast.parse(_io.open(path, encoding="utf-8").read())
    scopes: list[str] = []

    class _Visitor(ast.NodeVisitor):
        def __init__(self):
            self.stack: list[str] = []

        def _enter(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_FunctionDef = _enter
        visit_AsyncFunctionDef = _enter
        visit_ClassDef = _enter

        def visit_Call(self, node):
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name == "scale_delay":
                scopes.append("::".join(self.stack) or "<module>")
            self.generic_visit(node)

    _Visitor().visit(tree)
    return scopes


@pytest.mark.parametrize("path", _CLASS_B_MODULES)
def test_no_class_b_module_calls_the_symmetric_delay_helper(path):
    """
    ``pacing.scale_delay()`` must not be called in a Class B module, save for
    the one documented courtesy-tier exception.

    The failure mode this guards is a maintainer reaching for the
    obvious-looking helper; catching it here beats finding out when a provider
    starts returning 429s.
    """
    callers = _symmetric_delay_callers(path)
    allowed = _SYMMETRIC_DELAY_EXCEPTIONS.get(path, 0)
    assert len(callers) <= allowed, (
        f"{path} calls pacing.scale_delay() on a quota delay, in: "
        f"{callers} ({allowed} call(s) allowed)"
    )


def test_the_symmetric_delay_exception_is_where_it_claims_to_be():
    """The one allowed call must be VirusTotal's tier helper, nowhere else."""
    assert _symmetric_delay_callers("sources/virustotal.py") == ["_vt_delay"]


def test_virustotal_uses_the_floor_for_public_and_symmetric_only_for_premium(
    monkeypatch,
):
    """
    The exception is narrow: public keeps the documented 15 s floor under every
    profile, and only the premium courtesy delay is allowed to shrink.
    """
    from sources import virustotal

    monkeypatch.setattr(virustotal, "VT_API_TIER", "public")
    for profile in ("quiet", "normal", "aggressive"):
        _set(monkeypatch, profile)
        assert virustotal._vt_delay() >= 15.0, profile

    monkeypatch.setattr(virustotal, "VT_API_TIER", "premium")
    _set(monkeypatch, "normal")
    normal = virustotal._vt_delay()
    _set(monkeypatch, "aggressive")
    assert virustotal._vt_delay() < normal


def test_shodan_courtesy_delay_is_floor_protected(monkeypatch):
    """Shodan publishes no limit, but the mechanism must match the others."""
    from config import SHODAN_RATE_LIMIT_DELAY

    for profile in ("quiet", "normal", "aggressive"):
        _set(monkeypatch, profile)
        assert (
            pacing.scale_delay_floor(SHODAN_RATE_LIMIT_DELAY)
            >= SHODAN_RATE_LIMIT_DELAY
        )


# ---------------------------------------------------------------------------
# Guarantee 1b — documented limits, asserted as numbers
# ---------------------------------------------------------------------------


def test_documented_limits_are_respected_at_every_profile(monkeypatch):
    """
    Each baseline must be >= the interval implied by the provider's published
    rate, under all three profiles.  Sourced from each provider's live docs on
    2026-07-29 — see the corrected Class B table in docs/BACKLOG.md.
    """
    # (label, source file, constant, required minimum interval in seconds)
    cases = [
        ("NVD no key (5 req / 30 s)",
         "sources/nvd.py", "_NVD_DELAY_NO_KEY", 6.0),
        ("NVD with key (50 req / 30 s)",
         "sources/nvd.py", "_NVD_DELAY_WITH_KEY", 0.6),
        ("VirusTotal public (4 req/min)",
         "sources/virustotal.py", "_VT_RATE_LIMIT_DELAY", 15.0),
        ("XposedOrNot (2 req/s)",
         "sources/breach_lookup.py", "_XON_MIN_INTERVAL", 0.5),
        ("LeakCheck public (1 req/s)",
         "sources/breach_lookup.py", "_LEAKCHECK_MIN_INTERVAL", 1.0),
        ("BlockCypher (3 req/s)",
         "sources/blockchain.py", "WALLET_REQUEST_DELAY", 0.34),
        ("GitHub search unauth (10 req/min)",
         "sources/github_scraper.py", "SEARCH_RATE_LIMIT_DELAY_UNAUTH", 6.0),
        ("GitHub search auth (30 req/min)",
         "sources/github_scraper.py", "SEARCH_RATE_LIMIT_DELAY_AUTH", 2.0),
        ("GitHub code search (10 req/min, both tiers)",
         "sources/github_scraper.py", "CODE_SEARCH_RATE_LIMIT_DELAY", 6.0),
        ("GitLab search (10 req/min per IP)",
         "sources/gitlab_scraper.py", "SEARCH_RATE_LIMIT_DELAY", 6.0),
    ]

    for profile in ("quiet", "normal", "aggressive"):
        _set(monkeypatch, profile)
        for label, path, name, documented in cases:
            baseline = _committed_constant(path, name)
            applied = pacing.scale_delay_floor(baseline)
            assert applied >= documented, f"{label} under {profile}: {applied}"


def test_leakcheck_baseline_was_corrected_upward():
    """
    Regression pin for the 2.1 Bug 3 fix: 0.4 s against a documented 1 RPS was
    2.5x over the limit even at `normal`.
    """
    committed = _committed_constant(
        "sources/breach_lookup.py", "_LEAKCHECK_MIN_INTERVAL"
    )
    assert committed > 1.0


def test_gitlab_search_delay_does_not_branch_on_the_token():
    """
    GitLab caps /search per IP; a token does not lift it.  Asserting the
    AUTH/UNAUTH constants are *gone* prevents the split being reintroduced.
    """
    from sources import gitlab_scraper

    assert not hasattr(gitlab_scraper, "RATE_LIMIT_DELAY_AUTH")
    assert not hasattr(gitlab_scraper, "RATE_LIMIT_DELAY_UNAUTH")


# ---------------------------------------------------------------------------
# Guarantee 2 — the delay is paid on non-200 responses
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 429, 500, 403])
async def test_xposedornot_pays_the_delay_on_non_200(monkeypatch, status):
    """A 429 must make us slower, not faster."""
    from sources import breach_lookup

    monkeypatch.setattr(breach_lookup, "_XON_MIN_INTERVAL", 0.05)
    monkeypatch.setattr(breach_lookup, "_xon_semaphore", None, raising=False)

    slept: list[float] = []

    async def _record(seconds):
        slept.append(seconds)

    monkeypatch.setattr(breach_lookup.asyncio, "sleep", _record)
    monkeypatch.setattr(
        breach_lookup.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession([_FakeResponse(status)], []),
    )

    await breach_lookup.query_xposedornot("someone@example.com")

    assert slept, f"HTTP {status} skipped the rate-limit delay"
    assert slept[0] > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 429, 500])
async def test_leakcheck_pays_the_delay_on_non_200(monkeypatch, status):
    from sources import breach_lookup

    monkeypatch.setattr(breach_lookup, "_LEAKCHECK_MIN_INTERVAL", 0.05)
    monkeypatch.setattr(breach_lookup, "_leakcheck_semaphore", None, raising=False)

    slept: list[float] = []

    async def _record(seconds):
        slept.append(seconds)

    monkeypatch.setattr(breach_lookup.asyncio, "sleep", _record)
    monkeypatch.setattr(
        breach_lookup.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession([_FakeResponse(status)], []),
    )

    await breach_lookup.query_leakcheck("someone@example.com")

    assert slept, f"HTTP {status} skipped the rate-limit delay"
    assert slept[0] > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 429, 500])
async def test_hudson_rock_pays_the_delay_on_non_200(monkeypatch, status):
    from sources import infostealer

    monkeypatch.setattr(infostealer, "_HR_MIN_INTERVAL", 0.05)
    monkeypatch.setattr(infostealer, "_hr_semaphore", None, raising=False)

    slept: list[float] = []

    async def _record(seconds):
        slept.append(seconds)

    monkeypatch.setattr(infostealer.asyncio, "sleep", _record)
    monkeypatch.setattr(
        infostealer.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession([_FakeResponse(status)], []),
    )

    await infostealer._get_json(
        infostealer._EMAIL_ENDPOINT, {"email": "someone@example.com"}
    )

    assert slept, f"HTTP {status} skipped the rate-limit delay"
    assert slept[0] > 0


# ---------------------------------------------------------------------------
# Guarantee 3 — measured effective rate under concurrency
# ---------------------------------------------------------------------------


async def _measure_effective_rate(query_fn, module, interval_attr, monkeypatch,
                                  concurrency_attr, n_requests=12):
    """
    Fire *n_requests* concurrently through a real semaphore + real sleeps and
    return (elapsed, observed_rate, documented_rate).

    Uses genuinely small intervals so the test runs in ~1 s while still
    exercising the real asyncio.sleep and the real semaphore.
    """
    calls: list[float] = []

    monkeypatch.setattr(
        module.aiohttp,
        "ClientSession",
        lambda *a, **k: _FakeSession(
            [_FakeResponse(200, {}) for _ in range(n_requests)], calls
        ),
    )

    interval = getattr(module, interval_attr)
    concurrency = getattr(module, concurrency_attr)

    start = time.perf_counter()
    await asyncio.gather(*[query_fn(i) for i in range(n_requests)])
    elapsed = time.perf_counter() - start

    observed_rate = n_requests / elapsed if elapsed else float("inf")
    documented_rate = 1.0 / interval
    return elapsed, observed_rate, documented_rate


@pytest.mark.asyncio
async def test_xposedornot_effective_rate_stays_within_the_documented_limit(
    monkeypatch,
):
    """
    MEASURED, not reasoned: 12 concurrent lookups through the real semaphore
    and real sleeps must not exceed 2 req/s scaled to the test interval.
    """
    from sources import breach_lookup

    # Shrink the interval 20x so the test is fast; the RATIO under test is
    # unchanged, which is the property that matters.
    monkeypatch.setattr(breach_lookup, "_XON_MIN_INTERVAL", 0.025)
    monkeypatch.setattr(breach_lookup, "_xon_semaphore", None, raising=False)
    _set(monkeypatch, "aggressive")     # the profile that used to break this

    async def _one(i):
        return await breach_lookup.query_xposedornot(f"user{i}@example.com")

    elapsed, observed, documented = await _measure_effective_rate(
        _one, breach_lookup, "_XON_MIN_INTERVAL", monkeypatch,
        "_XON_MAX_CONCURRENCY",
    )

    assert observed <= documented * 1.15, (
        f"observed {observed:.2f} req/s vs documented {documented:.2f} req/s "
        f"({elapsed:.3f}s elapsed)"
    )


@pytest.mark.asyncio
async def test_leakcheck_effective_rate_stays_within_the_documented_limit(
    monkeypatch,
):
    from sources import breach_lookup

    monkeypatch.setattr(breach_lookup, "_LEAKCHECK_MIN_INTERVAL", 0.055)
    monkeypatch.setattr(breach_lookup, "_leakcheck_semaphore", None, raising=False)
    _set(monkeypatch, "aggressive")

    async def _one(i):
        return await breach_lookup.query_leakcheck(f"user{i}@example.com")

    elapsed, observed, documented = await _measure_effective_rate(
        _one, breach_lookup, "_LEAKCHECK_MIN_INTERVAL", monkeypatch,
        "_LEAKCHECK_MAX_CONCURRENCY",
    )

    assert observed <= documented * 1.15, (
        f"observed {observed:.2f} req/s vs documented {documented:.2f} req/s "
        f"({elapsed:.3f}s elapsed)"
    )


@pytest.mark.asyncio
async def test_hudson_rock_effective_rate_stays_within_its_courtesy_limit(
    monkeypatch,
):
    from sources import infostealer

    monkeypatch.setattr(infostealer, "_HR_MIN_INTERVAL", 0.025)
    monkeypatch.setattr(infostealer, "_hr_semaphore", None, raising=False)
    _set(monkeypatch, "aggressive")

    async def _one(i):
        return await infostealer._get_json(
            infostealer._EMAIL_ENDPOINT, {"email": f"user{i}@example.com"}
        )

    elapsed, observed, documented = await _measure_effective_rate(
        _one, infostealer, "_HR_MIN_INTERVAL", monkeypatch,
        "_HR_MAX_CONCURRENCY",
    )

    assert observed <= documented * 1.15, (
        f"observed {observed:.2f} req/s vs documented {documented:.2f} req/s "
        f"({elapsed:.3f}s elapsed)"
    )


@pytest.mark.asyncio
async def test_semaphore_and_delay_would_multiply_without_the_fix(monkeypatch):
    """
    Demonstrates the bug the derivation prevents, so the test suite documents
    *why* rate_limit_delay multiplies by concurrency rather than just asserting
    that it does.

    Two workers each sleeping the bare 0.5 s interval yield ~4 req/s against a
    documented 2 req/s.  Deriving the delay from (interval x concurrency)
    brings it back to 2.
    """
    interval = 0.5
    concurrency = 2
    documented_rate = 1.0 / interval          # 2 req/s

    naive_rate = concurrency / interval       # what the old code produced
    assert naive_rate == pytest.approx(documented_rate * concurrency)

    _set(monkeypatch, "normal")
    derived = pacing.rate_limit_delay(interval, concurrency)
    fixed_rate = concurrency / derived
    assert fixed_rate == pytest.approx(documented_rate)
