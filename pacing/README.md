# pacing/

Single source of truth for **how patient Ezio is with an external target**.

Before this module, timeout / retry / politeness values were hardcoded independently
in 15+ places across `scraper/`, `crawler/`, `search/` and `sources/`, with no
relationship to each other. Two of them had already silently drifted from their own
documentation. This module makes one named profile govern all of them.

## The three profiles

| Profile | Intent |
|---|---|
| `quiet` | Maximum patience and politeness. Long timeouts, long gaps between retries, **fewer** retries, much longer inter-request delays. Use against fragile or rate-limiting targets, or when you don't want to look like a scraper. |
| `normal` | The baseline. Every scaled value equals the unmodified constant at its call site. Default. |
| `aggressive` | Minimum patience. Short timeouts, fast retries, minimal politeness delay. Trades completeness for wall-clock. |

Three tiers rather than an nmap-style 0–5: six barely-distinguishable tiers multiply
the surface area to keep consistent across every call site for marginal benefit.
Adding a fourth later costs one row in `_SCALES`.

## Design: multipliers applied to a corrected baseline

`normal` is the source of truth. `quiet` and `aggressive` are *derived* from it by
scale factors — there is no table of absolute per-tier values anywhere. Hand-authoring
three absolute value sets per constant is precisely how the original constants drifted.

Each call site keeps its own `normal` baseline constant where a reader expects it, and
passes it in:

```python
from pacing import retry_plan, scale_timeout

max_retries, retry_delays = retry_plan(MAX_RETRIES, RETRY_DELAYS)
timeout = scale_timeout(SEARCH_TIMEOUT)
```

This keeps `ui.py`'s dependency on the module constants intact and keeps existing tests
that monkeypatch them (e.g. `crawler.spider.RETRY_DELAYS`) working unchanged.

## Scale factors

Relative to `normal` = 1.0:

| | `quiet` | `normal` | `aggressive` |
|---|---|---|---|
| timeouts | 1.75× | 1.0× | 0.55× |
| politeness / rate-limit delays | 2.5× | 1.0× | 0.25× |
| retry backoff | 2.0× | 1.0× | 0.4× |
| retry count | −1 | +0 | +0 |
| adaptive-timeout floor | 1.4× | 1.0× | 0.7× |

Politeness delays scale harder than timeouts because that is what a user actually
means by "be quiet" — a 1.75× timeout is invisible against a healthy target, whereas a
2.5× inter-request gap is the real behaviour change.

All scaled timeouts are clamped to a 2.0 s absolute floor. An `aggressive` profile that
computes a sub-second connect timeout against a Tor circuit isn't fast, it's a
guaranteed failure that wastes the run.

## Two delay helpers, and picking the right one

| Helper | Use for | `aggressive` behaviour |
|---|---|---|
| `scale_delay()` | Ezio's *own* politeness — crawler same-domain gaps, scraper pacing. Nobody published a number; we chose it. | shrinks to 0.25× |
| `scale_delay_floor()` | A delay that encodes a **third party's published quota**. | **clamps at the baseline** |

`scale_delay_floor(x) >= x` for every profile. `quiet` scales the documented interval
*up* (exceeding a rate-limit interval can never cause a 429); `normal` is the identity;
`aggressive` clamps. `aggressive` therefore buys nothing against a rate-limited
provider, and that is the intended outcome — the alternative trades a 429 for a few
seconds of wall-clock, losing the data the run existed to collect.

The asymmetry makes the quota guarantee **structural, not procedural**. A reviewer
confirms one function is monotonic non-decreasing instead of re-verifying a dozen
providers' published limits every time `_SCALES` is retuned.

Getting this wrong is not hypothetical: `github_scraper.py`, `gitlab_scraper.py` and
`paste_scraper.py` shipped using `scale_delay()` on quota-driven delays, so `aggressive`
was pushing all three past their providers' documented per-minute limits in production.

### `rate_limit_delay(min_interval, concurrency)`

A bounding semaphore and a per-request sleep are two mechanisms, and left alone they
*multiply*: N workers each sleeping `min_interval` produce `N / min_interval` requests
per second — N times the documented rate. `rate_limit_delay()` derives both from the
one real-world quota:

```python
_XON_MAX_CONCURRENCY = 2
_XON_MIN_INTERVAL = 0.5          # documented: 2 req/s per IP

pacing.rate_limit_delay(_XON_MIN_INTERVAL, _XON_MAX_CONCURRENCY)   # -> 1.0 s
```

**The caller must sleep *inside* its semaphore**, not after releasing it — the slot has
to stay held for the delay or the arithmetic doesn't apply. It inherits the floor rule.

### Pay the delay on failure, too

Put the sleep in a `finally` inside the semaphore. Three enrichment clients used to
`return` on non-200 before reaching their sleep, so a run of 429s — exactly what a rate
limiter emits — made Ezio speed up instead of backing off. Measured at the time of
the fix: 12 sequential 429s went out with a mean gap of 0.0000 s.

### `retry_after_seconds(source, fallback, *, floor=None, max_wait=120)`

When a provider answers 429 it usually says how long to wait. Honour that instead of
guessing. Handles `Retry-After` (delta-seconds or HTTP-date) and `X-RateLimit-Reset`
(epoch ms, epoch s, or delta-seconds), ignores stale/clock-skewed values, and accepts
either a header mapping or an object whose `str()` contains the headers — the latter
covers LLM clients that bury them in an exception message.

`fallback` applies only when no header is present. `floor` is the minimum in all cases
and defaults to `fallback`. For an enrichment client the two are the same documented
interval: a server saying "1 second" does not license undercutting a documented 15, since
both constraints bind. Where the fallback is a *guess* rather than a quota — the LLM retry
path's 65 s "outlast a 1-minute window" — pass a smaller explicit `floor` so a server
asking for less is actually honoured.

`max_wait` clamps at 120 s. A provider answering "come back in an hour" should degrade
that one source, not block the investigation for an hour.

### `RollingWindow(limit, window)`

For a provider whose limit is a *rolling* window rather than a rate. A flat delay
enforces the correct mean but has no memory of when earlier requests went out, so a
burst-then-idle pattern can still put `limit + 1` requests inside one window. Measured on
a scaled 5-per-1 s model: the flat delay achieved 6 requests in 0.510 s; the window's
tightest 6-request span was 1.006 s.

`acquire(min_spacing=...)` enforces both the window cap *and* a minimum gap between
consecutive requests, because some providers document both (NVD: 5 per rolling 30 s, and
"sleep for six seconds between requests"). Enforcing them in two places is the
semaphore-and-delay multiplication mistake in another costume.

In-process state only. That is enough for a limit scoped to one investigation in one
process, and deliberately does not attempt the cross-process persistence a daily or
weekly quota would need — see pattern 1 in `docs/BACKLOG.md`. Currently NVD is the only
consumer; it stays reusable but nothing else in the tree documents a rolling window.

## The adaptive-timeout interaction

`db/search_engine_stats.py:get_engine_timeout()` is already a self-tuning mechanism: it
multiplies an engine's own observed average response time by 2 and clamps the result
into an 8–45 s window. That behaviour is good and survives intact.

**The profile scales the bounds, never the computed value.** `scale_adaptive_bounds()`
moves the clamp window; the value inside it is still driven by real measured latency.
Multiplying the adaptive *output* by a profile factor would let a guess override a
measurement — the profile would fight the adaptive logic instead of complementing it.

Floor and ceiling move by deliberately different factors: the ceiling takes the full
timeout scale (so `quiet` grants a genuinely slow engine much more room), the floor a
gentler one (so `quiet` is slightly less eager to cut off a fast engine, without the
floor overtaking a latency the engine has actually demonstrated).

## Selecting a profile

Two surfaces, same precedence pattern as `--use-proxies` vs `configure proxy --enable`:

```bash
# One-shot, this run only — does not touch on-disk config
ezio investigate "LockBit ransomware" --pace quiet

# Persistent default across runs
ezio configure pace --profile aggressive
ezio configure pace --show
```

The one-shot flag wins when both are set.

Transport is the `EZIO_PACE` environment variable, matching the existing
`EZIO_USE_PROXIES` / `EZIO_USE_PROXY` chokepoint pattern. That is what lets
library code under `scraper/`, `crawler/`, `search/` and `sources/` read the profile
without importing anything CLI-specific, so the CLI and the API pipeline share one
implementation with no per-caller wiring.

The value is read fresh on every call, never cached at import time — the one-shot flag
sets it inside `run()`, long after `scraper.scrape` has been imported. An unset or
unrecognised value falls back to `normal` silently; a typo must never abort an
investigation.

## Out of scope

- **ScrapingAnt transport timing** — a separate paid transport with its own defaults and
  its own mutual-exclusion/fallback behaviour. Stays independently configured.
- **LLM call timeouts** — patience for a language-model API call, not politeness toward
  a scraped target. Different concern.
- **Tor circuit rotation** — backlog item 1b, not yet implemented. See the TODO at the
  foot of `__init__.py` for the intended interaction when it ships.
