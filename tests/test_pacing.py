"""Tests for the pacing profile system (pacing/)."""

import pytest

import pacing


@pytest.fixture(autouse=True)
def _clean_pace_env(monkeypatch):
    """Every test starts from an unset profile."""
    monkeypatch.delenv(pacing.ENV_VAR, raising=False)
    yield


def _set(monkeypatch, profile):
    monkeypatch.setenv(pacing.ENV_VAR, profile)


# ---------------------------------------------------------------------------
# Profile selection
# ---------------------------------------------------------------------------


def test_default_profile_is_normal():
    assert pacing.get_profile() == "normal"


@pytest.mark.parametrize("profile", ["quiet", "normal", "aggressive"])
def test_valid_profiles_round_trip(monkeypatch, profile):
    _set(monkeypatch, profile)
    assert pacing.get_profile() == profile


@pytest.mark.parametrize("raw", ["QUIET", "  Aggressive  ", "Normal"])
def test_profile_is_case_and_whitespace_insensitive(monkeypatch, raw):
    _set(monkeypatch, raw)
    assert pacing.get_profile() == raw.strip().lower()


@pytest.mark.parametrize("raw", ["", "turbo", "5", "quie"])
def test_unrecognised_profile_falls_back_silently(monkeypatch, raw):
    """A typo must never abort an investigation."""
    _set(monkeypatch, raw)
    assert pacing.get_profile() == "normal"


def test_profile_is_read_per_call_not_cached(monkeypatch):
    """The one-shot --pace flag sets the env var long after import."""
    assert pacing.get_profile() == "normal"
    _set(monkeypatch, "quiet")
    assert pacing.get_profile() == "quiet"
    _set(monkeypatch, "aggressive")
    assert pacing.get_profile() == "aggressive"


# ---------------------------------------------------------------------------
# Scaling
# ---------------------------------------------------------------------------


def test_normal_is_the_identity_baseline(monkeypatch):
    """`normal` must return every baseline unchanged — it IS the source of truth."""
    _set(monkeypatch, "normal")
    assert pacing.scale_timeout(30) == 30
    assert pacing.scale_delay(6.0) == 6.0
    assert pacing.scale_retry_delay(0.5) == 0.5
    assert pacing.scale_delay_range(2.0, 8.0) == (2.0, 8.0)
    assert pacing.scale_adaptive_bounds(8.0, 45.0) == (8.0, 45.0)
    assert pacing.retry_plan(3, (2.0, 4.0, 8.0)) == (3, (2.0, 4.0, 8.0))


def test_quiet_is_more_patient_than_normal_than_aggressive(monkeypatch):
    values = {}
    for profile in ("quiet", "normal", "aggressive"):
        _set(monkeypatch, profile)
        values[profile] = (pacing.scale_timeout(30), pacing.scale_delay(6.0))

    assert values["quiet"][0] > values["normal"][0] > values["aggressive"][0]
    assert values["quiet"][1] > values["normal"][1] > values["aggressive"][1]


def test_profiles_are_meaningfully_not_marginally_different(monkeypatch):
    """quiet vs aggressive must be a real behaviour change, not noise."""
    _set(monkeypatch, "quiet")
    quiet_timeout, quiet_delay = pacing.scale_timeout(30), pacing.scale_delay(6.0)
    _set(monkeypatch, "aggressive")
    agg_timeout, agg_delay = pacing.scale_timeout(30), pacing.scale_delay(6.0)

    assert quiet_timeout >= agg_timeout * 3
    assert quiet_delay >= agg_delay * 5


def test_scaled_timeout_never_drops_below_the_absolute_floor(monkeypatch):
    """A sub-second Tor connect timeout isn't fast, it's a guaranteed failure."""
    _set(monkeypatch, "aggressive")
    assert pacing.scale_timeout(0.1) >= 2.0
    assert pacing.scale_timeout(3) >= 2.0


def test_delay_range_preserves_jitter(monkeypatch):
    """Scaling both ends must not collapse the randomisation window."""
    _set(monkeypatch, "quiet")
    low, high = pacing.scale_delay_range(2.0, 8.0)
    assert low < high
    assert high / low == pytest.approx(4.0)


def test_scale_timeout_ms_matches_seconds(monkeypatch):
    _set(monkeypatch, "quiet")
    assert pacing.scale_timeout_ms(30_000) == int(pacing.scale_timeout(30.0) * 1000)


# ---------------------------------------------------------------------------
# scale_delay_floor — the quota guarantee
# ---------------------------------------------------------------------------

# Every provider-dictated constant currently in the tree, as (module, attr).
# Kept as a literal list so adding a Class B site without a floor test fails
# review rather than silently shipping.
_CLASS_B_BASELINES = [
    ("sources.nvd", "_NVD_DELAY_NO_KEY"),
    ("sources.nvd", "_NVD_DELAY_WITH_KEY"),
    ("sources.virustotal", "_VT_RATE_LIMIT_DELAY"),
    ("sources.breach_lookup", "_XON_MIN_INTERVAL"),
    ("sources.breach_lookup", "_LEAKCHECK_MIN_INTERVAL"),
    ("sources.dns_enrichment", "CIRCL_DELAY"),
    ("sources.infostealer", "_HR_MIN_INTERVAL"),
    ("sources.blockchain", "WALLET_REQUEST_DELAY"),
    ("sources.historical_intel", "ENTITY_REQUEST_DELAY"),
    ("sources.github_scraper", "SEARCH_RATE_LIMIT_DELAY_UNAUTH"),
    ("sources.github_scraper", "SEARCH_RATE_LIMIT_DELAY_AUTH"),
    ("sources.github_scraper", "CODE_SEARCH_RATE_LIMIT_DELAY"),
    ("sources.github_scraper", "BLOB_FETCH_RATE_LIMIT_DELAY"),
    ("sources.gitlab_scraper", "SEARCH_RATE_LIMIT_DELAY"),
    ("sources.gitlab_scraper", "PROJECT_RATE_LIMIT_DELAY"),
    ("sources.paste_scraper", "DEFAULT_RATE_LIMIT"),
]


@pytest.mark.parametrize("profile", ["quiet", "normal", "aggressive"])
@pytest.mark.parametrize("baseline", [0.4, 0.5, 0.7, 1.0, 1.5, 6.0, 6.5, 15.0])
def test_scale_delay_floor_never_shrinks_under_any_profile(
    monkeypatch, profile, baseline
):
    """
    The defining property: scale_delay_floor(x) >= x, for EVERY profile.

    This is what makes the quota guarantee structural rather than procedural — a
    reviewer confirms this one function is monotonic non-decreasing instead of
    re-verifying a dozen providers' published limits whenever _SCALES is tuned.
    """
    _set(monkeypatch, profile)
    assert pacing.scale_delay_floor(baseline) >= baseline


def test_scale_delay_floor_is_identity_at_normal_and_aggressive(monkeypatch):
    """`aggressive` clamps AT the documented delay — it buys nothing here."""
    for profile in ("normal", "aggressive"):
        _set(monkeypatch, profile)
        assert pacing.scale_delay_floor(6.5) == 6.5


def test_scale_delay_floor_still_lets_quiet_be_more_polite(monkeypatch):
    """Exceeding a rate-limit interval can never cause a 429, so quiet may."""
    _set(monkeypatch, "quiet")
    assert pacing.scale_delay_floor(6.0) > 6.0


def test_scale_delay_is_still_symmetric_for_non_quota_delays(monkeypatch):
    """
    The two helpers must stay distinguishable: scale_delay() is for Ezio's
    own politeness (crawler, scraper) and is allowed to shrink.  If this ever
    starts behaving like the floor variant, callers lose the ability to express
    "aggressive really should be faster here".
    """
    _set(monkeypatch, "aggressive")
    assert pacing.scale_delay(6.0) < 6.0
    assert pacing.scale_delay_floor(6.0) == 6.0


@pytest.mark.parametrize("profile", ["quiet", "normal", "aggressive"])
@pytest.mark.parametrize("module_name,attr", _CLASS_B_BASELINES)
def test_every_class_b_constant_is_floor_protected(
    monkeypatch, profile, module_name, attr
):
    """
    Each provider-dictated constant in the tree, run through the floor helper,
    must come back >= its documented baseline under all three profiles.
    """
    import importlib

    module = importlib.import_module(module_name)
    baseline = getattr(module, attr)
    _set(monkeypatch, profile)
    assert pacing.scale_delay_floor(baseline) >= baseline, f"{module_name}.{attr}"


# ---------------------------------------------------------------------------
# rate_limit_delay — one mechanism for semaphore + delay
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["quiet", "normal", "aggressive"])
@pytest.mark.parametrize("concurrency", [1, 2, 3, 8])
def test_rate_limit_delay_holds_the_aggregate_rate(
    monkeypatch, profile, concurrency
):
    """
    N workers each sleeping the returned delay must not exceed the documented
    aggregate rate.  The bug this prevents: N workers each sleeping the bare
    interval produce N times the documented rate.
    """
    _set(monkeypatch, profile)
    min_interval = 0.5                       # documented 2 req/s
    delay = pacing.rate_limit_delay(min_interval, concurrency)

    effective_interval = delay / concurrency
    assert effective_interval >= min_interval


def test_rate_limit_delay_scales_with_concurrency(monkeypatch):
    _set(monkeypatch, "normal")
    assert pacing.rate_limit_delay(0.5, 1) == 0.5
    assert pacing.rate_limit_delay(0.5, 2) == 1.0
    assert pacing.rate_limit_delay(0.5, 4) == 2.0


def test_rate_limit_delay_treats_bad_concurrency_as_one(monkeypatch):
    _set(monkeypatch, "normal")
    for bad in (0, -1):
        assert pacing.rate_limit_delay(0.5, bad) == 0.5


def test_rate_limit_delay_inherits_the_floor_rule(monkeypatch):
    _set(monkeypatch, "aggressive")
    assert pacing.rate_limit_delay(1.1, 2) >= 2.2


# ---------------------------------------------------------------------------
# Retry plan
# ---------------------------------------------------------------------------


def test_quiet_makes_fewer_attempts_but_waits_longer(monkeypatch):
    """The stated quiet trade-off: back off rather than hammer."""
    _set(monkeypatch, "normal")
    normal_count, normal_delays = pacing.retry_plan(3, (2.0, 4.0, 8.0))
    _set(monkeypatch, "quiet")
    quiet_count, quiet_delays = pacing.retry_plan(3, (2.0, 4.0, 8.0))

    assert quiet_count < normal_count
    assert all(q > n for q, n in zip(quiet_delays, normal_delays))


def test_aggressive_keeps_attempts_and_shortens_waits(monkeypatch):
    _set(monkeypatch, "normal")
    normal_count, normal_delays = pacing.retry_plan(3, (2.0, 4.0, 8.0))
    _set(monkeypatch, "aggressive")
    agg_count, agg_delays = pacing.retry_plan(3, (2.0, 4.0, 8.0))

    assert agg_count == normal_count
    assert all(a < n for a, n in zip(agg_delays, normal_delays))


@pytest.mark.parametrize("profile", ["quiet", "normal", "aggressive"])
def test_retry_delays_are_always_indexable_for_every_attempt(monkeypatch, profile):
    """The caller does retry_delays[attempt - 1]; it must never IndexError."""
    _set(monkeypatch, profile)
    for base_count, base_delays in [
        (3, (2.0, 4.0, 8.0)),
        (1, (1.0,)),
        (5, (1.0, 2.0)),      # deliberately short/mismatched baseline
        (0, ()),
    ]:
        count, delays = pacing.retry_plan(base_count, base_delays)
        for attempt in range(1, count + 1):
            assert delays[attempt - 1] >= 0


def test_retry_count_never_goes_negative(monkeypatch):
    _set(monkeypatch, "quiet")
    count, _ = pacing.retry_plan(0, ())
    assert count == 0


# ---------------------------------------------------------------------------
# Adaptive bounds — the deliberate non-multiplier interaction
# ---------------------------------------------------------------------------


def test_quiet_widens_ceiling_and_raises_floor(monkeypatch):
    _set(monkeypatch, "quiet")
    floor, ceiling = pacing.scale_adaptive_bounds(8.0, 45.0)
    assert ceiling > 45.0      # more room for a genuinely slow engine
    assert floor > 8.0         # slightly less eager to clamp a fast one


def test_aggressive_tightens_both_bounds(monkeypatch):
    _set(monkeypatch, "aggressive")
    floor, ceiling = pacing.scale_adaptive_bounds(8.0, 45.0)
    assert ceiling < 45.0
    assert floor < 8.0


def test_floor_never_exceeds_ceiling(monkeypatch):
    for profile in ("quiet", "normal", "aggressive"):
        _set(monkeypatch, profile)
        floor, ceiling = pacing.scale_adaptive_bounds(40.0, 41.0)
        assert floor <= ceiling


def test_adaptive_computation_stays_latency_driven_under_every_profile(monkeypatch):
    """
    The core interaction guarantee.

    An engine that has demonstrated a 6 s average must get the same
    latency-derived 12 s timeout under every profile — the profile moves the
    clamp window, it does not override the measurement.
    """
    from db.search_engine_stats import get_engine_timeout

    stats = {"total_attempts": 10, "avg_response_time_ms": 6000.0}
    results = {}
    for profile in ("quiet", "normal", "aggressive"):
        _set(monkeypatch, profile)
        results[profile] = get_engine_timeout(stats)

    assert results == {"quiet": 12.0, "normal": 12.0, "aggressive": 12.0}


def test_adaptive_timeout_tracks_observed_latency_within_a_profile(monkeypatch):
    """Faster engine → shorter timeout, under each profile independently."""
    from db.search_engine_stats import get_engine_timeout

    for profile in ("quiet", "normal", "aggressive"):
        _set(monkeypatch, profile)
        fast = get_engine_timeout({"total_attempts": 5, "avg_response_time_ms": 5000.0})
        slow = get_engine_timeout({"total_attempts": 5, "avg_response_time_ms": 10000.0})
        assert fast < slow, profile


def test_profile_decides_cutoff_for_an_engine_past_the_ceiling(monkeypatch):
    """Where the profile SHOULD bite: an engine slower than the normal ceiling."""
    from db.search_engine_stats import get_engine_timeout

    stats = {"total_attempts": 10, "avg_response_time_ms": 40_000.0}  # → 80 s raw
    _set(monkeypatch, "quiet")
    quiet = get_engine_timeout(stats)
    _set(monkeypatch, "aggressive")
    aggressive = get_engine_timeout(stats)

    assert quiet > 45.0 > aggressive


# ---------------------------------------------------------------------------
# Single source of truth — call sites read from pacing
# ---------------------------------------------------------------------------


def test_search_config_accessors_follow_the_profile(monkeypatch):
    from search import config as search_config

    _set(monkeypatch, "normal")
    assert search_config.search_timeout() == search_config.SEARCH_TIMEOUT
    assert search_config.engine_retry_count() == search_config.ENGINE_RETRY_COUNT

    _set(monkeypatch, "quiet")
    quiet_timeout = search_config.search_timeout()
    quiet_backoff = search_config.retry_backoff(0)
    _set(monkeypatch, "aggressive")
    assert quiet_timeout > search_config.search_timeout()
    assert quiet_backoff > search_config.retry_backoff(0)


def test_both_search_callers_inherit_one_config(monkeypatch):
    """The 1.9.4 consolidation means one wiring point, not two."""
    import search
    import search.search as search_mod

    assert search.search_config is search_mod.search_config


def test_dead_engine_timeout_constant_is_gone():
    import search
    import search.search as search_mod
    from search import config as search_config

    for module in (search, search_mod, search_config):
        assert not hasattr(module, "ENGINE_TIMEOUT"), module.__name__


def test_scrape_baseline_matches_its_documented_intent():
    """The v1.9.4 contradiction: MAX_RETRIES=1 vs a docstring promising 3/2/4/8."""
    from scraper import scrape

    assert scrape.MAX_RETRIES == 3
    assert scrape.RETRY_DELAYS == (2.0, 4.0, 8.0)
    assert "3-attempt exponential backoff (2 s / 4 s / 8 s)" in scrape.__doc__


def test_scraper_and_crawler_share_one_baseline():
    """Both were written against the same design; they must not drift again."""
    from crawler import spider
    from scraper import scrape

    assert scrape.MAX_RETRIES == spider.MAX_RETRIES
    assert scrape.RETRY_DELAYS == spider.RETRY_DELAYS


def test_cli_reuses_pacing_definitions_rather_than_duplicating_them():
    from ezio_cli import config as cli_config

    assert cli_config.PACE_PROFILES is pacing.PROFILES
    assert cli_config.DEFAULT_PACE == pacing.DEFAULT_PROFILE
    assert cli_config.PACE_ENV_VAR == pacing.ENV_VAR


def test_apply_env_does_not_override_an_explicit_one_shot_flag(monkeypatch):
    """--pace sets the env var before apply_env(); the flag must survive."""
    from ezio_cli import config as cli_config

    monkeypatch.setenv(pacing.ENV_VAR, "quiet")
    monkeypatch.setattr(
        cli_config, "load_config", lambda: {**cli_config.DEFAULT_CONFIG, "pace": "aggressive"}
    )
    cli_config.apply_env()
    assert pacing.get_profile() == "quiet"


def test_describe_covers_every_profile():
    for profile in pacing.PROFILES:
        assert profile in pacing.describe(profile)
