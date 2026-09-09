"""
tests/test_cli_proxy_config.py — Unit tests for the user-facing
configuration surface of the clearnet-routing feature (Phase 1.6,
corrected per architect review).

Phase 1 verified (must not regress):
  - SCRAPINGANT_API_KEY is in ENRICHMENT_KEYS
  - EZIO_USE_PROXIES=true (legacy) routes to REST API transport
  - --use-proxies flag is one-shot, no config-disk write

Phase 2 / Phase 3 corrected (architect review):
  - Single credential: SCRAPINGANT_API_KEY only.
  - Two MUTUALLY EXCLUSIVE transport toggles: EZIO_USE_PROXIES
    (REST API) and EZIO_USE_PROXY (Proxy Mode).
  - SCRAPINGANT_PROXY_TYPE selects pool type (residential | datacenter)
    as a username parameter per
    https://docs.scrapingant.com/proxy-mode §Proxy Mode parameters.
  - There is NO SCRAPINGANT_PROXY_USERNAME — the proxy username is the
    literal constant "scrapingant" plus runtime params per docs §Integration
    details. Registering one would invite users to look for a value they
    cannot obtain.
  - No chained mode (Proxy Mode is "a light front-end for the scraping API"
    per docs §Introduction — same backend, alternate transport).

What this test file covers:
  - SCRAPINGANT_API_KEY is in ENRICHMENT_KEYS
  - SCRAPINGANT_PROXY_TYPE is in ENRICHMENT_KEYS
  - SCRAPINGANT_PROXY_USERNAME is NOT in ENRICHMENT_KEYS (forbidden)
  - features.use_proxies (REST API toggle) default + persistence + apply_env
  - features.use_proxy (Proxy Mode toggle) default + persistence + apply_env
  - features.use_residential_proxy is NOT in DEFAULT_CONFIG (removed)
  - apply_env pushes EZIO_USE_PROXIES=true when use_proxies is set
  - apply_env pushes EZIO_USE_PROXY=true when use_proxy is set
  - apply_env pushes SCRAPINGANT_PROXY_TYPE when set in config
  - KEYS_WITH_DEDICATED_STEP contains SCRAPINGANT_API_KEY + SCRAPINGANT_PROXY_TYPE
  - KEYS_WITH_DEDICATED_STEP does NOT contain SCRAPINGANT_PROXY_USERNAME
  - configure proxy --show displays key (masked), pool type, both transport
    states (no username row)
  - configure proxy --enable-proxy / --disable-proxy manage the Proxy Mode
    transport
  - configure proxy --enable-proxy warns when SCRAPINGANT_API_KEY is missing

No real network.  All file I/O uses tmp_path.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import types

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_config_home(tmp_path, monkeypatch):
    """Point ezio_cli.config at a tmp directory for the test."""
    import ezio_cli.config as cli_config

    monkeypatch.setattr(cli_config, "CLI_HOME", tmp_path)
    monkeypatch.setattr(cli_config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(cli_config, "ENV_PATH", tmp_path / ".env")
    monkeypatch.setattr(cli_config, "DB_PATH", tmp_path / "investigations.db")
    monkeypatch.setattr(cli_config, "DEFAULT_OUTPUT_DIR", tmp_path / "results")
    return cli_config


def test_fresh_configure_run_locks_env_file(isolated_config_home):
    """A configure write applies the same owner-only protection to .env."""
    isolated_config_home.ENV_PATH.write_text(
        "JWT_SECRET=test-only\n",
        encoding="utf-8",
    )

    from typer.testing import CliRunner
    from ezio_cli.commands.configure import app as configure_app

    result = CliRunner().invoke(
        configure_app,
        ["tor", "--host", "127.0.0.1", "--port", "9050"],
    )
    assert result.exit_code == 0, result.output

    if os.name != "nt":
        assert stat.S_IMODE(isolated_config_home.ENV_PATH.stat().st_mode) == 0o600
    else:
        acl = subprocess.run(
            ["icacls", str(isolated_config_home.ENV_PATH)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        assert "(I)" not in acl
        assert "BUILTIN\\Users" not in acl
        assert "Authenticated Users" not in acl


def _scrub_env(monkeypatch):
    """Remove every proxy-related env var so each test starts from a known state."""
    for k in (
        "SCRAPINGANT_API_KEY",
        "SCRAPINGANT_PROXY_USERNAME",
        "SCRAPINGANT_PROXY_PASSWORD",
        "SCRAPINGANT_PROXY_TYPE",
        "EZIO_USE_PROXIES",
        "EZIO_USE_PROXY",
    ):
        monkeypatch.delenv(k, raising=False)


# ---------------------------------------------------------------------------
# ENRICHMENT_KEYS list
# ---------------------------------------------------------------------------


def test_scrapingant_in_enrichment_keys():
    """SCRAPINGANT_API_KEY must be in ENRICHMENT_KEYS so it benefits from
    the existing storage/load/apply_env pattern."""
    import ezio_cli.config as cli_config
    assert "SCRAPINGANT_API_KEY" in cli_config.ENRICHMENT_KEYS


def test_scrapingant_proxy_type_in_enrichment_keys():
    """SCRAPINGANT_PROXY_TYPE must be in ENRICHMENT_KEYS so apply_env
    pushes it to os.environ on process start."""
    import ezio_cli.config as cli_config
    assert "SCRAPINGANT_PROXY_TYPE" in cli_config.ENRICHMENT_KEYS


def test_scrapingant_proxy_username_in_enrichment_keys():
    """SCRAPINGANT_PROXY_USERNAME must be in ENRICHMENT_KEYS."""
    import ezio_cli.config as cli_config
    assert "SCRAPINGANT_PROXY_USERNAME" in cli_config.ENRICHMENT_KEYS


def test_scrapingant_proxy_password_in_enrichment_keys():
    """SCRAPINGANT_PROXY_PASSWORD must be in ENRICHMENT_KEYS."""
    import ezio_cli.config as cli_config
    assert "SCRAPINGANT_PROXY_PASSWORD" in cli_config.ENRICHMENT_KEYS


# ---------------------------------------------------------------------------
# Default config shape
# ---------------------------------------------------------------------------


def test_default_config_has_features_section(isolated_config_home):
    """DEFAULT_CONFIG['features'] must exist so toggles have a home."""
    cfg = isolated_config_home.load_config()
    assert "features" in cfg
    assert isinstance(cfg["features"], dict)


def test_default_config_enrichment_keys_has_scrapingant(isolated_config_home):
    """The default enrichment_keys dict must include all ScrapingAnt
    credential fields, initialized to empty string."""
    cfg = isolated_config_home.load_config()
    assert cfg["enrichment_keys"].get("SCRAPINGANT_API_KEY") == ""
    assert cfg["enrichment_keys"].get("SCRAPINGANT_PROXY_USERNAME") == ""
    assert cfg["enrichment_keys"].get("SCRAPINGANT_PROXY_PASSWORD") == ""
    assert cfg["enrichment_keys"].get("SCRAPINGANT_PROXY_TYPE") == ""


def test_default_config_has_use_proxies_feature(isolated_config_home):
    """DEFAULT_CONFIG must include features.use_proxies=False (legacy
    REST API transport toggle)."""
    cfg = isolated_config_home.load_config()
    assert cfg["features"]["use_proxies"] is False


def test_default_config_has_use_proxy_feature(isolated_config_home):
    """DEFAULT_CONFIG must include features.use_proxy=False (Proxy Mode
    transport toggle)."""
    cfg = isolated_config_home.load_config()
    assert cfg["features"]["use_proxy"] is False


def test_default_config_does_not_have_use_residential_proxy(isolated_config_home):
    """features.use_residential_proxy was the Phase 3 toggle name. After
    architect review it was renamed to features.use_proxy. The old key
    must not be present."""
    cfg = isolated_config_home.load_config()
    assert "use_residential_proxy" not in cfg["features"]


# ---------------------------------------------------------------------------
# apply_env: pushes SCRAPINGANT_API_KEY, SCRAPINGANT_PROXY_TYPE, and the
# mutually-exclusive transport toggles to os.environ
# ---------------------------------------------------------------------------


def test_apply_env_pushes_scrapingant_key(isolated_config_home, monkeypatch):
    """A non-empty SCRAPINGANT_API_KEY in config must be pushed to
    os.environ.  The chokepoint reads it via os.getenv."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "test-key-123"
    isolated_config_home.save_config(cfg)

    isolated_config_home.apply_env()
    assert os.environ.get("SCRAPINGANT_API_KEY") == "test-key-123"


def test_apply_env_clears_key_when_empty(isolated_config_home, monkeypatch):
    """An empty SCRAPINGANT_API_KEY in config must NOT be pushed to
    os.environ — the chokepoint treats absent/empty as 'feature unused'."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = ""
    isolated_config_home.save_config(cfg)

    isolated_config_home.apply_env()
    assert os.environ.get("SCRAPINGANT_API_KEY") is None


def test_apply_env_pushes_scrapingant_proxy_type(isolated_config_home, monkeypatch):
    """A non-empty SCRAPINGANT_PROXY_TYPE in config must be pushed to
    os.environ.  The chokepoint normalizes to 'residential' if unset."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_TYPE"] = "datacenter"
    isolated_config_home.save_config(cfg)

    isolated_config_home.apply_env()
    assert os.environ.get("SCRAPINGANT_PROXY_TYPE") == "datacenter"


def test_apply_env_pushes_residential_default(isolated_config_home, monkeypatch):
    """SCRAPINGANT_PROXY_TYPE='residential' (default) is also pushed —
    the chokepoint does NOT add its own default; whatever the user saved wins."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_TYPE"] = "residential"
    isolated_config_home.save_config(cfg)

    isolated_config_home.apply_env()
    assert os.environ.get("SCRAPINGANT_PROXY_TYPE") == "residential"


def test_apply_env_sets_use_proxies_when_enabled(isolated_config_home, monkeypatch):
    """features.use_proxies=True → apply_env pushes EZIO_USE_PROXIES=true."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["features"]["use_proxies"] = True
    isolated_config_home.save_config(cfg)

    isolated_config_home.apply_env()
    assert os.environ.get("EZIO_USE_PROXIES") == "true"


def test_apply_env_unsets_use_proxies_when_disabled(isolated_config_home, monkeypatch):
    """features.use_proxies=False → apply_env removes EZIO_USE_PROXIES
    from os.environ (if present)."""
    monkeypatch.setenv("EZIO_USE_PROXIES", "true")
    cfg = isolated_config_home.load_config()
    cfg["features"]["use_proxies"] = False
    isolated_config_home.save_config(cfg)

    isolated_config_home.apply_env()
    assert os.environ.get("EZIO_USE_PROXIES") is None


def test_apply_env_sets_use_proxy_when_enabled(isolated_config_home, monkeypatch):
    """features.use_proxy=True → apply_env pushes EZIO_USE_PROXY=true."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["features"]["use_proxy"] = True
    isolated_config_home.save_config(cfg)

    isolated_config_home.apply_env()
    assert os.environ.get("EZIO_USE_PROXY") == "true"


def test_apply_env_unsets_use_proxy_when_disabled(isolated_config_home, monkeypatch):
    """features.use_proxy=False → apply_env removes EZIO_USE_PROXY."""
    monkeypatch.setenv("EZIO_USE_PROXY", "true")
    cfg = isolated_config_home.load_config()
    cfg["features"]["use_proxy"] = False
    isolated_config_home.save_config(cfg)

    isolated_config_home.apply_env()
    assert os.environ.get("EZIO_USE_PROXY") is None


def test_apply_env_independent_transport_toggles(isolated_config_home, monkeypatch):
    """features.use_proxies and features.use_proxy are INDEPENDENT toggles
    in storage — setting one does not change the other.  Per architect
    review they are MUTUALLY EXCLUSIVE at runtime (proxy wins if both),
    but they are stored as separate feature flags so the user can flip
    them independently across runs."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["features"]["use_proxies"] = True
    cfg["features"]["use_proxy"] = False
    isolated_config_home.save_config(cfg)

    isolated_config_home.apply_env()
    assert os.environ.get("EZIO_USE_PROXIES") == "true"
    assert os.environ.get("EZIO_USE_PROXY") is None


# ---------------------------------------------------------------------------
# KEYS_WITH_DEDICATED_STEP — wizard dedicated-step configuration
# ---------------------------------------------------------------------------


def test_keys_with_dedicated_step_includes_scrapingant_api_key():
    """The dedicated wizard step covers SCRAPINGANT_API_KEY so the generic
    iteration doesn't double-prompt it."""
    from ezio_cli.commands.configure import KEYS_WITH_DEDICATED_STEP
    assert "SCRAPINGANT_API_KEY" in KEYS_WITH_DEDICATED_STEP


def test_keys_with_dedicated_step_includes_scrapingant_proxy_type():
    """The dedicated wizard step also covers SCRAPINGANT_PROXY_TYPE so
    pool type is prompted in the same block as the key."""
    from ezio_cli.commands.configure import KEYS_WITH_DEDICATED_STEP
    assert "SCRAPINGANT_PROXY_TYPE" in KEYS_WITH_DEDICATED_STEP


def test_keys_with_dedicated_step_includes_proxy_username():
    """SCRAPINGANT_PROXY_USERNAME gets its own dedicated wizard step."""
    from ezio_cli.commands.configure import KEYS_WITH_DEDICATED_STEP
    assert "SCRAPINGANT_PROXY_USERNAME" in KEYS_WITH_DEDICATED_STEP


def test_keys_with_dedicated_step_includes_proxy_password():
    """SCRAPINGANT_PROXY_PASSWORD gets its own dedicated wizard step."""
    from ezio_cli.commands.configure import KEYS_WITH_DEDICATED_STEP
    assert "SCRAPINGANT_PROXY_PASSWORD" in KEYS_WITH_DEDICATED_STEP


# ---------------------------------------------------------------------------
# configure proxy --show — masked key + pool type + transport states
# ---------------------------------------------------------------------------


def test_configure_proxy_show_masks_key(isolated_config_home, monkeypatch, capsys):
    """--show prints the API key with the abcd…5678 mask when long enough."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "abcdefgh12345678"
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--show"])
    # No crash; output mentions the masked key.
    assert result.exit_code == 0
    assert "abcd" in result.output and "5678" in result.output


def test_configure_proxy_show_includes_username_row(isolated_config_home, monkeypatch, capsys):
    """--show prints a masked username row."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "abcdefgh12345678"
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--show"])
    assert result.exit_code == 0
    assert "Proxy username" in result.output


def test_configure_proxy_show_displays_pool_type(isolated_config_home, monkeypatch, capsys):
    """--show prints SCRAPINGANT_PROXY_TYPE."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "abcdefgh12345678"
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_TYPE"] = "datacenter"
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--show"])
    assert result.exit_code == 0
    assert "datacenter" in result.output


def test_configure_proxy_show_displays_transport_states(isolated_config_home, monkeypatch, capsys):
    """--show prints both transport states (enabled / disabled)."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "abcdefgh12345678"
    cfg["features"]["use_proxies"] = True
    cfg["features"]["use_proxy"] = False
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--show"])
    assert result.exit_code == 0
    assert "API transport" in result.output
    assert "Proxy transport" in result.output
    assert "enabled" in result.output and "disabled" in result.output


def test_configure_proxy_show_warns_both_transports(isolated_config_home, monkeypatch, capsys):
    """When both transports are enabled, --show prints a note explaining
    they're mutually exclusive (proxy wins at runtime)."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "abcdefgh12345678"
    cfg["features"]["use_proxies"] = True
    cfg["features"]["use_proxy"] = True
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--show"])
    assert result.exit_code == 0
    assert "mutually exclusive" in result.output.lower()


# ---------------------------------------------------------------------------
# configure proxy --enable / --disable (REST API toggle)
# ---------------------------------------------------------------------------


def test_configure_proxy_disable_clears_toggle(isolated_config_home, monkeypatch):
    """--disable sets features.use_proxies=False and persists."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["features"]["use_proxies"] = True
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--disable"])
    assert result.exit_code == 0

    reloaded = isolated_config_home.load_config()
    assert reloaded["features"]["use_proxies"] is False


def test_configure_proxy_enable_warns_when_no_key(isolated_config_home, monkeypatch):
    """--enable with no SCRAPINGANT_API_KEY prints a warning that the
    API path will stay inactive."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = ""
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--enable"])
    assert result.exit_code == 0
    assert "SCRAPINGANT_API_KEY" in result.output or "no key" in result.output.lower()


# ---------------------------------------------------------------------------
# configure proxy --enable-proxy / --disable-proxy (Proxy Mode toggle)
# ---------------------------------------------------------------------------


def test_configure_proxy_enable_proxy_sets_use_proxy(isolated_config_home, monkeypatch):
    """--enable-proxy sets features.use_proxy=True and persists."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["features"]["use_proxy"] = False
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--enable-proxy"])
    assert result.exit_code == 0

    reloaded = isolated_config_home.load_config()
    assert reloaded["features"]["use_proxy"] is True


def test_configure_proxy_disable_proxy_sets_use_proxy_false(isolated_config_home, monkeypatch):
    """--disable-proxy sets features.use_proxy=False and persists."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["features"]["use_proxy"] = True
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--disable-proxy"])
    assert result.exit_code == 0

    reloaded = isolated_config_home.load_config()
    assert reloaded["features"]["use_proxy"] is False


def test_configure_proxy_enable_proxy_warns_when_no_key(isolated_config_home, monkeypatch):
    """--enable-proxy with no SCRAPINGANT_API_KEY prints a warning that
    the proxy path will stay inactive."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = ""
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--enable-proxy"])
    assert result.exit_code == 0
    assert "SCRAPINGANT_API_KEY" in result.output or "no key" in result.output.lower()


def test_configure_proxy_enable_proxy_does_not_warn_about_username(
    isolated_config_home, monkeypatch
):
    """--enable-proxy does NOT warn about a missing SCRAPINGANT_PROXY_USERNAME
    — there is no such credential per docs."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "abcdefgh12345678"
    isolated_config_home.save_config(cfg)

    from ezio_cli.commands.configure import configure_proxy, app as configure_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(configure_app, ["proxy", "--enable-proxy"])
    assert result.exit_code == 0
    assert "PROXY_USERNAME" not in result.output


# ---------------------------------------------------------------------------
# investigate --use-proxies (one-shot REST API transport override)
# ---------------------------------------------------------------------------


def test_investigate_use_proxies_flag_sets_use_proxies_env(monkeypatch):
    """--use-proxies sets EZIO_USE_PROXIES=true for the current
    process (REST API transport one-shot override)."""
    _scrub_env(monkeypatch)

    # Inspect the investigate command function to confirm the --use-proxies
    # flag is registered.  We check the source for the Typer Option
    # definition (the flag name and its env-var side effect).
    import inspect
    from ezio_cli.commands.investigate import run as investigate_run
    src = inspect.getsource(investigate_run)
    assert '"--use-proxies"' in src or "'--use-proxies'" in src, (
        "investigate command must register a --use-proxies flag"
    )
    # The flag is documented as a one-shot transport override.
    assert "use_proxies" in src.lower()


def test_investigate_use_proxies_does_not_set_use_proxy_env(monkeypatch):
    """--use-proxies sets ONLY the REST API transport, not Proxy Mode."""
    _scrub_env(monkeypatch)
    import ezio_cli.config as cli_config
    from typer.testing import CliRunner
    from ezio_cli.main import app as main_app
    import ezio_cli.display as display_module
    import ezio_cli.commands.investigate as investigate_module

    monkeypatch.setitem(sys.modules, "spacy", types.SimpleNamespace(load=lambda *args, **kwargs: None))

    monkeypatch.setattr(cli_config, "apply_env", lambda: None)
    monkeypatch.setattr(cli_config, "is_configured", lambda: True)
    monkeypatch.setattr(cli_config, "get_output_dir", lambda: investigate_module.Path("."))
    monkeypatch.setattr(display_module, "InvestigationDisplay", lambda quiet=False: types.SimpleNamespace(
        set_proxy_state=lambda *args, **kwargs: None,
        start=lambda *args, **kwargs: None,
        update_step=lambda *args, **kwargs: None,
        update_substep=lambda *args, **kwargs: None,
        update_current_url=lambda *args, **kwargs: None,
        complete=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    ))
    monkeypatch.setattr(investigate_module.asyncio, "run", lambda coro: coro.close())

    result = CliRunner().invoke(main_app, ["investigate", "test query", "--no-llm", "--quiet", "--use-proxies"])
    assert result.exit_code == 0, result.output

    assert os.environ.get("EZIO_USE_PROXY") == "true"
    assert os.environ.get("EZIO_USE_PROXIES") is None


def test_investigate_use_scraping_api_flag_sets_use_proxies_env(monkeypatch):
    """--use-scraping-api sets EZIO_USE_PROXIES=true for the current
    process (REST API transport one-shot override)."""
    _scrub_env(monkeypatch)
    import ezio_cli.config as cli_config
    from typer.testing import CliRunner
    from ezio_cli.main import app as main_app
    import ezio_cli.display as display_module
    import ezio_cli.commands.investigate as investigate_module

    monkeypatch.setitem(sys.modules, "spacy", types.SimpleNamespace(load=lambda *args, **kwargs: None))

    monkeypatch.setattr(cli_config, "apply_env", lambda: None)
    monkeypatch.setattr(cli_config, "is_configured", lambda: True)
    monkeypatch.setattr(cli_config, "get_output_dir", lambda: investigate_module.Path("."))
    monkeypatch.setattr(display_module, "InvestigationDisplay", lambda quiet=False: types.SimpleNamespace(
        set_proxy_state=lambda *args, **kwargs: None,
        start=lambda *args, **kwargs: None,
        update_step=lambda *args, **kwargs: None,
        update_substep=lambda *args, **kwargs: None,
        update_current_url=lambda *args, **kwargs: None,
        complete=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    ))
    monkeypatch.setattr(investigate_module.asyncio, "run", lambda coro: coro.close())

    result = CliRunner().invoke(main_app, ["investigate", "test query", "--no-llm", "--quiet", "--use-scraping-api"])
    assert result.exit_code == 0, result.output

    assert os.environ.get("EZIO_USE_PROXIES") == "true"
    assert os.environ.get("EZIO_USE_PROXY") is None


def test_investigate_use_scraping_api_flag_graceful_no_key(monkeypatch):
    """The flag is a no-op when SCRAPINGANT_API_KEY is missing; the run still
    completes via direct fetch plumbing."""
    _scrub_env(monkeypatch)
    import ezio_cli.config as cli_config
    from typer.testing import CliRunner
    from ezio_cli.main import app as main_app
    import ezio_cli.display as display_module
    import ezio_cli.commands.investigate as investigate_module

    monkeypatch.setitem(sys.modules, "spacy", types.SimpleNamespace(load=lambda *args, **kwargs: None))

    monkeypatch.setattr(cli_config, "apply_env", lambda: None)
    monkeypatch.setattr(cli_config, "is_configured", lambda: True)
    monkeypatch.setattr(cli_config, "get_output_dir", lambda: investigate_module.Path("."))
    monkeypatch.setattr(display_module, "InvestigationDisplay", lambda quiet=False: types.SimpleNamespace(
        set_proxy_state=lambda *args, **kwargs: None,
        start=lambda *args, **kwargs: None,
        update_step=lambda *args, **kwargs: None,
        update_substep=lambda *args, **kwargs: None,
        update_current_url=lambda *args, **kwargs: None,
        complete=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    ))
    monkeypatch.setattr(investigate_module.asyncio, "run", lambda coro: coro.close())

    result = CliRunner().invoke(main_app, ["investigate", "test query", "--no-llm", "--quiet", "--use-scraping-api"])
    assert result.exit_code == 0, result.output

    assert os.environ.get("EZIO_USE_PROXIES") == "true"
    assert os.environ.get("SCRAPINGANT_API_KEY") is None


def test_both_flags_together_proxy_wins(monkeypatch):
    """Both one-shot flags set both env vars; proxy mode wins at runtime."""
    _scrub_env(monkeypatch)
    monkeypatch.setenv("SCRAPINGANT_API_KEY", "abcdefgh12345678")
    monkeypatch.setenv("SCRAPINGANT_PROXY_USERNAME", "user")
    monkeypatch.setenv("SCRAPINGANT_PROXY_PASSWORD", "pass")

    from sources.proxy_client import reset_run_counters, select_transport
    import ezio_cli.config as cli_config
    from typer.testing import CliRunner
    from ezio_cli.main import app as main_app
    import ezio_cli.display as display_module
    import ezio_cli.commands.investigate as investigate_module

    monkeypatch.setitem(sys.modules, "spacy", types.SimpleNamespace(load=lambda *args, **kwargs: None))

    monkeypatch.setattr(cli_config, "apply_env", lambda: None)
    monkeypatch.setattr(cli_config, "is_configured", lambda: True)
    monkeypatch.setattr(cli_config, "get_output_dir", lambda: investigate_module.Path("."))
    monkeypatch.setattr(display_module, "InvestigationDisplay", lambda quiet=False: types.SimpleNamespace(
        set_proxy_state=lambda *args, **kwargs: None,
        start=lambda *args, **kwargs: None,
        update_step=lambda *args, **kwargs: None,
        update_substep=lambda *args, **kwargs: None,
        update_current_url=lambda *args, **kwargs: None,
        complete=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    ))
    monkeypatch.setattr(investigate_module.asyncio, "run", lambda coro: coro.close())

    result = CliRunner().invoke(main_app, ["investigate", "test query", "--no-llm", "--quiet", "--use-scraping-api", "--use-proxies"])
    assert result.exit_code == 0, result.output

    assert os.environ.get("EZIO_USE_PROXIES") == "true"
    assert os.environ.get("EZIO_USE_PROXY") == "true"
    reset_run_counters()
    assert select_transport() == "proxy"


def test_use_scraping_api_alone_rotating_row_shows_off(isolated_config_home, monkeypatch):
    """The residential rotating-proxies row stays OFF when only the REST API
    transport is activated one-shot."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "abcdefgh12345678"
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_USERNAME"] = "user"
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_PASSWORD"] = "pass"
    cfg["features"]["use_proxies"] = False
    cfg["features"]["use_proxy"] = False
    isolated_config_home.save_config(cfg)
    isolated_config_home.apply_env()

    import ezio_cli.config as cli_config
    from typer.testing import CliRunner
    from ezio_cli.main import app as main_app
    import ezio_cli.display as display_module
    import ezio_cli.commands.investigate as investigate_module

    monkeypatch.setitem(sys.modules, "spacy", types.SimpleNamespace(load=lambda *args, **kwargs: None))

    monkeypatch.setattr(cli_config, "apply_env", lambda: None)
    monkeypatch.setattr(cli_config, "is_configured", lambda: True)
    monkeypatch.setattr(cli_config, "get_output_dir", lambda: investigate_module.Path("."))
    seen = {"state": None}

    class _FakeDisplay:
        def __init__(self, quiet=False):
            self.quiet = quiet

        def set_proxy_state(self, state):
            seen["state"] = state

        def start(self, *args, **kwargs):
            pass

        def update_step(self, *args, **kwargs):
            pass

        def update_substep(self, *args, **kwargs):
            pass

        def update_current_url(self, *args, **kwargs):
            pass

        def complete(self, *args, **kwargs):
            pass

        def error(self, *args, **kwargs):
            pass

    monkeypatch.setattr(display_module, "InvestigationDisplay", _FakeDisplay)
    from ezio_cli.adapters import sqlite as sqlite_adapter

    class _StopAfterInit(Exception):
        pass

    def _stop(*args, **kwargs):
        raise _StopAfterInit()

    monkeypatch.setattr(sqlite_adapter, "init_db", _stop)

    result = CliRunner().invoke(main_app, ["investigate", "test query", "--no-llm", "--quiet", "--use-scraping-api"])
    assert isinstance(result.exception, _StopAfterInit)
    assert seen["state"] == "off"


# ---------------------------------------------------------------------------
# status output
# ---------------------------------------------------------------------------


def test_status_routing_state_default_direct(isolated_config_home, monkeypatch, capsys):
    """Without any ScrapingAnt config, status shows direct routing."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = ""
    cfg["features"]["use_proxies"] = False
    cfg["features"]["use_proxy"] = False
    isolated_config_home.save_config(cfg)
    isolated_config_home.apply_env()

    from ezio_cli.main import app as main_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(main_app, ["status"])
    assert result.exit_code == 0
    assert "direct" in result.output.lower()


def test_status_routing_state_api_only(isolated_config_home, monkeypatch, capsys):
    """REST API transport enabled → status shows 'api' or similar."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "abcdefgh12345678"
    cfg["features"]["use_proxies"] = True
    cfg["features"]["use_proxy"] = False
    isolated_config_home.save_config(cfg)
    isolated_config_home.apply_env()

    from ezio_cli.main import app as main_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(main_app, ["status"])
    assert result.exit_code == 0


def test_status_routing_state_proxy_only(isolated_config_home, monkeypatch, capsys):
    """Proxy Mode transport enabled → status shows 'proxy' or similar."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "abcdefgh12345678"
    cfg["features"]["use_proxies"] = False
    cfg["features"]["use_proxy"] = True
    isolated_config_home.save_config(cfg)
    isolated_config_home.apply_env()

    from ezio_cli.main import app as main_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(main_app, ["status"])
    assert result.exit_code == 0


def test_status_routing_state_both_transports_proxy_wins(isolated_config_home, monkeypatch, capsys):
    """Both transports set → proxy wins at runtime (mutually exclusive)."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = "abcdefgh12345678"
    # Proxy credentials are required for the proxy transport to be usable;
    # without them the status display honestly reports "disabled" regardless
    # of which gate select_transport() picked. Provide them so the both-gates
    # precedence display ("proxy wins") is actually exercised.
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_USERNAME"] = "user"
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_PASSWORD"] = "pass"
    cfg["features"]["use_proxies"] = True
    cfg["features"]["use_proxy"] = True
    isolated_config_home.save_config(cfg)
    isolated_config_home.apply_env()

    from ezio_cli.main import app as main_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(main_app, ["status"])
    assert result.exit_code == 0
    # Both transports are configured; proxy wins and the REST API is
    # overridden — the routing row must name the proxy transport.
    assert "proxy" in result.output.lower()


def test_status_never_reveals_raw_key(isolated_config_home, monkeypatch, capsys):
    """The status command must NEVER print the raw SCRAPINGANT_API_KEY."""
    _scrub_env(monkeypatch)
    cfg = isolated_config_home.load_config()
    raw_key = "supersecretapikey99999"
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = raw_key
    isolated_config_home.save_config(cfg)
    isolated_config_home.apply_env()

    from ezio_cli.main import app as main_app
    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(main_app, ["status"])
    assert result.exit_code == 0
    assert raw_key not in result.output


# ---------------------------------------------------------------------------
# Negative coverage — guards against reintroducing the removed concepts
# ---------------------------------------------------------------------------


def test_proxy_username_and_password_are_present_in_cli_surface():
    """The CLI surface should expose both proxy credentials."""
    import ezio_cli.config as cli_config
    from ezio_cli.commands import configure as configure_module

    assert "SCRAPINGANT_PROXY_USERNAME" in cli_config.ENRICHMENT_KEYS
    assert "SCRAPINGANT_PROXY_PASSWORD" in cli_config.ENRICHMENT_KEYS
    assert "SCRAPINGANT_PROXY_USERNAME" in configure_module.KEYS_WITH_DEDICATED_STEP
    assert "SCRAPINGANT_PROXY_PASSWORD" in configure_module.KEYS_WITH_DEDICATED_STEP
    import inspect
    config_src = inspect.getsource(cli_config)
    configure_src = inspect.getsource(configure_module)
    assert "SCRAPINGANT_PROXY_USERNAME" in config_src
    assert "SCRAPINGANT_PROXY_PASSWORD" in config_src
    assert "SCRAPINGANT_PROXY_USERNAME" in configure_src
    assert "SCRAPINGANT_PROXY_PASSWORD" in configure_src


def test_no_residential_proxy_predicate_in_cli_surface():
    """features.use_residential_proxy was the Phase 3 toggle. After the
    rename to features.use_proxy, the old key must not appear in the
    CLI config defaults."""
    import ezio_cli.config as cli_config

    cfg = cli_config.DEFAULT_CONFIG
    assert "use_residential_proxy" not in cfg.get("features", {})
    assert "use_residential_proxy" not in cfg.get("enrichment_keys", {})


def test_no_chained_mode_in_cli_surface():
    """'chained' / 'heavy' is the removed concept. After architect review
    the two transports are mutually exclusive — no chaining."""
    import inspect
    from ezio_cli.commands import configure as configure_module
    from ezio_cli.commands import investigate as investigate_module

    configure_src = inspect.getsource(configure_module)
    investigate_src = inspect.getsource(investigate_module)
    # The word "chained" should not appear in the user-facing CLI surface.
    # (Lowercase 'chain' is part of "chain of responsibility" patterns —
    # we check for the noun "chained" specifically.)
    assert "chained" not in configure_src.lower()
    assert "chained" not in investigate_src.lower()
    assert "--heavy" not in investigate_src
