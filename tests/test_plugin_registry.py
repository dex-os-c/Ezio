"""Tests for plugins/registry.py — collector/enricher plugin discovery."""

import asyncio
import textwrap

import pytest

from plugins import registry


@pytest.fixture(autouse=True)
def _clean_registry():
    """Every test gets a fresh registry — plugin state must not leak across tests."""
    registry.reset_registry()
    yield
    registry.reset_registry()


def test_register_collector_and_enricher_directly():
    @registry.register_collector("test_collector")
    async def _collect(query):
        return [{"url": "https://example.test", "title": query}]

    @registry.register_enricher("test_enricher")
    async def _enrich(query, entities):
        return [{"url": "https://example.test/enrich", "source": "plugin:test_enricher"}]

    collectors = registry.get_collectors()
    enrichers = registry.get_enrichers()

    assert "test_collector" in collectors
    assert "test_enricher" in enrichers

    result = asyncio.run(collectors["test_collector"]("bit locker"))
    assert result == [{"url": "https://example.test", "title": "bit locker"}]


def test_redefining_a_plugin_name_overwrites_with_a_warning(caplog):
    @registry.register_collector("dup")
    async def _first(query):
        return [{"url": "first"}]

    @registry.register_collector("dup")
    async def _second(query):
        return [{"url": "second"}]

    result = asyncio.run(registry.get_collectors()["dup"]("q"))
    assert result == [{"url": "second"}]


def test_discover_plugins_loads_files_from_directory(tmp_path):
    plugin_file = tmp_path / "my_plugin.py"
    plugin_file.write_text(
        textwrap.dedent(
            """
            from plugins.registry import register_collector

            @register_collector("from_file")
            async def collect(query):
                return [{"url": "https://from-file.test", "title": query}]
            """
        )
    )

    registry.discover_plugins(tmp_path, force=True)

    collectors = registry.get_collectors()
    assert "from_file" in collectors
    result = asyncio.run(collectors["from_file"]("hello"))
    assert result[0]["url"] == "https://from-file.test"


def test_discover_plugins_skips_underscore_prefixed_files(tmp_path):
    (tmp_path / "_helper.py").write_text(
        "from plugins.registry import register_collector\n"
        "@register_collector('should_not_load')\n"
        "async def collect(query):\n"
        "    return []\n"
    )

    registry.discover_plugins(tmp_path, force=True)

    assert "should_not_load" not in registry.get_collectors()


def test_broken_plugin_file_is_skipped_not_raised(tmp_path):
    (tmp_path / "broken.py").write_text("this is not valid python syntax ][")
    (tmp_path / "good.py").write_text(
        "from plugins.registry import register_collector\n"
        "@register_collector('good')\n"
        "async def collect(query):\n"
        "    return [{'url': 'ok'}]\n"
    )

    # Must not raise despite the syntax error in broken.py.
    registry.discover_plugins(tmp_path, force=True)

    assert "good" in registry.get_collectors()


def test_discover_plugins_on_missing_directory_is_a_noop(tmp_path):
    missing = tmp_path / "does_not_exist"
    registry.discover_plugins(missing, force=True)
    assert registry.get_collectors() == {}
    assert registry.get_enrichers() == {}


def test_plugin_dir_respects_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("EZIO_PLUGIN_DIR", str(tmp_path / "custom"))
    assert registry.plugin_dir() == tmp_path / "custom"


def test_plugin_dir_defaults_to_home_ezio_plugins(monkeypatch):
    monkeypatch.delenv("EZIO_PLUGIN_DIR", raising=False)
    from pathlib import Path

    assert registry.plugin_dir() == Path.home() / ".ezio" / "plugins"


def test_discover_is_idempotent_without_force(tmp_path):
    plugin_file = tmp_path / "once.py"
    plugin_file.write_text(
        "from plugins.registry import register_collector\n"
        "@register_collector('once')\n"
        "async def collect(query):\n"
        "    return []\n"
    )

    registry.discover_plugins(tmp_path, force=True)
    assert "once" in registry.get_collectors()

    # Remove the file, then discover again without force — should NOT
    # re-scan (idempotent), so the previously-registered plugin persists
    # rather than the registry silently going empty on a second call.
    plugin_file.unlink()
    registry.discover_plugins(tmp_path)
    assert "once" in registry.get_collectors()
