"""
plugins/registry.py — discovery and registration for custom
collector/enricher plugins.

Plugins are plain .py files dropped into ``~/.ezio/plugins/`` (override
the directory with the ``EZIO_PLUGIN_DIR`` environment variable). Each
file registers itself using the decorators below at import time::

    # ~/.ezio/plugins/my_source.py
    from plugins.registry import register_collector

    @register_collector("my_source")
    async def collect(query: str) -> list[dict]:
        return [{"url": "https://example.test", "title": "...", "snippet": "..."}]

Enricher plugins follow the same pattern with ``register_enricher`` — see
plugins/base.py for the exact contract.

Discovery is fail-safe by design: a plugin file that raises on import,
or a collector/enricher call that raises at run time, is logged and
skipped — it never prevents the investigation from completing. Built-in
sources (sources/*.py) are not touched by this module at all; this is a
purely additive extension point, not a replacement for them.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from plugins.base import CollectorFn, EnricherFn

logger = logging.getLogger(__name__)

_COLLECTORS: dict[str, CollectorFn] = {}
_ENRICHERS: dict[str, EnricherFn] = {}
_DISCOVERED = False


def register_collector(name: str):
    """Decorator: register an async ``(query) -> list[dict]`` collector plugin."""

    def _wrap(fn: CollectorFn) -> CollectorFn:
        if name in _COLLECTORS:
            logger.warning("Plugin collector '%s' redefined — overwriting previous registration", name)
        _COLLECTORS[name] = fn
        return fn

    return _wrap


def register_enricher(name: str):
    """Decorator: register an async ``(entity) -> dict`` enricher plugin."""

    def _wrap(fn: EnricherFn) -> EnricherFn:
        if name in _ENRICHERS:
            logger.warning("Plugin enricher '%s' redefined — overwriting previous registration", name)
        _ENRICHERS[name] = fn
        return fn

    return _wrap


def plugin_dir() -> Path:
    """Directory scanned for plugin files: ``$EZIO_PLUGIN_DIR`` or ``~/.ezio/plugins``."""
    override = os.environ.get("EZIO_PLUGIN_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".ezio" / "plugins"


def discover_plugins(directory: Optional[Path] = None, *, force: bool = False) -> None:
    """Import every ``*.py`` file in the plugin directory so its decorators run.

    Idempotent — only scans once per process unless ``force=True``. Files
    starting with ``_`` are skipped (convention for shared helper modules
    a plugin author doesn't want auto-loaded as a plugin itself).
    """
    global _DISCOVERED
    if _DISCOVERED and not force:
        return
    _DISCOVERED = True

    target = directory or plugin_dir()
    if not target.is_dir():
        return

    for path in sorted(target.glob("*.py")):
        if path.name.startswith("_"):
            continue
        module_name = f"ezio_plugin_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            logger.info("Loaded plugin file: %s", path.name)
        except Exception as exc:  # a broken plugin must never break an investigation
            logger.warning("Failed to load plugin %s: %s — skipping", path.name, exc)
            sys.modules.pop(module_name, None)


def get_collectors() -> dict[str, CollectorFn]:
    """Return all registered collector plugins, triggering discovery first."""
    discover_plugins()
    return dict(_COLLECTORS)


def get_enrichers() -> dict[str, EnricherFn]:
    """Return all registered enricher plugins, triggering discovery first."""
    discover_plugins()
    return dict(_ENRICHERS)


def reset_registry() -> None:
    """Test helper: clear all registered/discovered state."""
    global _DISCOVERED
    _COLLECTORS.clear()
    _ENRICHERS.clear()
    _DISCOVERED = False
