"""
plugins/base.py — type contracts for custom collector/enricher plugins.

A collector plugin fetches raw "pages" for a query — the same dict shape
the built-in sources (sources/paste_scraper.py, sources/github_scraper.py,
etc.) already return: at minimum a ``url`` key, optionally ``title``,
``snippet``, and ``text``. Those pages flow into the exact same
filter → extract → enrich pipeline as every built-in source, so a plugin's
findings get entity extraction, confidence scoring, and graph placement
for free.

An enricher plugin takes the refined query and the list of already-extracted
entity dicts, and returns a list of *page* dicts in exactly the shape the
built-in enrichment sources use (``sources/enrichment.py``'s OTX/MalwareBazaar/
ThreatFox handlers): ``{"url": ..., "content": ..., "text": ..., "source": "<plugin_name>"}``.
Those pages are folded into the same ``enrichment_pages`` list the built-in
enrichers populate, so a plugin's findings get persisted and re-extracted
through the exact same path as everything else — no separate storage model
to maintain.

Both are plain async callables — no base class or subclassing required.
Register them with the decorators in plugins.registry.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

CollectorFn = Callable[[str], Awaitable[list[dict[str, Any]]]]
EnricherFn = Callable[[str, list[dict[str, Any]]], Awaitable[list[dict[str, Any]]]]
