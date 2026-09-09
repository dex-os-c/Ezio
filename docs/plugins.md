# Plugins

Ezio's built-in sources (`sources/*.py`) cover Tor search engines, paste
sites, code forges, RSS feeds, and reputation/enrichment APIs. Plugins let
you add your own collectors and enrichers **without editing core files** —
drop a `.py` file into a directory and it's picked up automatically the
next time you run `ezio investigate`.

## How it works

Plugins live in `~/.ezio/plugins/` by default (override with the
`EZIO_PLUGIN_DIR` environment variable). Every `*.py` file in that
directory (except ones starting with `_`) is imported once per run, and
any collector/enricher it registers via the decorators below participates
in the pipeline alongside the built-in sources.

A broken plugin — a syntax error, a raised exception, a timeout — is
logged and skipped. **It never fails your investigation.** This is the
same fail-isolation the built-in sources already get from the CLI's
`_safe()` wrapper; plugins go through that exact wrapper, not a separate,
less-tested path.

## Writing a collector

A collector takes the (LLM-refined) query string and returns a list of
page dicts — the same shape `sources/paste_scraper.py`,
`sources/github_scraper.py`, etc. already return.

```python
# ~/.ezio/plugins/my_collector.py
from plugins.registry import register_collector

@register_collector("my_source")
async def collect(query: str) -> list[dict]:
    # Fetch however you like — an internal API, a private feed, a local
    # dataset. Return page-shaped dicts:
    return [
        {
            "url": "https://internal.example/report/42",
            "title": "Relevant finding",
            "snippet": "Short summary shown in search results.",
            "text": "Full text — this is what entity extraction reads.",
        }
    ]
```

Returned pages flow through the exact same filter → scrape → extract →
graph pipeline as every built-in source: entities get extracted,
confidence-scored, and placed on the relationship graph automatically.

## Writing an enricher

An enricher takes the refined query and the list of already-extracted
entity dicts, and returns page-shaped records — the same pattern
`sources/enrichment.py` uses for OTX/MalwareBazaar/ThreatFox results.

```python
# ~/.ezio/plugins/my_enricher.py
from plugins.registry import register_enricher

@register_enricher("my_lookup")
async def enrich(query: str, entities: list[dict]) -> list[dict]:
    hits = []
    for entity in entities:
        if entity.get("type") == "ip":
            # ... look it up against whatever internal/private source ...
            hits.append({
                "url": f"https://internal.example/ip/{entity['value']}",
                "content": "Internal reputation notes for this IP.",
                "text": "Internal reputation notes for this IP.",
            })
    return hits
```

## Running with a custom plugin directory

```bash
EZIO_PLUGIN_DIR=./my-plugins ezio investigate "query" --no-llm
```

You'll see plugin activity live in the CLI display and in the final
"Source details" table, labeled `plugin:<name>`.

## Notes

- Plugins are per-process, discovered once per `investigate` run — there's
  no hot-reload during a single run.
- There's currently no plugin marketplace/packaging story — this is a
  local-file mechanism, deliberately simple. If you need to ship a plugin
  to other people, distribute the `.py` file and have them drop it in
  their own `~/.ezio/plugins/`.
- The web UI / API pipeline does not yet call the plugin registry — this
  first pass wires plugins into the CLI (`ezio investigate`) only.
