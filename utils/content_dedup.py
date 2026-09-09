"""Content-hash deduplication for investigation page records."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable


def content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def deduplicate_page_records(pages: Iterable[dict]) -> list[dict]:
    """Collapse identical content while retaining every source URL.

    The first page remains canonical for extraction and DB entity provenance;
    ``source_urls`` carries the complete mirror set for reporting.
    """
    by_hash: dict[str, dict] = {}
    for page in pages:
        text = page.get("text") or page.get("content") or page.get("cleaned_text") or ""
        url = (page.get("url") or page.get("link") or "").strip()
        if not url:
            continue
        digest = page.get("raw_content_hash") or content_hash(text)
        existing = by_hash.get(digest)
        if existing is None:
            item = dict(page)
            item["url"] = url
            item["raw_content_hash"] = digest
            item["source_urls"] = list(dict.fromkeys([url, *(page.get("source_urls") or [])]))
            by_hash[digest] = item
        else:
            existing["source_urls"] = list(dict.fromkeys([
                *existing.get("source_urls", []),
                url,
                *(page.get("source_urls") or []),
            ]))
    return list(by_hash.values())
