"""Tests for Phase 1 gazetteer expansion in the no-LLM ranker."""

from __future__ import annotations

from ezio.llm import _build_query_expansion, _heuristic_filter
from ezio_cli.commands.investigate import _filter_clearnet_pages


def _legacy_picks(results: list[dict], query: str, top_n: int) -> list[int]:
    """Reference implementation of the pre-expansion query scoring path."""
    scored = []
    for index, page in enumerate(results, 1):
        url = (page.get("link") or page.get("url") or "").lower()
        title = (page.get("title") or "").lower()
        content = page.get("text_content") or page.get("content") or page.get("text") or ""
        score = min(len(content) / 1000.0, 5.0)
        for term in (query or "").lower().split():
            if term in url:
                score += 3.0
            if term in title:
                score += 2.0
        if ".onion" in url:
            score += 2.0
        for noise in ("index", "search", "directory", "home", "about", "faq", "help", "login", "register", "signup", "browse"):
            if noise in url:
                score -= 3.0
        scored.append((index, score))
    scored.sort(key=lambda item: -item[1])
    return [index for index, _ in scored[:top_n]]


def test_lazarus_expansion_is_deterministic_and_capped() -> None:
    first = _build_query_expansion("Lazarus Group")
    second = _build_query_expansion("Lazarus Group")

    assert first == second
    assert first["expanded"] is True
    assert first["matches"][0]["available_aliases"] > 8

    aliases = [term for term in first["terms"] if term["tier"] == "alias_term"]
    assert len(aliases) == 8
    assert [term["term"] for term in aliases] == sorted(
        (term["term"] for term in aliases),
        key=lambda term: (term.casefold(), term),
    )


def test_zero_synonym_gazetteer_hit_keeps_legacy_behavior() -> None:
    results = [
        {"link": "https://example.test/ucylocker", "title": "ucyLocker report", "content": "x" * 500},
        {"link": "https://example.test/generic", "title": "Generic report", "content": "x" * 500},
    ]

    expansion = _build_query_expansion("$ucyLocker")
    assert expansion["expanded"] is False
    assert _heuristic_filter(results, "$ucyLocker", 2) == _legacy_picks(results, "$ucyLocker", 2)


def test_original_term_beats_page_with_many_alias_matches() -> None:
    expansion = _build_query_expansion("Lazarus Group")
    aliases = [term["term"] for term in expansion["terms"] if term["tier"] == "alias_term"]

    results = [
        {
            "link": "https://analyst.test/lazarus-report",
            "title": "Lazarus incident report",
            "content": "x" * 1000,
        },
        {
            "link": "https://feed.test/" + "/".join(aliases),
            "title": " ".join(aliases),
            "content": "x" * 1000,
        },
    ]

    assert _heuristic_filter(results, "Lazarus Group", 1) == [1]

    original = next(term for term in expansion["terms"] if term["tier"] == "original_term")
    alias = next(term for term in expansion["terms"] if term["tier"] == "alias_term")
    exact = next(term for term in expansion["terms"] if term["tier"] == "exact_phrase")
    assert exact["title_weight"] > original["title_weight"] > alias["title_weight"]
    assert exact["url_weight"] > original["url_weight"] > alias["url_weight"]


def test_unmatched_query_is_unexpanded() -> None:
    assert _build_query_expansion("ordinary phrase")["expanded"] is False


def test_clearnet_candidates_use_the_same_weighted_filter() -> None:
    pages = [
        {
            "url": "https://analyst.test/lazarus-report",
            "title": "Lazarus incident report",
            "text_content": "x" * 1000,
        },
        {
            "url": "https://feed.test/" + "/".join(
                term["term"]
                for term in _build_query_expansion("Lazarus Group")["terms"]
                if term["tier"] == "alias_term"
            ),
            "title": "Alias roundup",
            "text_content": "x" * 1000,
        },
    ]

    selected = _filter_clearnet_pages(pages, "Lazarus Group", 1)

    assert [page["url"] for page in selected] == [pages[0]["url"]]


def test_clearnet_filter_does_not_mutate_tor_scoring_inputs() -> None:
    tor_results = [
        {"link": "https://tor.test/lazarus", "title": "Lazarus report", "content": "x" * 1000},
        {"link": "https://tor.test/generic", "title": "Generic report", "content": "x" * 1000},
    ]
    before = _heuristic_filter(tor_results, "Lazarus Group", 2)

    _filter_clearnet_pages(
        [{"url": "https://rss.test/story", "title": "Story", "text_content": "x" * 1000}],
        "Lazarus Group",
        1,
    )

    assert _heuristic_filter(tor_results, "Lazarus Group", 2) == before
