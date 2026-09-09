"""Query diversification helpers for sparse Tor search results."""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)


async def diversify_query(
    primary_query: str,
    result_count: int,
    llm_client,
) -> list[str]:
    if result_count >= 5:
        return []

    if llm_client is not None:
        prompt = f"""
The dark web search query "{primary_query}" returned only {result_count} results.

Generate 2 alternative search queries that might find more relevant dark web content on the same topic.

Rules:
- Each query should use different keywords
- Use terminology threat actors actually use
- Keep queries under 6 words
- Return ONLY a JSON array of 2 strings
- No explanation, just the array

Example: ["lockbit affiliate panel", "lockbit ransomware leak site"]
"""
        try:
            response = await llm_client.generate(prompt)
            alternatives = json.loads(response.strip())
            if isinstance(alternatives, list):
                return [str(item).strip() for item in alternatives[:2] if str(item).strip()]
        except Exception as exc:
            logger.debug("query diversification LLM failed: %s", exc)

    words = primary_query.split()
    if len(words) >= 2:
        return [
            " ".join(words[:2]),
            " ".join(words[-2:]) + " darkweb",
        ]
    return []
