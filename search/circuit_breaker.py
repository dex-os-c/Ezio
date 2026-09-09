"""DB-backed circuit breaker for search engine resilience."""

from __future__ import annotations

import logging
import asyncio
from typing import Any

from db.search_engine_stats import (
    get_all_engine_stats_async,
    record_engine_attempt,
    reset_circuit_async,
    should_skip_engine_async,
)

logger = logging.getLogger(__name__)

# Compatibility exports for older admin routes. The authoritative state is now
# stored in search_engine_stats so circuits persist across CLI and API restarts.
_engine_failures: dict[str, int] = {}
_engine_last_success: dict[str, float] = {}
_engine_state: dict[str, str] = {}
_engine_open_time: dict[str, float] = {}


async def record_failure(engine_name: str) -> None:
    await asyncio.to_thread(
        record_engine_attempt,
        engine_name,
        False,
        0,
        0,
    )


async def record_success(engine_name: str, results_count: int = 0, response_time_ms: float = 0) -> None:
    await asyncio.to_thread(
        record_engine_attempt,
        engine_name,
        True,
        results_count,
        response_time_ms,
    )


async def is_open(engine_name: str) -> bool:
    try:
        return await should_skip_engine_async(engine_name)
    except Exception as exc:
        logger.debug("circuit check failed for %s: %s", engine_name, exc)
        return False


async def reset_circuit(engine_name: str) -> None:
    try:
        await reset_circuit_async(engine_name)
    except Exception as exc:
        logger.debug("circuit reset failed for %s: %s", engine_name, exc)


async def get_all_states() -> dict[str, dict[str, Any]]:
    try:
        rows = await get_all_engine_stats_async()
        return {
            row["engine_name"]: {
                "state": "open" if row.get("is_circuit_open") else "closed",
                "failures": int(row.get("consecutive_failures") or 0),
                "last_success": row.get("last_success_at"),
                "score": row.get("score", 0),
            }
            for row in rows
        }
    except Exception as exc:
        logger.debug("get_all_states failed: %s", exc)
        return {}


async def close() -> None:
    return None
