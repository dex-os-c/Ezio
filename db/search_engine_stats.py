"""Persistent search-engine health and scoring helpers."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import text

import pacing

logger = logging.getLogger(__name__)


CREATE_SEARCH_ENGINE_STATS_SQL = """
CREATE TABLE IF NOT EXISTS search_engine_stats (
    engine_name TEXT PRIMARY KEY,
    total_attempts INTEGER DEFAULT 0,
    total_successes INTEGER DEFAULT 0,
    total_results INTEGER DEFAULT 0,
    consecutive_failures INTEGER DEFAULT 0,
    last_success_at TIMESTAMP NULL,
    last_attempt_at TIMESTAMP NULL,
    avg_response_time_ms REAL DEFAULT 0,
    is_circuit_open BOOLEAN DEFAULT FALSE,
    circuit_opened_at TIMESTAMP NULL
)
"""


def ensure_search_engine_stats_table() -> None:
    try:
        from db.session import get_engine

        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text(CREATE_SEARCH_ENGINE_STATS_SQL))
            conn.commit()
    except Exception as exc:
        logger.debug("search_engine_stats init failed: %s", exc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def circuit_duration_for_failures(consecutive_failures: int) -> timedelta:
    if consecutive_failures >= 30:
        return timedelta(days=7)
    if consecutive_failures >= 10:
        return timedelta(hours=24)
    return timedelta(hours=2)


# `normal` pacing baseline for the adaptive per-engine timeout.
ENGINE_TIMEOUT_DEFAULT = 20.0     # no observations yet
ENGINE_TIMEOUT_FLOOR = 8.0        # lower clamp
ENGINE_TIMEOUT_CEILING = 45.0     # upper clamp
ENGINE_TIMEOUT_MULTIPLIER = 2.0   # applied to observed average response time


def get_engine_timeout(stats: dict[str, Any]) -> float:
    """
    Return the adaptive per-engine timeout, in seconds.

    This is a self-tuning value: an engine's own observed average response
    time drives the result.  The pacing profile deliberately scales only the
    *bounds* it is clamped into and the no-observations default — never the
    computed value itself.  Multiplying the adaptive output by a profile
    factor would let a profile guess override a real measurement, so the
    profile would fight the adaptive logic instead of complementing it.  With
    bounds-scaling, an engine that has demonstrated it answers in 6 s still
    gets a 12 s timeout under every profile; what changes is how much room a
    genuinely slow engine is granted before the ceiling cuts it off, and how
    eagerly a fast one is clamped up off the floor.
    """
    floor, ceiling = pacing.scale_adaptive_bounds(
        ENGINE_TIMEOUT_FLOOR, ENGINE_TIMEOUT_CEILING
    )

    # No observations yet — nothing to adapt to, so this is a plain timeout
    # and takes the ordinary timeout scale, clamped into the same window.
    if int(stats.get("total_attempts") or 0) == 0:
        return max(floor, min(ceiling, pacing.scale_timeout(ENGINE_TIMEOUT_DEFAULT)))
    avg_ms = float(stats.get("avg_response_time_ms") or 0)
    if avg_ms == 0:
        return max(floor, min(ceiling, pacing.scale_timeout(ENGINE_TIMEOUT_DEFAULT)))

    dynamic = (avg_ms / 1000.0) * ENGINE_TIMEOUT_MULTIPLIER
    return max(floor, min(ceiling, dynamic))


def engine_priority_score(stats: dict[str, Any]) -> float:
    attempts = int(stats.get("total_attempts") or 0)
    if attempts == 0:
        return 0.5

    successes = int(stats.get("total_successes") or 0)
    total_results = int(stats.get("total_results") or 0)
    success_rate = successes / max(attempts, 1)
    avg_results = total_results / max(successes, 1)
    results_score = min(avg_results / 20.0, 1.0)
    score = (success_rate * 0.6) + (results_score * 0.4)
    if float(stats.get("avg_response_time_ms") or 0) > 20000:
        score *= 0.8
    return score


def _row_to_dict(row: Any) -> dict[str, Any]:
    mapping = row._mapping if hasattr(row, "_mapping") else row
    item = dict(mapping)
    item["is_circuit_open"] = bool(item.get("is_circuit_open"))
    item["score"] = engine_priority_score(item)
    return item


def get_engine_stats(name: str) -> dict[str, Any]:
    try:
        from db.session import get_session

        ensure_search_engine_stats_table()
        with get_session() as session:
            row = session.execute(
                text("SELECT * FROM search_engine_stats WHERE engine_name = :name"),
                {"name": name},
            ).fetchone()
            if row is not None:
                return _row_to_dict(row)
    except Exception as exc:
        logger.debug("get_engine_stats failed for %s: %s", name, exc)

    return {
        "engine_name": name,
        "total_attempts": 0,
        "total_successes": 0,
        "total_results": 0,
        "consecutive_failures": 0,
        "last_success_at": None,
        "last_attempt_at": None,
        "avg_response_time_ms": 0.0,
        "is_circuit_open": False,
        "circuit_opened_at": None,
        "score": 0.5,
    }


def get_all_engine_stats() -> list[dict[str, Any]]:
    try:
        from db.session import get_session

        ensure_search_engine_stats_table()
        with get_session() as session:
            rows = session.execute(
                text("SELECT * FROM search_engine_stats ORDER BY engine_name")
            ).fetchall()
            return [_row_to_dict(row) for row in rows]
    except Exception as exc:
        logger.debug("get_all_engine_stats failed: %s", exc)
        return []


def reset_circuit(name: str) -> None:
    try:
        from db.session import get_session

        ensure_search_engine_stats_table()
        with get_session() as session:
            session.execute(
                text(
                    """
                    INSERT INTO search_engine_stats (engine_name, is_circuit_open, circuit_opened_at, consecutive_failures)
                    VALUES (:name, FALSE, NULL, 0)
                    ON CONFLICT (engine_name) DO UPDATE SET
                        is_circuit_open = FALSE,
                        circuit_opened_at = NULL,
                        consecutive_failures = 0
                    """
                ),
                {"name": name},
            )
    except Exception as exc:
        logger.debug("reset_circuit failed for %s: %s", name, exc)


def should_skip_engine(name: str) -> bool:
    stats = get_engine_stats(name)
    if not stats.get("is_circuit_open"):
        return False

    opened_at = _coerce_dt(stats.get("circuit_opened_at"))
    if opened_at is None:
        return False

    failures = int(stats.get("consecutive_failures") or 0)
    duration = circuit_duration_for_failures(failures)
    if _utcnow() - opened_at >= duration:
        logger.info("Engine %s circuit reset - testing again", name)
        reset_circuit(name)
        return False
    return True


def record_engine_attempt(
    name: str,
    success: bool,
    results_count: int,
    response_time_ms: float,
) -> None:
    try:
        from db.session import get_session

        ensure_search_engine_stats_table()
        now = _utcnow()
        with get_session() as session:
            current = session.execute(
                text("SELECT * FROM search_engine_stats WHERE engine_name = :name"),
                {"name": name},
            ).fetchone()
            existing = _row_to_dict(current) if current is not None else get_engine_stats(name)

            attempts = int(existing.get("total_attempts") or 0) + 1
            successes = int(existing.get("total_successes") or 0) + (1 if success else 0)
            total_results = int(existing.get("total_results") or 0) + max(int(results_count or 0), 0)
            previous_avg = float(existing.get("avg_response_time_ms") or 0)
            avg_ms = response_time_ms if attempts == 1 else (
                ((previous_avg * (attempts - 1)) + float(response_time_ms or 0)) / attempts
            )
            failures = 0 if success else int(existing.get("consecutive_failures") or 0) + 1
            open_circuit = False
            opened_at = None
            if not success and failures >= 3:
                open_circuit = True
                opened_at = now
                duration = circuit_duration_for_failures(failures)
                logger.info(
                    "Engine %s circuit opened - %d consecutive failures, skipping for %s",
                    name,
                    failures,
                    _format_duration(duration),
                )

            session.execute(
                text(
                    """
                    INSERT INTO search_engine_stats (
                        engine_name, total_attempts, total_successes, total_results,
                        consecutive_failures, last_success_at, last_attempt_at,
                        avg_response_time_ms, is_circuit_open, circuit_opened_at
                    )
                    VALUES (
                        :name, :attempts, :successes, :total_results,
                        :failures, :last_success_at, :last_attempt_at,
                        :avg_ms, :is_open, :opened_at
                    )
                    ON CONFLICT (engine_name) DO UPDATE SET
                        total_attempts = :attempts,
                        total_successes = :successes,
                        total_results = :total_results,
                        consecutive_failures = :failures,
                        last_success_at = :last_success_at,
                        last_attempt_at = :last_attempt_at,
                        avg_response_time_ms = :avg_ms,
                        is_circuit_open = :is_open,
                        circuit_opened_at = :opened_at
                    """
                ),
                {
                    "name": name,
                    "attempts": attempts,
                    "successes": successes,
                    "total_results": total_results,
                    "failures": failures,
                    "last_success_at": now if success else existing.get("last_success_at"),
                    "last_attempt_at": now,
                    "avg_ms": avg_ms,
                    "is_open": open_circuit,
                    "opened_at": opened_at,
                },
            )
    except Exception as exc:
        logger.debug("record_engine_attempt failed for %s: %s", name, exc)


def _format_duration(duration: timedelta) -> str:
    seconds = int(duration.total_seconds())
    if seconds >= 86400:
        return f"{seconds // 86400}d"
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    return f"{seconds}s"


async def get_engine_stats_async(name: str) -> dict[str, Any]:
    return await asyncio.to_thread(get_engine_stats, name)


async def get_all_engine_stats_async() -> list[dict[str, Any]]:
    return await asyncio.to_thread(get_all_engine_stats)


async def should_skip_engine_async(name: str) -> bool:
    return await asyncio.to_thread(should_skip_engine, name)


async def reset_circuit_async(name: str) -> None:
    await asyncio.to_thread(reset_circuit, name)


def record_engine_attempt_async(
    name: str,
    success: bool,
    results_count: int,
    response_time_ms: float,
) -> Optional[asyncio.Task]:
    try:
        loop = asyncio.get_running_loop()
        return loop.create_task(
            asyncio.to_thread(
                record_engine_attempt,
                name,
                success,
                results_count,
                response_time_ms,
            )
        )
    except RuntimeError:
        record_engine_attempt(name, success, results_count, response_time_ms)
        return None
