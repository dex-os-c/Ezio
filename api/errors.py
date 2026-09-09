"""
api/errors.py — Safe error responses: public generic message, private detailed log.

All internal/unhandled errors surfaced to API clients must go through these
helpers so that:

  * the client only ever sees a generic message plus a correlation ID, and
  * the full exception (message + traceback) is logged server-side, tagged
    with the same correlation ID, for the operator to correlate.

This is the standard "public error, private log" split. Never place a raw
exception object or its string representation into a response body — a raw
message can leak database connection fragments, internal file paths, the
reason an enrichment provider call failed (which may include partial
credential material for a malformed key), or other implementation details
that make the system easier to probe. Use these helpers instead.
"""

from __future__ import annotations

import logging
import uuid
from typing import Optional

from fastapi import HTTPException, Request

logger = logging.getLogger("ezio.api.errors")

# Generic, safe message shown to clients for any unhandled/internal error.
GENERIC_ERROR_MESSAGE = (
    "An internal error occurred. Reference the correlation ID when contacting support."
)


def new_correlation_id() -> str:
    """Return a fresh correlation ID for a single failed request."""
    return uuid.uuid4().hex


def log_exception(
    exc: BaseException,
    *,
    context: str = "",
    request: Optional[Request] = None,
    correlation_id: Optional[str] = None,
    level: int = logging.ERROR,
) -> str:
    """Log the full exception detail server-side, tagged with a correlation ID.

    Returns the correlation ID so the caller can echo it (and only it) back to
    the client. The full message and traceback stay in the server log only.
    """
    correlation_id = correlation_id or new_correlation_id()

    where = context
    if request is not None:
        try:
            where = f"{request.method} {request.url.path}"
            if context:
                where = f"{where} ({context})"
        except Exception:  # never let logging path-extraction raise
            where = context

    logger.log(
        level,
        "[correlation_id=%s] Internal error in %s: %s",
        correlation_id,
        where or "request",
        exc,
        exc_info=exc,
    )
    return correlation_id


def safe_detail(correlation_id: str, message: str = GENERIC_ERROR_MESSAGE) -> str:
    """A generic ``detail`` string safe to return to clients, with the ID appended."""
    return f"{message} (correlation ID: {correlation_id})"


def safe_error_body(correlation_id: str, message: str = GENERIC_ERROR_MESSAGE) -> dict:
    """A generic JSON body safe to return to clients (generic message + ID)."""
    return {"detail": message, "correlation_id": correlation_id}


def internal_http_exception(
    exc: BaseException,
    *,
    request: Optional[Request] = None,
    context: str = "",
    status_code: int = 500,
) -> HTTPException:
    """Log ``exc`` in full and build an ``HTTPException`` with a safe body.

    Raise the returned exception from a route handler:

        raise internal_http_exception(exc, context="create_monitor")
    """
    correlation_id = log_exception(exc, context=context, request=request)
    return HTTPException(status_code=status_code, detail=safe_detail(correlation_id))
