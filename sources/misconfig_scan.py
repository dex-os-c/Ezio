"""
sources/misconfig_scan.py — real, passive misconfiguration scanning.

Everything here is a normal HTTP GET/HEAD request a browser would make —
no exploitation, no brute forcing, no credential guessing. Four checks:

1. Missing security response headers (CSP, HSTS, X-Content-Type-Options, ...)
2. Exposed sensitive files (.git/config, .env, .DS_Store, backups, ...)
3. Reachable default admin panels
4. TLS certificate health (expiry, self-signed)

This scans whatever target the caller passes in directly — unlike the
dark-web crawler in scraper/scrape.py, which fetches automatically
*discovered* URLs and therefore applies a strict SSRF blocklist,
misconfig-scan is aimed at a target the user explicitly typed (their own
infrastructure, most commonly), so it does not block private/internal
addresses. It still refuses to follow redirects blindly (redirects are
reported, not chased) so a malicious server can't pivot the scan
elsewhere, and it never touches non-HTTP(S) schemes.

Use only against systems you're authorized to test — see
docs/USAGE_POLICY.md.
"""

from __future__ import annotations

import logging
import ssl
import socket
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)

USER_AGENT = "Ezio-MisconfigScan/1.0 (+authorized-testing; see docs/USAGE_POLICY.md)"

_SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy": "no Content-Security-Policy — reduces protection against XSS/injection",
    "strict-transport-security": "no Strict-Transport-Security — HTTPS downgrade/stripping is possible",
    "x-content-type-options": "no X-Content-Type-Options: nosniff — MIME-sniffing attacks are possible",
    "x-frame-options": "no X-Frame-Options (and no frame-ancestors CSP) — clickjacking is possible",
    "referrer-policy": "no Referrer-Policy — full URLs may leak to third parties via the Referer header",
}

_SENSITIVE_PATHS: list[str] = [
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.DS_Store",
    "/.svn/entries",
    "/.htpasswd",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/backup.zip",
    "/.aws/credentials",
]

_ADMIN_PATHS: list[str] = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/manager/html",
]

_BODY_SNIPPET_LIMIT = 512


def _normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("empty target")
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme!r} — only http/https are scanned")
    if not parsed.hostname:
        raise ValueError("target has no hostname")
    return target


def _finding(severity: str, check: str, path: str, note: str) -> dict[str, str]:
    return {"severity": severity, "check": check, "path": path, "note": note}


async def _fetch(
    session: aiohttp.ClientSession, url: str, method: str = "GET"
) -> Optional[aiohttp.ClientResponse]:
    try:
        resp = await session.request(method, url, allow_redirects=False, ssl=True)
        return resp
    except aiohttp.ClientConnectorCertificateError:
        # Retry once without cert verification purely to observe headers/paths;
        # the cert problem itself is reported separately by _check_tls().
        try:
            return await session.request(method, url, allow_redirects=False, ssl=False)
        except Exception as exc:
            logger.debug("misconfig_scan: %s %s failed even without TLS verify: %s", method, url, exc)
            return None
    except Exception as exc:
        logger.debug("misconfig_scan: %s %s failed: %s", method, url, exc)
        return None


async def _check_security_headers(session: aiohttp.ClientSession, base_url: str) -> tuple[list[dict], Optional[str]]:
    resp = await _fetch(session, base_url, "GET")
    if resp is None:
        return [], "root page unreachable — security header check skipped"
    findings = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for header, note in _SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(_finding("medium", "missing security header", "/", note))
    server = headers.get("server")
    if server:
        findings.append(
            _finding("low", "verbose server banner", "/", f"Server header discloses: {server}")
        )
    powered_by = headers.get("x-powered-by")
    if powered_by:
        findings.append(
            _finding("low", "verbose framework banner", "/", f"X-Powered-By discloses: {powered_by}")
        )
    if 300 <= resp.status < 400 and resp.headers.get("Location"):
        findings.append(
            _finding(
                "low",
                "redirect on root",
                "/",
                f"root redirects to {resp.headers['Location']!r} (not followed — see module docstring)",
            )
        )
    resp.release()
    return findings, None


async def _check_sensitive_paths(session: aiohttp.ClientSession, base_url: str) -> list[dict]:
    findings = []
    for path in _SENSITIVE_PATHS:
        resp = await _fetch(session, base_url.rstrip("/") + path, "GET")
        if resp is None:
            continue
        if resp.status == 200:
            body = (await resp.text(errors="replace"))[:_BODY_SNIPPET_LIMIT] if resp.content_length else ""
            findings.append(
                _finding(
                    "high",
                    "exposed sensitive path",
                    path,
                    "HTTP 200 on a path that should not be public — verify manually, "
                    "some servers return 200 for every path (soft-404)",
                )
            )
            _ = body  # reserved for future content-based confirmation heuristics
        resp.release()
    return findings


async def _check_admin_paths(session: aiohttp.ClientSession, base_url: str) -> list[dict]:
    findings = []
    for path in _ADMIN_PATHS:
        resp = await _fetch(session, base_url.rstrip("/") + path, "GET")
        if resp is None:
            continue
        if resp.status == 200:
            findings.append(
                _finding(
                    "medium",
                    "default admin panel reachable",
                    path,
                    "reachable with no visible authentication challenge",
                )
            )
        elif resp.status in (401, 403):
            findings.append(
                _finding(
                    "low",
                    "default admin panel present",
                    path,
                    f"exists and requires auth (HTTP {resp.status}) — confirm access is restricted to trusted networks",
                )
            )
        resp.release()
    return findings


def _check_tls_sync(hostname: str, port: int = 443, timeout: float = 8.0) -> tuple[list[dict], Optional[str]]:
    findings: list[dict] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return [
            _finding("high", "invalid TLS certificate", "/", f"certificate verification failed: {exc.verify_message or exc}")
        ], None
    except Exception as exc:
        return [], f"TLS check skipped: {exc}"

    not_after = cert.get("notAfter") if cert else None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(_finding("high", "expired TLS certificate", "/", f"expired {-days_left} day(s) ago"))
            elif days_left < 30:
                findings.append(_finding("medium", "TLS certificate expiring soon", "/", f"expires in {days_left} day(s)"))
        except Exception as exc:
            logger.debug("misconfig_scan: could not parse cert expiry %r: %s", not_after, exc)
    return findings, None


async def scan_target(target: str, timeout: float = 10.0) -> dict[str, Any]:
    """Run all passive checks against *target*. Never raises — failures become findings/errors."""
    findings: list[dict] = []
    errors: list[str] = []

    try:
        base_url = _normalize_target(target)
    except ValueError as exc:
        return {
            "target": target,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "findings": [],
            "errors": [f"invalid target: {exc}"],
        }

    client_timeout = aiohttp.ClientTimeout(total=timeout)
    headers = {"User-Agent": USER_AGENT}
    async with aiohttp.ClientSession(timeout=client_timeout, headers=headers) as session:
        header_findings, header_err = await _check_security_headers(session, base_url)
        findings.extend(header_findings)
        if header_err:
            errors.append(header_err)

        findings.extend(await _check_sensitive_paths(session, base_url))
        findings.extend(await _check_admin_paths(session, base_url))

    hostname = urlparse(base_url).hostname
    if hostname and urlparse(base_url).scheme == "https":
        try:
            import asyncio

            tls_findings, tls_err = await asyncio.to_thread(_check_tls_sync, hostname)
            findings.extend(tls_findings)
            if tls_err:
                errors.append(tls_err)
        except Exception as exc:
            errors.append(f"TLS check failed: {exc}")

    return {
        "target": base_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "errors": errors,
    }
