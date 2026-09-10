"""
cli/commands/misconfig_scanner.py — `ezio misconfig-scan` command.

Runs a real, passive misconfiguration scan against a target you specify:
missing security headers, exposed sensitive paths (.git, .env, backups),
reachable default admin panels, and TLS certificate health. Every check
is a normal HTTP GET/HEAD request — no exploitation, no brute forcing.

Only scan systems you are authorized to test — see docs/USAGE_POLICY.md,
which governs this command exactly as it governs the rest of Ezio.

Command
-------
ezio misconfig-scan TARGET [--json] [--timeout SECONDS]
"""

from __future__ import annotations

import asyncio
import json

import typer
from rich.console import Console
from rich.table import Table

from sources.misconfig_scan import scan_target as _scan_target

console = Console()

_SEVERITY_STYLE = {
    "high": "bold red",
    "medium": "yellow",
    "low": "dim cyan",
}


def run(
    target: str = typer.Argument(
        ...,
        help="Host or URL to scan (e.g. example.com or https://example.com). "
        "Only scan targets you are authorized to test.",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        help="Per-request timeout in seconds.",
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Print findings as JSON instead of a table.",
    ),
) -> None:
    """Run a real passive misconfiguration scan against TARGET.

    Checks: missing security headers, exposed sensitive paths (.git/.env/
    backups), reachable default admin panels, TLS certificate health.
    All checks are passive HTTP requests — nothing here exploits, brute
    forces, or guesses credentials.
    """
    result = asyncio.run(_scan_target(target, timeout=timeout))

    if as_json:
        console.print(json.dumps(result, indent=2))
        return

    console.print(
        f"[dim]target:[/dim] {result['target']}    "
        f"[dim]scanned:[/dim] {result['scanned_at']}"
    )
    console.print(
        "[dim italic]Passive checks only (headers, exposed paths, admin panels, TLS). "
        "Scan only systems you're authorized to test.[/dim italic]\n"
    )

    for error in result["errors"]:
        console.print(f"[yellow]⚠ {error}[/yellow]")

    findings = result["findings"]
    if not findings:
        console.print("[green]No misconfigurations found by these checks.[/green]")
        console.print(
            "[dim]Note: absence of findings here is not a clean bill of health — "
            "this covers a fixed, passive checklist, not a full assessment.[/dim]"
        )
        return

    table = Table(title="misconfig-scan findings")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Check")
    table.add_column("Path")
    table.add_column("Note")

    severity_order = {"high": 0, "medium": 1, "low": 2}
    for finding in sorted(findings, key=lambda f: severity_order.get(f["severity"], 9)):
        style = _SEVERITY_STYLE.get(finding["severity"], "white")
        table.add_row(
            f"[{style}]{finding['severity'].upper()}[/{style}]",
            finding["check"],
            finding["path"],
            finding["note"],
        )

    console.print(table)
