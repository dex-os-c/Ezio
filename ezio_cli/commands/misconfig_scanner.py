"""
cli/commands/misconfig_scanner.py — `ezio misconfig-scan` command.

BONUS / LAST-PRIORITY FEATURE.

This is deliberately a *simulated* module: it renders a canned,
pasted-in scanner banner and a static findings table instead of doing
any live scanning. It exists to preview what a future misconfiguration
scanner could surface (open panels, exposed .git/.env, weak headers,
default creds) without spending build time on a real network scanner —
that work is explicitly out of scope for this pass. The rest of the
pipeline (investigate/enrich/export/actors) is the real, working core;
this command is a mockup layered on top of it.

Command
-------
ezio misconfig-scan [TARGET] [--json]
    Prints a simulated scan banner + a static table of example
    findings. No network requests are made.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# ---------------------------------------------------------------------------
# Pasted / static banner text — this is NOT live tool output. It's a fixed
# string meant to look like a scanner's startup banner for demo purposes.
# ---------------------------------------------------------------------------
SIMULATED_BANNER = r"""
[color(141)] _______ ___ ___ _______
|   _   |_  |  _  |     |
|.  1___|_  |_   _|  |  |
|.  __) |_______|_____|
|:  |    misconfig-scanner (simulated) v0.1
|::.|    eagle-vision sweep — demo mode, no live requests
'---'
[/]
""".strip("\n")

# Static, hand-authored example findings. Numbers/paths are illustrative,
# not derived from any real scan of the target.
SIMULATED_FINDINGS = [
    {
        "severity": "high",
        "check": "exposed .git directory",
        "path": "/.git/config",
        "note": "source tree potentially clonable from the public web root",
    },
    {
        "severity": "high",
        "check": "exposed .env file",
        "path": "/.env",
        "note": "would leak API keys / DB credentials if publicly served",
    },
    {
        "severity": "medium",
        "check": "missing security headers",
        "path": "/",
        "note": "no Content-Security-Policy or X-Frame-Options observed",
    },
    {
        "severity": "medium",
        "check": "default admin panel reachable",
        "path": "/admin",
        "note": "login page reachable without IP allow-listing",
    },
    {
        "severity": "low",
        "check": "verbose server banner",
        "path": "/",
        "note": "server header discloses stack/version details",
    },
]

_SEVERITY_STYLE = {
    "high": "bold red",
    "medium": "yellow",
    "low": "dim cyan",
}


def run(
    target: Optional[str] = typer.Argument(
        None,
        help="Target label for the simulated report (display only — not scanned).",
    ),
    as_json: bool = typer.Option(
        False,
        "--json",
        help="Print the simulated findings as JSON instead of a table.",
    ),
) -> None:
    """Render a simulated misconfiguration-scan report.

    This is a bonus, lowest-priority module: it does not open sockets,
    resolve DNS, or touch the target in any way. It exists purely to
    demo the intended UX for a future real scanner.
    """
    label = target or "example-target.local"
    generated_at = datetime.now(timezone.utc).isoformat()

    if as_json:
        payload = {
            "target": label,
            "simulated": True,
            "generated_at": generated_at,
            "findings": SIMULATED_FINDINGS,
        }
        console.print(json.dumps(payload, indent=2))
        return

    console.print(Panel(SIMULATED_BANNER, border_style="color(141)", expand=False))
    console.print(
        f"[dim]target:[/dim] {label}    "
        f"[dim]mode:[/dim] [bold yellow]SIMULATED — no live requests made[/bold yellow]"
    )
    console.print()

    table = Table(title="misconfig-scan (simulated) findings", show_lines=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Check")
    table.add_column("Path")
    table.add_column("Note")

    for finding in SIMULATED_FINDINGS:
        style = _SEVERITY_STYLE.get(finding["severity"], "white")
        table.add_row(
            f"[{style}]{finding['severity'].upper()}[/{style}]",
            finding["check"],
            finding["path"],
            finding["note"],
        )

    console.print(table)
    console.print(
        "\n[dim italic]This output is pasted demo data, not a live scan. "
        "misconfig-scan is a bonus module — the real pipeline is "
        "investigate / enrich / export / actors.[/dim italic]"
    )
