"""
cli/commands/actors.py — `ezio actors` and `ezio actor` commands.

Persistent cross-investigation actor profiles.  Backed by the
``actor_profiles`` / ``actor_aliases`` / ``actor_infrastructure`` tables
populated automatically by the investigation pipeline.

Commands
--------
ezio actors [--limit N] [--search TERM] [--json]
    List all profiles in a table.  Optional ``--search`` does a
    case-insensitive partial match against canonical_handle + aliases.

ezio actor <handle> [--json]
    Show the full profile: aliases, infrastructure, investigation
    history, notes.

ezio actor <handle> --note "text"
    Append an analyst note to the profile's notes column.  Each note is
    timestamped; existing notes are preserved.
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

console = Console()


def run(
    handle: Optional[str] = typer.Argument(
        None,
        help="Canonical handle (or UUID) to inspect. Omit to list all.",
    ),
    limit: int = typer.Option(
        20, "--limit", "-n", help="Number of profiles to list (only when handle omitted)"
    ),
    search: Optional[str] = typer.Option(
        None, "--search", "-s", help="Case-insensitive partial match"
    ),
    note: Optional[str] = typer.Option(
        None, "--note", help="Append an analyst note (requires <handle>)"
    ),
    timeline: bool = typer.Option(
        False, "--timeline",
        help="Show chronological activity timeline (requires <handle>)",
    ),
    event_types: Optional[str] = typer.Option(
        None, "--event-types",
        help=(
            "Comma-separated event types to include "
            "(FIRST_SEEN, INVESTIGATION, NEW_ALIAS, "
            "NEW_INFRASTRUCTURE, NOTE_ADDED)"
        ),
    ),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
) -> None:
    """Inspect or annotate persistent actor profiles."""
    from ezio_cli import config as cli_config

    cli_config.apply_env()
    from ezio_cli.adapters import sqlite as sqlite_adapter

    sqlite_adapter.init_db()

    if handle and timeline:
        _show_timeline(
            handle,
            limit=limit,
            event_types=event_types,
            as_json=as_json,
        )
        return

    if handle and note and isinstance(note, str):
        # ``note`` may be a typer OptionInfo sentinel when this function is
        # called programmatically from another command (see the
        # ``ezio timeline`` shortcut) — only treat a real string as
        # a request to append.
        _add_note(handle, note)
        return

    if handle:
        _show_profile(handle, as_json=as_json)
        return

    _list_profiles(limit=limit, search=search, as_json=as_json)


def _list_profiles(limit: int, search: Optional[str], as_json: bool) -> None:
    from ezio_cli.adapters import sqlite as sqlite_adapter

    if search:
        profiles = sqlite_adapter.search_actor_profiles(search, limit=limit)
    else:
        profiles = sqlite_adapter.list_actor_profiles(limit=limit)

    if as_json:
        console.print(json.dumps(profiles, indent=2, default=str))
        return

    if not profiles:
        if search:
            console.print(
                f"[grey50]No actor profiles matching [bold]{search}[/bold].[/grey50]"
            )
        else:
            console.print(
                "[grey50]No actor profiles yet. "
                "Run an investigation that surfaces a "
                "THREAT_ACTOR_HANDLE / RANSOMWARE_GROUP entity.[/grey50]"
            )
        return

    table = Table(title="Actor profiles", show_lines=False)
    table.add_column("Handle", style="cyan", no_wrap=True)
    table.add_column("Investigations", justify="right")
    table.add_column("First seen")
    table.add_column("Last seen")
    table.add_column("Aliases", justify="right")
    table.add_column("Conf", justify="right")

    for p in profiles:
        table.add_row(
            str(p.get("canonical_handle") or ""),
            str(p.get("investigation_count") or 0),
            _short_dt(p.get("first_seen_at")),
            _short_dt(p.get("last_seen_at")),
            str(p.get("alias_count") or 0),
            f"{(p.get('confidence') or 0.0):.2f}",
        )
    console.print(table)


def _show_profile(handle: str, as_json: bool) -> None:
    from ezio_cli.adapters import sqlite as sqlite_adapter

    profile = sqlite_adapter.get_actor_profile(handle)
    if profile is None:
        console.print(f"[red]Actor not found:[/red] {handle}")
        raise typer.Exit(code=1)

    if as_json:
        # Augment JSON output with computed alias candidates so the
        # --json consumer gets the same view as the rich renderer.
        try:
            alias_block = _compute_alias_candidates_block(
                profile,
                sqlite_adapter=sqlite_adapter,
            )
            profile["alias_candidates"] = alias_block
        except Exception:
            profile["alias_candidates"] = {
                "confirmed": [], "likely": [], "possible": []
            }
        console.print(json.dumps(profile, indent=2, default=str))
        return

    console.rule(
        f"[bold cyan]{profile['canonical_handle']}[/bold cyan]"
    )

    info = Table(show_header=False, show_lines=False)
    info.add_column("Field", style="bold")
    info.add_column("Value")
    info.add_row("ID", str(profile.get("id") or ""))
    info.add_row("First seen", _short_dt(profile.get("first_seen_at")))
    info.add_row("Last seen", _short_dt(profile.get("last_seen_at")))
    info.add_row("Investigations", str(profile.get("investigation_count") or 0))
    info.add_row("Confidence", f"{profile.get('confidence') or 0.0:.2f}")
    info.add_row("Aliases", str(len(profile.get("aliases") or [])))
    info.add_row(
        "Infrastructure",
        str(len(profile.get("infrastructure") or [])),
    )
    console.print(info)

    aliases = profile.get("aliases") or []
    if aliases:
        a_table = Table(title="Aliases", show_lines=False)
        a_table.add_column("Type", style="bold")
        a_table.add_column("Value")
        a_table.add_column("Confidence", justify="right")
        for a in aliases:
            a_table.add_row(
                str(a.get("alias_type") or ""),
                str(a.get("alias_value") or ""),
                f"{(a.get('confidence') or 0.0):.2f}",
            )
        console.print(a_table)

    # Cross-alias resolution surface (always visible — empty tiers are
    # omitted from the table to keep the noise level down).
    try:
        alias_block = _compute_alias_candidates_block(
            profile,
            sqlite_adapter=sqlite_adapter,
        )
    except Exception as exc:
        console.print(
            f"[grey50]Alias candidate lookup failed: {exc}[/grey50]"
        )
        alias_block = {
            "confirmed": [], "likely": [], "possible": []
        }

    candidate_rows: list[tuple[str, float, str]] = []
    for c in alias_block.get("confirmed") or []:
        candidate_rows.append(
            (
                c.get("candidate_handle") or "",
                float(c.get("confidence") or 0.0),
                " | ".join(c.get("signals") or []),
            )
        )
    for c in alias_block.get("likely") or []:
        candidate_rows.append(
            (
                c.get("candidate_handle") or "",
                float(c.get("confidence") or 0.0),
                " | ".join(c.get("signals") or []),
            )
        )
    for c in alias_block.get("possible") or []:
        candidate_rows.append(
            (
                c.get("candidate_handle") or "",
                float(c.get("confidence") or 0.0),
                " | ".join(c.get("signals") or []),
            )
        )
    if candidate_rows:
        c_table = Table(title="Possible aliases", show_lines=False)
        c_table.add_column("Handle", style="cyan")
        c_table.add_column("Conf", justify="right")
        c_table.add_column("Signals")
        for handle_str, conf, sigs in candidate_rows:
            c_table.add_row(handle_str, f"{conf:.2f}", sigs or "—")
        console.print(c_table)
    else:
        console.print(
            "[grey50]No alias candidates above the default threshold "
            "(0.60). Lower with the API for a broader sweep.[/grey50]"
        )

    infra = profile.get("infrastructure") or []
    if infra:
        i_table = Table(title="Infrastructure", show_lines=False)
        i_table.add_column("Type", style="bold")
        i_table.add_column("Value")
        i_table.add_column("Last seen")
        for i in infra:
            i_table.add_row(
                str(i.get("entity_type") or ""),
                str(i.get("entity_value") or ""),
                _short_dt(i.get("last_seen_at")),
            )
        console.print(i_table)

    inv_ids = profile.get("investigation_ids") or []
    if inv_ids:
        investigations = sqlite_adapter.get_actor_investigations(handle)
        if investigations:
            v_table = Table(title="Investigation history", show_lines=False)
            v_table.add_column("ID", style="cyan")
            v_table.add_column("Query")
            v_table.add_column("Status")
            v_table.add_column("Created")
            for inv in investigations:
                v_table.add_row(
                    str(inv.get("id") or "")[:8],
                    (inv.get("query") or "")[:60],
                    str(inv.get("status") or ""),
                    _short_dt(inv.get("created_at")),
                )
            console.print(v_table)

    notes = (profile.get("notes") or "").strip()
    if notes:
        console.print()
        console.print("[bold]Analyst notes[/bold]")
        console.print(notes)
    else:
        console.print()
        console.print(
            "[grey50]No analyst notes yet. "
            "Add one with: ezio actor "
            f"{profile['canonical_handle']} --note \"text\"[/grey50]"
        )


def _compute_alias_candidates_block(
    profile: dict,
    sqlite_adapter,
    min_confidence: float = 0.60,
) -> dict:
    """Best-effort helper that runs the alias-resolution pass and groups
    the candidates into the three confidence tiers.

    The CLI is sync; the manager method is async, so we drive it via
    ``asyncio.run`` from a single-shot loop.  Errors are returned as
    empty tiers so the rest of the rendering can continue.
    """
    import asyncio

    from sources.actor_profiles import ActorProfileManager

    actor_id = profile.get("id")
    if not actor_id:
        return {"confirmed": [], "likely": [], "possible": []}

    try:
        manager = ActorProfileManager()
        candidates = asyncio.run(
            manager.find_alias_candidates(
                actor_id, min_confidence=min_confidence
            )
        )
    except Exception:
        return {"confirmed": [], "likely": [], "possible": []}

    confirmed: list[dict] = []
    likely: list[dict] = []
    possible: list[dict] = []
    for c in candidates or []:
        conf = float(c.get("confidence") or 0.0)
        entry = {
            "candidate_actor_id": c.get("candidate_actor_id"),
            "candidate_handle": c.get("candidate_handle"),
            "confidence": conf,
            "signals": c.get("signals") or [],
            "shared_infrastructure": c.get("shared_infrastructure") or [],
            "shared_pgp": c.get("shared_pgp") or [],
            "shared_investigations": c.get("shared_investigations") or [],
        }
        if conf >= 0.90:
            confirmed.append(entry)
        elif conf >= 0.75:
            likely.append(entry)
        else:
            possible.append(entry)
    return {"confirmed": confirmed, "likely": likely, "possible": possible}


def _add_note(handle: str, note: str) -> None:
    from ezio_cli.adapters import sqlite as sqlite_adapter

    ok = sqlite_adapter.add_actor_note(handle, note)
    if not ok:
        console.print(f"[red]Actor not found:[/red] {handle}")
        raise typer.Exit(code=1)
    console.print(f"[green]✓[/green] Note added to actor profile: [bold]{handle}[/bold]")


def _show_timeline(
    handle: str,
    limit: int = 50,
    event_types: Optional[str] = None,
    as_json: bool = False,
) -> None:
    """Render the actor's activity timeline via the manager.

    The timeline is computed on the fly by
    :meth:`ActorProfileManager.get_actor_timeline` — see
    ``sources/actor_profiles.py``.  This helper exists because the CLI
    command body is synchronous; we drive the async manager via a
    one-shot ``asyncio.run`` like the rest of the command does for the
    alias-candidates pass.
    """
    from sources.actor_profiles import ActorProfileManager

    try:
        manager = ActorProfileManager()
        # Fetch extra events when filtering so the user still gets up to
        # ``limit`` matches after the filter narrows them down.
        fetch_limit = limit
        if event_types:
            fetch_limit = max(limit * 4, 100)
        events = asyncio.run(
            manager.get_actor_timeline(
                handle,
                limit=fetch_limit,
                event_types=_parse_event_types(event_types),
            )
        )
    except Exception as exc:
        console.print(f"[red]Failed to build timeline:[/red] {exc}")
        raise typer.Exit(code=1)

    if event_types:
        wanted = _parse_event_types(event_types) or set()
        if wanted:
            events = [e for e in events if e.get("event_type") in wanted]

    events = events[: max(1, int(limit or 50))]

    if as_json:
        last_seen = events[-1].get("timestamp") if events else None
        payload = {
            "handle": handle,
            "event_count": len(events),
            "first_seen": events[0].get("timestamp") if events else None,
            "last_seen": last_seen,
            "events": events,
        }
        console.print(json.dumps(payload, indent=2, default=str))
        return

    if not events:
        console.print(
            f"[grey50]No timeline events for [bold]{handle}[/bold]. "
            "Run an investigation or add aliases/notes to populate "
            "the profile.[/grey50]"
        )
        return

    console.rule(f"[bold cyan]Actor Timeline: {handle}[/bold cyan]")

    type_color = {
        "FIRST_SEEN": "green",
        "INVESTIGATION": "cyan",
        "NEW_ALIAS": "yellow",
        "NEW_INFRASTRUCTURE": "magenta",
        "NOTE_ADDED": "blue",
    }

    for event in events:
        ts = event.get("timestamp") or "—"
        ts_short = str(ts)[:10] if ts != "—" else "—"
        event_type = str(event.get("event_type") or "UNKNOWN")
        description = str(event.get("description") or "")

        colour = type_color.get(event_type, "white")
        console.print(
            f"[bold]{ts_short}[/bold]  [{colour}]{event_type}[/{colour}]"
        )
        console.print(f"            {description}")

        meta = event.get("metadata") or {}
        inv_query = event.get("investigation_query")
        if inv_query:
            console.print(
                f"            [grey50]query=[italic]{inv_query}[/italic][/grey50]"
            )
        for k, v in meta.items():
            if v in (None, "", [], {}):
                continue
            console.print(f"            [grey50]{k}={v}[/grey50]")
        console.print()

    console.rule(f"{len(events)} events total")


def _parse_event_types(raw: Optional[str]) -> Optional[set[str]]:
    """Normalise a comma-separated ``--event-types`` value into a set.

    Returns ``None`` when no filter is requested so the manager can
    skip its filtering branch entirely.
    """
    if not raw:
        return None
    parts = {p.strip().upper() for p in raw.split(",") if p and p.strip()}
    return parts or None


def _short_dt(value) -> str:
    """Trim ISO datetime to YYYY-MM-DD HH:MM for compact table rendering."""
    if not value:
        return "—"
    s = str(value)
    if len(s) >= 16:
        return s[:16].replace("T", " ")
    return s