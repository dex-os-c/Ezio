"""
cli/commands/export.py — convert a saved investigation to a sharable format.

    ezio export <id_or_json_file> --format stix|misp|sigma|yara|snort|suricata|package|csv|md|json
    ezio package <id_or_json_file>
"""

from __future__ import annotations

import csv
import io
import json
import re as _re
import uuid
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

console = Console()


def run(
    target: str = typer.Argument(..., help="Investigation id or .json file"),
    fmt: str = typer.Option(
        "json",
        "--format",
        help=(
            "stix|misp|sigma|yara|snort|suricata|package|csv|md|json — "
            "yara produces a .yar file, snort/suricata produce .rules files."
        ),
    ),
    output: Optional[Path] = typer.Option(None, "--output", help="Output file"),
    tlp: str = typer.Option(
        "white",
        "--tlp",
        help="TLP marker for IOC package: white|green|amber|red",
    ),
    redact_credentials: bool = typer.Option(
        True,
        "--redact-credentials/--no-redact-credentials",
        help="Partially redact credentials in the IOC package",
    ),
    include_raw: bool = typer.Option(
        False,
        "--include-raw/--no-include-raw",
        help="Include raw scraped page content in pages/ subfolder",
    ),
) -> None:
    """Export an investigation."""
    from ezio_cli import config as cli_config
    cli_config.apply_env()

    fmt = fmt.lower()
    if fmt not in (
        "stix",
        "misp",
        "sigma",
        "yara",
        "snort",
        "suricata",
        "package",
        "csv",
        "md",
        "json",
    ):
        console.print(f"[red]Unsupported format:[/red] {fmt}")
        raise typer.Exit(code=2)

    inv_id, data = _load_target(target)
    if not data:
        console.print(f"[red]Could not load investigation:[/red] {target}")
        raise typer.Exit(code=1)

    payload, suffix = _render(
        fmt,
        inv_id,
        data,
        tlp=tlp,
        redact_credentials=redact_credentials,
        include_raw=include_raw,
    )
    out_path = output or _default_out_path(
        target,
        suffix,
        fmt=fmt,
        query=_investigation_metadata(data, inv_id).get("query"),
    )
    out_path = Path(out_path).expanduser()
    if out_path.exists():
        safe_path = _collision_safe_output_path(out_path, fmt)
        console.print(
            f"[yellow]Warning:[/yellow] {out_path} already exists; "
            f"writing {safe_path} to avoid overwriting it."
        )
        out_path = safe_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, bytes):
        out_path.write_bytes(payload)
    else:
        out_path.write_text(payload, encoding="utf-8")
    console.print(f"[green]Wrote[/green] {out_path}")


def _collision_safe_output_path(path: Path, fmt: str) -> Path:
    """Return a format-aware unused path without overwriting an export."""
    candidate = path.with_name(f"{path.stem}-{fmt}{path.suffix}")
    counter = 2
    while candidate.exists():
        candidate = path.with_name(f"{path.stem}-{fmt}-{counter}{path.suffix}")
        counter += 1
    return candidate


def _load_target(target: str) -> tuple[Optional[str], Optional[dict]]:
    p = Path(target).expanduser()
    if p.exists() and p.suffix == ".json":
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None, None
        inv_id = data.get("investigation", {}).get("id") or data.get("id")
        return inv_id, data
    from ezio_cli.adapters import sqlite as sqlite_adapter
    sqlite_adapter.init_db()
    try:
        resolved = sqlite_adapter.resolve_investigation_id(target) or target
        data = sqlite_adapter.investigation_to_export_dict(resolved)
    except Exception as exc:
        # Do not let an ORM/SQLAlchemy read failure become an empty export.
        # init_db() is the schema choke-point; this guard covers a schema
        # mismatch that manifests while loading a table/column not included in
        # the lightweight preflight contract.  Rendering happens only after
        # this function returns, so no artifact can be written on failure.
        from sqlalchemy.exc import OperationalError

        if isinstance(exc, OperationalError):
            raise sqlite_adapter.DatabaseSchemaError(
                "Export could not read the database; the schema may be stale. "
                "Run `alembic upgrade head` and retry."
            ) from exc
        raise
    if not data or not data.get("investigation"):
        return None, None
    return resolved, data


def _render(
    fmt: str,
    inv_id: Optional[str],
    data: dict,
    *,
    tlp: str = "white",
    redact_credentials: bool = True,
    include_raw: bool = False,
) -> tuple[str | bytes, str]:
    if fmt == "json":
        return json.dumps(data, indent=2, default=str), ".json"

    if fmt == "csv":
        return _csv_from_data(data), ".csv"

    if fmt == "md":
        from ezio_cli.commands.investigate import _render_markdown  # reuse renderer
        # Adapt shape: _render_markdown expects flat payload
        flat = _flatten_for_md(data)
        return _render_markdown(flat), ".md"

    # Package format: works with both JSON files (no DB needed) and live IDs.
    # The package generator uses investigation_id only for filename / metadata
    # — never for DB lookup — so a non-UUID id from a JSON file is fine here.
    if fmt == "package":
        return _render_package(
            inv_id or "", data, tlp=tlp,
            redact_credentials=redact_credentials,
            include_raw=include_raw,
        )

    # YARA / Snort / Suricata can work with either a DB investigation_id
    # (preferred) or a plain JSON file containing entities.
    if fmt in ("yara", "snort", "suricata"):
        return _render_detection_rule(fmt, inv_id, data, tlp=tlp)

    # STIX/MISP/Sigma need a real investigation_id (UUID) and load from DB
    if inv_id is None:
        raise typer.BadParameter(
            "STIX, MISP, and Sigma export require an investigation id in the database "
            "(not a bare JSON file)."
        )
    try:
        inv_uuid = uuid.UUID(inv_id)
    except (ValueError, TypeError) as exc:
        raise typer.BadParameter(f"Invalid investigation id: {inv_id} ({exc})") from exc

    if fmt == "stix":
        from export import investigation_to_stix_bundle, bundle_to_json
        from export.stix import get_last_relationship_warning
        bundle = investigation_to_stix_bundle(inv_uuid)
        warning = get_last_relationship_warning()
        if warning:
            console.print(
                f"[yellow]Warning:[/yellow] STIX relationships were not included: {warning}"
            )
        return bundle_to_json(bundle), ".json"

    if fmt == "misp":
        from export import investigation_to_misp_event, misp_event_to_json
        event = investigation_to_misp_event(inv_uuid)
        return misp_event_to_json(event), ".json"

    if fmt == "sigma":
        from export import render_sigma_rules
        # The IOC package and direct CLI export must share the same generator.
        # ``data`` was loaded through the CLI's init_db() choke-point above;
        # loading the entities again through export_sigma_rules() used to
        # create a second, error-swallowing DB path and yielded empty files.
        return render_sigma_rules(data.get("entities") or []), ".yml"

    raise typer.BadParameter(f"Unknown format: {fmt}")


def _render_detection_rule(
    fmt: str,
    inv_id: Optional[str],
    data: dict,
    *,
    tlp: str = "white",
) -> tuple[str, str]:
    """Render YARA / Snort / Suricata rules.

    Prefers the live DB if ``inv_id`` is a UUID.  Falls back to the entities
    already embedded in the JSON payload so this still works when the user
    passes a ``.json`` file (the API path requires a DB investigation).
    """
    investigation = _investigation_metadata(data, inv_id)
    investigation_dict: dict = {
        "id": investigation.get("id") or inv_id or "",
        "run_id": investigation.get("run_id"),
        "query": investigation.get("query") or "",
        "summary": investigation.get("summary") or "",
        "created_at": investigation.get("created_at"),
    }
    entities = data.get("entities") or []

    # If we have a real investigation id in the DB, prefer the live entities
    # — they may include additional context the JSON file lacks.
    if inv_id:
        try:
            inv_uuid = uuid.UUID(inv_id)
        except (ValueError, TypeError):
            inv_uuid = None
        if inv_uuid is not None:
            try:
                from export.stix import _load_entities_for_investigation  # noqa: PLC0415
                live_entities = _load_entities_for_investigation(str(inv_uuid))
                if live_entities:
                    entities = live_entities
            except Exception:
                # Fall back to JSON entities silently
                pass

    tlp_marker = f"TLP:{(tlp or 'white').upper()}"

    if fmt == "yara":
        from export.yara_export import generate_yara_rules
        return generate_yara_rules(entities, investigation_dict, tlp=tlp_marker), ".yar"

    if fmt in ("snort", "suricata"):
        from export.snort_export import generate_snort_rules
        return (
            generate_snort_rules(
                entities, investigation_dict, format=fmt, tlp=tlp_marker
            ),
            ".rules",
        )

    raise typer.BadParameter(f"Unknown detection format: {fmt}")


def _render_package(
    inv_id: str,
    data: dict,
    *,
    tlp: str,
    redact_credentials: bool,
    include_raw: bool,
) -> tuple[bytes, str]:
    """Build an IOC package ZIP from a saved investigation."""
    import asyncio
    from export.ioc_package import build_package_filename, generate_ioc_package

    investigation = _investigation_metadata(data, inv_id)
    entities = data.get("entities") or []

    # Build the flat-shape dict the package generator expects.
    investigation_dict: dict = {
        "id": investigation.get("id") or inv_id,
        "run_id": investigation.get("run_id"),
        "query": investigation.get("query") or "",
        "summary": investigation.get("summary") or "",
        "created_at": investigation.get("created_at"),
        "sources_used": data.get("sources_used") or {},
    }

    # Reuse the package filename helper for consistent naming.
    filename = build_package_filename(investigation_dict, inv_id)
    suffix = "".join([".", filename.split(".")[-1]]) if "." in filename else ".zip"

    zip_bytes = asyncio.run(
        generate_ioc_package(
            investigation_id=inv_id,
            entities=entities,
            investigation=investigation_dict,
            session=None,
            tlp=tlp,
            redact_credentials=redact_credentials,
            include_raw=include_raw,
        )
    )
    return zip_bytes, suffix


def _investigation_metadata(data: dict, inv_id: Optional[str] = None) -> dict:
    """Return metadata from either DB-shaped or flat CLI JSON payloads."""
    nested = data.get("investigation")
    nested = nested if isinstance(nested, dict) else {}
    fields = (
        "id",
        "run_id",
        "query",
        "refined_query",
        "model_used",
        "summary",
        "created_at",
        "sources_used",
    )
    metadata = {field: data[field] for field in fields if field in data}
    metadata.update(nested)
    metadata["id"] = nested.get("id") or data.get("id") or inv_id or ""
    metadata["query"] = nested.get("query") or data.get("query") or ""
    metadata["sources_used"] = (
        nested.get("sources_used") or data.get("sources_used") or {}
    )
    return metadata


def _csv_from_data(data: dict) -> str:
    entities = data.get("entities", [])
    if not entities and isinstance(data.get("investigation"), dict):
        entities = data.get("entities", [])
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["entity_type", "value", "canonical_value", "confidence", "priority_score",
         "extraction_method", "corroborating_sources", "investigation_count",
         "context_snippet"]
    )
    for e in entities:
        writer.writerow(
            [
                e.get("entity_type", ""),
                e.get("value", ""),
                e.get("canonical_value", ""),
                e.get("confidence", ""),
                e.get("priority_score", ""),
                e.get("extraction_method", ""),
                e.get("corroborating_sources", ""),
                e.get("investigation_count", 1),
                (e.get("context_snippet") or "").replace("\n", " ")[:500],
            ]
        )
    return buf.getvalue()


def _flatten_for_md(data: dict) -> dict:
    if "investigation" in data:
        inv = data["investigation"]
        return {
            "query": inv.get("query", ""),
            "refined_query": inv.get("refined_query"),
            "model_used": inv.get("model_used"),
            "created_at": inv.get("created_at", ""),
            "summary": inv.get("summary"),
            "entities": data.get("entities", []),
            "relationships": data.get("relationships", []),
            "sources_used": data.get("sources_used", {}),
        }
    return data


_FILENAME_SAFE = _re.compile(r"[^A-Za-z0-9_-]+")


def _default_out_path(
    target: str,
    suffix: str,
    fmt: str = "",
    query: Optional[str] = None,
) -> Path:
    from ezio_cli import config as cli_config
    p = Path(target).expanduser()
    if p.exists():
        # For package format, always use the auto-generated filename
        # (e.g. ezio-lockbit-20260609.zip) so multiple invocations
        # don't clobber the same target file.
        if fmt == "package":
            from export.ioc_package import build_package_filename
            inv_meta = {"id": p.stem, "query": query or p.stem}
            filename = build_package_filename(inv_meta, p.stem)
            return p.parent / filename
        # For detection rule formats, embed the format name so two calls
        # (e.g. yara + snort) don't overwrite each other when the user
        # passes the same input file.
        if fmt in ("yara", "snort", "suricata"):
            stem = _FILENAME_SAFE.sub("-", query or p.stem).strip("-_") or p.stem
            return p.parent / f"{stem}-{fmt}{suffix}"
        candidate = p.with_suffix(suffix)
        # Avoid overwriting input when suffix is the same (e.g. stix/misp .json)
        if candidate == p and fmt and fmt not in ("json",):
            return p.parent / f"{p.stem}-{fmt}{suffix}"
        return candidate
    return cli_config.get_output_dir() / f"{target}{suffix}"
