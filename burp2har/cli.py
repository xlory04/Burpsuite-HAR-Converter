"""
CLI entry point for burp2har.

Subcommands
-----------
  convert  <file.xml>  — convert Burp Suite XML → HAR  (default when a path is given)
  validate <file.xml>  — validate XML structure without converting
  info     <file.xml>  — show file statistics and metadata
  update               — check for and install the latest version
  help                 — show a detailed user guide

Shorthand
---------
  burp2har <file.xml>  →  burp2har convert <file.xml>
"""
from __future__ import annotations

import io
import sys
import traceback
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Optional
from urllib.parse import urlparse
import pathlib

import typer

from .config import DISPLAY_NAME, PROJECT_URL, RELEASES_PAGE_URL, VERSION
from .first_run import is_first_run, mark_initialized
from .functions import burp2har_run
from .updater import check_for_updates, perform_update
from .validator import CompatibilityStatus, validate_xml

# ── Rich (optional — graceful fallback to plain text) ─────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    _console     = Console()
    _err_console = Console(stderr=True)
    _HAS_RICH    = True
except ImportError:
    _HAS_RICH = False

# ── Typer app ─────────────────────────────────────────────────────────────────
app = typer.Typer(
    name="burp2har",
    add_completion=False,
    rich_markup_mode=None,
    no_args_is_help=False,
)

# ── Output helpers ─────────────────────────────────────────────────────────────

def _out(msg: str = "", stderr: bool = False) -> None:
    if _HAS_RICH:
        (_err_console if stderr else _console).print(msg)
    else:
        print(msg, file=sys.stderr if stderr else sys.stdout)


def _banner() -> None:
    if _HAS_RICH:
        _console.print(
            f"\n  [bold cyan]{DISPLAY_NAME}[/bold cyan]  [dim]v{VERSION}[/dim]"
        )
        _console.print(f"  [dim]{'─' * 44}[/dim]")
    else:
        print(f"\n  {DISPLAY_NAME}  v{VERSION}")
        print(f"  {'─' * 44}")


def _step(label: str) -> None:
    if _HAS_RICH:
        _console.print(f"\n  [bold]►[/bold] {label}")
    else:
        print(f"\n  ► {label}")


def _ok(msg: str) -> None:
    if _HAS_RICH:
        _console.print(f"    [green]✓[/green]  {msg}")
    else:
        print(f"    ✓  {msg}")


def _warn(msg: str) -> None:
    if _HAS_RICH:
        _err_console.print(f"    [yellow]![/yellow]  [yellow]WARN:[/yellow] {msg}")
    else:
        print(f"    !  WARN: {msg}", file=sys.stderr)


def _error(msg: str) -> None:
    if _HAS_RICH:
        _err_console.print(f"\n  [bold red]✗[/bold red]  [red]ERROR:[/red] {msg}\n")
    else:
        print(f"\n  ✗  ERROR: {msg}\n", file=sys.stderr)


def _separator() -> None:
    if _HAS_RICH:
        _console.print(f"  [dim]{'─' * 44}[/dim]")
    else:
        print(f"  {'─' * 44}")


def _box(title: str, lines: list) -> None:
    if _HAS_RICH:
        _console.print(Panel("\n".join(lines), title=title, border_style="yellow", expand=False))
    else:
        width = max((len(t) for t in lines + [title]), default=40) + 4
        print(f"\n  ┌{'─' * width}┐")
        print(f"  │  {title:<{width - 2}}│")
        print(f"  ├{'─' * width}┤")
        for line in lines:
            print(f"  │  {line:<{width - 2}}│")
        print(f"  └{'─' * width}┘\n")


# ── XML reading helper ─────────────────────────────────────────────────────────

def _read_xml(filename: pathlib.Path) -> Optional[str]:
    """Read XML with UTF-8/latin-1 fallback. Returns text or None on failure."""
    try:
        return filename.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        _warn("UTF-8 read failed — retrying with latin-1")
        try:
            return filename.read_text(encoding="latin-1")
        except Exception as exc:
            _error(f"Cannot read file: {exc}")
            return None
    except Exception as exc:
        _error(f"Cannot read file: {exc}")
        return None


# ── First-run check ────────────────────────────────────────────────────────────

def _maybe_first_run_check() -> None:
    """
    On the very first execution: run a silent update check, show a notice if a
    newer version exists, then mark the installation as initialized.
    Never blocks or errors — all failures are silently swallowed.
    """
    if not is_first_run():
        return
    mark_initialized()

    result = check_for_updates()
    if result["error"] or not result["available"]:
        return  # Silent when up-to-date or offline

    _box(
        "Update Available — First Run Notice",
        [
            f"A newer version is available: v{result['latest_version']}",
            f"Your current version       : v{result['current_version']}",
            "Run  burp2har update  to upgrade.",
            result["releases_url"],
        ],
    )


# ── convert ───────────────────────────────────────────────────────────────────

@app.command()
def convert(
    filename: pathlib.Path = typer.Argument(
        ..., help="Burp Suite XML export file.", show_default=False
    ),
    output: Optional[pathlib.Path] = typer.Option(
        None, "--output", "-o",
        help="Destination .har file. Default: same directory as input, .har extension.",
        show_default=False,
    ),
    check_updates: bool = typer.Option(
        False, "--check-updates",
        help="Verbose update check before converting.",
    ),
    auto_check_updates: bool = typer.Option(
        False, "--auto-check-updates",
        help="Silent update check — warns only if a newer version exists.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Show full stack trace on errors.",
    ),
):
    """Convert a Burp Suite XML export to HAR format."""
    _banner()

    # ── Optional update check ────────────────────────────────────────────────
    _silent = auto_check_updates and not check_updates
    if check_updates or auto_check_updates:
        if not _silent:
            _step("Checking for updates")
        upd = check_for_updates()
        if upd["error"]:
            if not _silent:
                _warn(f"Update check failed (offline?): {upd['error']}")
        elif upd["available"]:
            _box(
                "Update Available",
                [
                    f"Latest  : v{upd['latest_version']}",
                    f"Current : v{upd['current_version']}",
                    upd["releases_url"],
                ],
            )
        elif not _silent:
            _ok(f"Up to date (v{upd['latest_version']})")

    # ── Check input file ─────────────────────────────────────────────────────
    _step("Checking input file")
    if not filename.exists():
        _error(f"File not found: {filename}")
        raise typer.Exit(1)
    if not filename.is_file():
        _error(f"Path is not a file: {filename}")
        raise typer.Exit(1)
    if filename.suffix.lower() != ".xml":
        _warn(f"'{filename.name}' does not have .xml extension — proceeding anyway")
    _ok(f"Found: {filename}  ({filename.stat().st_size:,} bytes)")

    # ── Read and validate XML ────────────────────────────────────────────────
    _step("Validating XML format")
    xml_text = _read_xml(filename)
    if xml_text is None:
        raise typer.Exit(1)

    validation = validate_xml(xml_text)

    if validation.status == CompatibilityStatus.MALFORMED:
        _error(
            f"XML file is malformed and cannot be parsed.\n"
            f"    Detail: {validation.message}"
        )
        raise typer.Exit(2)

    if validation.status == CompatibilityStatus.INCOMPATIBLE:
        _error(
            "The XML format exported from Burp Suite is not compatible with this version.\n"
            "    Burp Suite may have updated its XML export format.\n"
            f"    Check the latest release here: {RELEASES_PAGE_URL}\n"
            f"\n    Technical detail: {validation.message}"
        )
        raise typer.Exit(2)

    if validation.status == CompatibilityStatus.PARTIALLY_COMPATIBLE:
        _warn(f"Partially compatible: {validation.message}")
        for w in validation.warnings[:5]:
            _warn(w)
        if len(validation.warnings) > 5:
            _warn(f"... and {len(validation.warnings) - 5} more warnings omitted")
        _out("    → Proceeding — some items may be skipped")
    else:
        _ok(f"Compatible — {validation.item_count} items found")

    # ── Output path ──────────────────────────────────────────────────────────
    if output is None:
        output = filename.parent / (filename.stem + ".har")

    # ── Convert ──────────────────────────────────────────────────────────────
    _step("Converting XML → HAR")
    if _HAS_RICH:
        _console.print(f"    Input:  [dim]{filename}[/dim]")
        _console.print(f"    Output: [dim]{output}[/dim]")
    else:
        print(f"    Input:  {filename}")
        print(f"    Output: {output}")

    try:
        stats = burp2har_run(filename, output, xml_text=xml_text)
    except Exception as exc:
        _error(f"Conversion failed: {exc}")
        if verbose:
            traceback.print_exc()
        raise typer.Exit(3)

    # ── Summary ──────────────────────────────────────────────────────────────
    _separator()
    if _HAS_RICH:
        _console.print(f"\n  [bold green]Conversion complete.[/bold green]")
        _console.print(f"  Output: [cyan]{output}[/cyan]")
        if stats:
            _console.print(
                f"  Converted: [green]{stats['entries']}[/green]"
                f"  |  Skipped: [yellow]{stats['skipped']}[/yellow]"
            )
    else:
        print(f"\n  Conversion complete.")
        print(f"  Output: {output}")
        if stats:
            print(f"  Converted: {stats['entries']}  |  Skipped: {stats['skipped']}")
    print()


# ── validate ──────────────────────────────────────────────────────────────────

@app.command()
def validate(
    filename: pathlib.Path = typer.Argument(..., help="Burp Suite XML export file."),
):
    """Validate a Burp Suite XML export without converting it."""
    _banner()

    if not filename.exists():
        _error(f"File not found: {filename}")
        raise typer.Exit(1)

    xml_text = _read_xml(filename)
    if xml_text is None:
        raise typer.Exit(1)

    result = validate_xml(xml_text)

    _step("Validation result")

    _STATUS_LABEL = {
        CompatibilityStatus.COMPATIBLE:           ("✓ COMPATIBLE",           "green"),
        CompatibilityStatus.PARTIALLY_COMPATIBLE:  ("! PARTIALLY COMPATIBLE", "yellow"),
        CompatibilityStatus.INCOMPATIBLE:          ("✗ INCOMPATIBLE",         "red"),
        CompatibilityStatus.MALFORMED:             ("✗ MALFORMED",            "red"),
    }
    label, color = _STATUS_LABEL.get(result.status, ("? UNKNOWN", "dim"))

    if _HAS_RICH:
        _console.print(f"    [{color}]{label}[/{color}]  —  {result.message}")
    else:
        print(f"    {label}  —  {result.message}")

    for w in result.warnings[:10]:
        _warn(w)
    if len(result.warnings) > 10:
        _warn(f"... and {len(result.warnings) - 10} more warnings omitted")

    if result.status == CompatibilityStatus.INCOMPATIBLE:
        _warn(
            "Burp Suite may have updated its XML export format.\n"
            f"    Check for a newer version: {RELEASES_PAGE_URL}"
        )
        raise typer.Exit(2)

    if result.status == CompatibilityStatus.MALFORMED:
        raise typer.Exit(2)

    print()


# ── info ──────────────────────────────────────────────────────────────────────

@app.command()
def info(
    filename: pathlib.Path = typer.Argument(..., help="Burp Suite XML export file."),
):
    """Show metadata and statistics from a Burp Suite XML export."""
    _banner()

    if not filename.exists():
        _error(f"File not found: {filename}")
        raise typer.Exit(1)

    xml_text = _read_xml(filename)
    if xml_text is None:
        raise typer.Exit(1)

    validation = validate_xml(xml_text)
    if not validation.ok:
        _error(f"File is not a valid Burp Suite export: {validation.message}")
        raise typer.Exit(2)

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        _error(f"Cannot parse XML: {exc}")
        raise typer.Exit(2)

    items     = list(root.iter("item"))
    methods   = Counter()
    hosts     = Counter()
    protocols = Counter()
    mimetypes = Counter()
    statuses  = Counter()

    for item in items:
        method   = (item.findtext("method")   or "UNKNOWN").upper()
        url      =  item.findtext("url")       or ""
        protocol = (item.findtext("protocol") or "").lower()
        mimetype = (item.findtext("mimetype") or "").strip()
        status   =  item.findtext("status")   or ""

        methods[method] += 1
        if protocol:
            protocols[protocol] += 1
        if mimetype:
            mimetypes[mimetype] += 1
        if status:
            statuses[status] += 1
        if url:
            parsed = urlparse(url)
            if parsed.netloc:
                hosts[parsed.netloc] += 1

    file_size = filename.stat().st_size

    # ── File summary ──────────────────────────────────────────────────────────
    _step("File")
    _ok(f"Path          : {filename}")
    _ok(f"Size          : {file_size:,} bytes  ({file_size / 1024 / 1024:.1f} MB)")
    _ok(f"Total items   : {len(items)}")
    _ok(f"Compatibility : {validation.status.value}")

    # ── HTTP Methods ──────────────────────────────────────────────────────────
    _step("HTTP Methods")
    for method, count in sorted(methods.items(), key=lambda x: -x[1]):
        if _HAS_RICH:
            _console.print(f"    [cyan]{method:<10}[/cyan]  {count:>5}")
        else:
            print(f"    {method:<10}  {count:>5}")

    # ── Response Status Codes ─────────────────────────────────────────────────
    if statuses:
        _step("Response Status Codes")
        for code, count in sorted(statuses.items(), key=lambda x: -x[1]):
            if _HAS_RICH:
                _console.print(f"    [cyan]{code:<6}[/cyan]  {count:>5}")
            else:
                print(f"    {code:<6}  {count:>5}")

    # ── Protocols ─────────────────────────────────────────────────────────────
    if protocols:
        _step("Protocols")
        for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
            if _HAS_RICH:
                _console.print(f"    [cyan]{proto:<8}[/cyan]  {count:>5}")
            else:
                print(f"    {proto:<8}  {count:>5}")

    # ── Hosts ─────────────────────────────────────────────────────────────────
    _step(f"Hosts  ({len(hosts)} unique)")
    for host, count in sorted(hosts.items(), key=lambda x: -x[1])[:15]:
        label = f"{count} req{'s' if count != 1 else ''}"
        if _HAS_RICH:
            _console.print(f"    [dim]{host:<45}[/dim]  {label}")
        else:
            print(f"    {host:<45}  {label}")
    if len(hosts) > 15:
        remainder = len(hosts) - 15
        if _HAS_RICH:
            _console.print(f"    [dim]... and {remainder} more host{'s' if remainder > 1 else ''}[/dim]")
        else:
            print(f"    ... and {remainder} more host{'s' if remainder > 1 else ''}")

    # ── MIME types ────────────────────────────────────────────────────────────
    if mimetypes:
        _step("MIME Types  (Burp label)")
        for mime, count in sorted(mimetypes.items(), key=lambda x: -x[1])[:10]:
            if _HAS_RICH:
                _console.print(f"    [dim]{mime:<22}[/dim]  {count:>5}")
            else:
                print(f"    {mime:<22}  {count:>5}")

    print()


# ── update ────────────────────────────────────────────────────────────────────

@app.command(name="update")
def update_cmd() -> None:
    """Check for and install the latest version of burp2har."""
    _banner()
    _step("Checking for updates")

    result = check_for_updates()

    if result["error"]:
        _error(f"Update check failed: {result['error']}")
        _warn("You may be offline or the GitHub API is temporarily unavailable.")
        _warn(f"Check manually: {result['releases_url']}")
        raise typer.Exit(1)

    if not result["available"]:
        _ok(f"You are already on the latest version (v{result['current_version']}).")
        print()
        raise typer.Exit(0)

    _box(
        "Update Available",
        [
            f"Current version : v{result['current_version']}",
            f"Latest version  : v{result['latest_version']}",
            f"Release page    : {result['releases_url']}",
        ],
    )

    confirmed = typer.confirm("  Install the update now?", default=True)
    if not confirmed:
        if _HAS_RICH:
            _console.print(
                f"\n  Skipped. Download manually: [cyan]{result['releases_url']}[/cyan]\n"
            )
        else:
            print(f"\n  Skipped. Download manually: {result['releases_url']}\n")
        raise typer.Exit(0)

    _step("Installing update")
    if _HAS_RICH:
        _console.print(f"  [dim]Running: pip install --upgrade git+{PROJECT_URL}.git[/dim]")
    else:
        print(f"  Running: pip install --upgrade git+{PROJECT_URL}.git")

    install = perform_update()

    if install["success"]:
        _ok("Update installed successfully.")
        if _HAS_RICH:
            _console.print(
                "\n  [dim]Restart your shell or run "
                "[bold]burp2har --version[/bold] to confirm.[/dim]\n"
            )
        else:
            print("\n  Restart your shell or run 'burp2har --version' to confirm.\n")
    else:
        _error(f"Update failed: {install['error']}")
        if install.get("output"):
            print(install["output"])
        _warn(f"Try manually:  pip install git+{PROJECT_URL}.git")
        raise typer.Exit(1)


# ── help ──────────────────────────────────────────────────────────────────────

@app.command(name="help")
def help_cmd() -> None:
    """Show the full user guide with examples."""
    _print_help()


def _print_help() -> None:
    if _HAS_RICH:
        _console.print()
        _console.print(
            Panel(
                f"[bold cyan]{DISPLAY_NAME}[/bold cyan]  [dim]v{VERSION}[/dim]\n\n"
                "Converts Burp Suite HTTP history exports (XML) to HAR format.\n"
                f"[dim]{PROJECT_URL}[/dim]",
                expand=False, border_style="cyan", padding=(1, 2),
            )
        )

        # ── Commands ──────────────────────────────────────────────────────────
        _console.print("\n[bold]COMMANDS[/bold]")
        cmd_tbl = Table(show_header=False, box=None, padding=(0, 2), show_edge=False)
        cmd_tbl.add_column(style="cyan bold", no_wrap=True)
        cmd_tbl.add_column()
        for cmd, desc in [
            ("burp2har convert <file.xml>",  "Convert XML -> HAR"),
            ("burp2har validate <file.xml>", "Validate XML structure and compatibility"),
            ("burp2har info <file.xml>",     "Show file statistics and metadata"),
            ("burp2har update",              "Check for and install the latest version"),
            ("burp2har help",                "Show this guide"),
            ("burp2har <file.xml>",          "Shorthand for 'convert'"),
        ]:
            cmd_tbl.add_row(cmd, desc)
        _console.print(cmd_tbl)

        # ── Options ───────────────────────────────────────────────────────────
        _console.print("\n[bold]OPTIONS  (convert)[/bold]")
        opt_tbl = Table(
            show_header=True, header_style="bold", box=None,
            padding=(0, 2), show_edge=False,
        )
        opt_tbl.add_column("Option",      style="cyan", no_wrap=True)
        opt_tbl.add_column("Description")
        opt_tbl.add_column("Default", style="dim")
        for opt, desc, dflt in [
            ("--output, -o PATH",    "Destination .har file",                     "same dir, .har"),
            ("--check-updates",      "Verbose update check before converting",     "off"),
            ("--auto-check-updates", "Silent update check (warns if newer)",       "off"),
            ("--verbose, -v",        "Show full stack trace on errors",            "off"),
        ]:
            opt_tbl.add_row(opt, desc, dflt)
        _console.print(opt_tbl)

        # ── Examples ──────────────────────────────────────────────────────────
        _console.print("\n[bold]EXAMPLES[/bold]")
        for desc, cmd in [
            ("Basic conversion",                        "burp2har convert export.xml"),
            ("Custom output path",                      "burp2har convert export.xml -o /tmp/traffic.har"),
            ("Windows path",                            r"burp2har convert C:\captures\export.xml -o C:\out\traffic.har"),
            ("Shorthand (same as convert)",             "burp2har export.xml"),
            ("Validate without converting",             "burp2har validate export.xml"),
            ("Show file statistics",                    "burp2har info export.xml"),
            ("Check and install updates",               "burp2har update"),
            ("Convert with verbose update check",       "burp2har convert export.xml --check-updates"),
            ("Run without installing (repo root)",      "python -m burp2har.cli convert export.xml"),
        ]:
            _console.print(f"  [dim]{desc}:[/dim]")
            _console.print(f"    [bold cyan]{cmd}[/bold cyan]\n")

        # ── Exit codes ────────────────────────────────────────────────────────
        _console.print("[bold]EXIT CODES[/bold]")
        for code, desc in [
            ("0", "Success"),
            ("1", "Input file not found or unreadable"),
            ("2", "XML validation failure (malformed or incompatible)"),
            ("3", "Conversion error"),
        ]:
            _console.print(f"  [cyan]{code}[/cyan]  {desc}")

        # ── Notes ─────────────────────────────────────────────────────────────
        _console.print()
        _console.print("[bold]NOTES[/bold]")
        for note in [
            "Output .har is saved next to the input file unless --output is specified",
            "Input must be a Burp Suite XML export: Proxy → HTTP history → Save items",
            f"Incompatible XML format? Check: [cyan]{RELEASES_PAGE_URL}[/cyan]",
            f"Bug reports / feature requests: [cyan]{PROJECT_URL}/issues[/cyan]",
        ]:
            _console.print(f"  • {note}")
        _console.print()

    else:
        W = 62
        sep = "─" * W
        print(f"\n  {DISPLAY_NAME}  v{VERSION}")
        print(f"  {PROJECT_URL}")
        print(f"\n  {sep}\n")
        print("  COMMANDS")
        for cmd, desc in [
            ("convert <file.xml>",  "Convert XML -> HAR"),
            ("validate <file.xml>", "Validate XML structure"),
            ("info <file.xml>",     "Show file statistics"),
            ("update",              "Install latest version"),
            ("help",                "Show this guide"),
            ("<file.xml>",          "Shorthand for convert"),
        ]:
            print(f"    burp2har {cmd:<25}  {desc}")
        print(f"\n  {sep}\n")
        print("  OPTIONS  (convert)")
        for opt, desc in [
            ("--output, -o PATH",    "Destination .har file"),
            ("--check-updates",      "Verbose update check"),
            ("--auto-check-updates", "Silent update check"),
            ("--verbose, -v",        "Show stack trace on error"),
        ]:
            print(f"    {opt:<28}  {desc}")
        print(f"\n  {sep}\n")
        print("  EXAMPLES")
        for cmd in [
            "burp2har convert export.xml",
            "burp2har convert export.xml -o /tmp/out.har",
            "burp2har export.xml",
            "burp2har validate export.xml",
            "burp2har info export.xml",
            "burp2har update",
        ]:
            print(f"    {cmd}")
        print(f"\n  {sep}\n")


# ── --version callback ─────────────────────────────────────────────────────────

def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"burp2har v{VERSION}")
        raise typer.Exit()


# ── app-level callback (no subcommand → show help) ────────────────────────────

@app.callback(invoke_without_command=True)
def _app_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version",
        callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """BurpSuite HAR Converter — convert Burp Suite XML exports to HAR format."""
    if ctx.invoked_subcommand is None:
        _print_help()


# ── Entry point ────────────────────────────────────────────────────────────────

_SUBCOMMANDS = {"convert", "validate", "info", "update", "help"}


def run() -> None:
    """
    Main entry point registered as the 'burp2har' console script.

    Handles two concerns before delegating to Typer:
    1. First-run check (silent update check + notice).
    2. Shorthand: ``burp2har file.xml`` -> ``burp2har convert file.xml``.
    """
    # On Windows the default stdout encoding is often cp1252, which cannot
    # represent Unicode symbols used in help text.  Reconfigure to UTF-8 so
    # all Rich output (and plain-text fallback) works on any Windows terminal.
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, io.UnsupportedOperation):
            pass

    _maybe_first_run_check()

    # Shorthand detection: if argv[1] is not a known subcommand or flag,
    # treat it as a file argument and inject 'convert'.
    if len(sys.argv) >= 2:
        first = sys.argv[1]
        if not first.startswith("-") and first not in _SUBCOMMANDS:
            sys.argv.insert(1, "convert")

    app()


if __name__ == "__main__":
    run()
