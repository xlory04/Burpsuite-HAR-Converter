"""
CLI entry point for burp2har.

Usage:
    burp2har <file.xml>
    burp2har help
    python -m burp2har.cli <file.xml>
"""

from __future__ import annotations

import sys
import traceback
from typing import Optional

import typer
import pathlib

from .config import PROJECT_NAME, PROJECT_URL, RELEASES_PAGE_URL, VERSION
from .updater import check_for_updates
from .validator import CompatibilityStatus, validate_xml
from .functions import burp2har_run

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

app = typer.Typer(
    add_completion=False,
    help=(
        f"{PROJECT_NAME} — Converte file XML esportati da Burp Suite "
        "nel formato HAR (HTTP Archive).\n\n"
        "Suggerimento: esegui  burp2har help  per una guida più dettagliata."
    ),
)


# ── Output helpers ─────────────────────────────────────────────────────────────

def _banner():
    if _HAS_RICH:
        _console.print(
            f"\n  [bold cyan]{PROJECT_NAME}[/bold cyan]  [dim]v{VERSION}[/dim]"
        )
        _console.print(f"  [dim]{'─' * 44}[/dim]")
    else:
        print(f"\n  {PROJECT_NAME}  v{VERSION}")
        print(f"  {'─' * 44}")


def _step(label: str):
    if _HAS_RICH:
        _console.print(f"\n  [bold]►[/bold] {label}")
    else:
        print(f"\n  ► {label}")


def _ok(msg: str):
    if _HAS_RICH:
        _console.print(f"    [green]✓[/green]  {msg}")
    else:
        print(f"    ✓  {msg}")


def _warn(msg: str):
    if _HAS_RICH:
        _err_console.print(f"    [yellow]![/yellow]  [yellow]WARN:[/yellow] {msg}")
    else:
        print(f"    !  WARN: {msg}", file=sys.stderr)


def _error(msg: str):
    if _HAS_RICH:
        _err_console.print(f"\n  [bold red]✗[/bold red]  [red]ERRORE:[/red] {msg}\n")
    else:
        print(f"\n  ✗  ERRORE: {msg}\n", file=sys.stderr)


def _separator():
    if _HAS_RICH:
        _console.print(f"  [dim]{'─' * 44}[/dim]")
    else:
        print(f"  {'─' * 44}")


def _info_box(title: str, lines: list[str]):
    """Print a bordered info box (update notice, summary, etc.)."""
    if _HAS_RICH:
        body = "\n".join(lines)
        _console.print(Panel(body, title=title, border_style="yellow", expand=False))
    else:
        width = max(len(t) for t in lines + [title]) + 4
        print(f"\n  ┌{'─' * width}┐")
        print(f"  │  {title:<{width - 2}}│")
        print(f"  ├{'─' * width}┤")
        for line in lines:
            print(f"  │  {line:<{width - 2}}│")
        print(f"  └{'─' * width}┘\n")


# ── Help command ───────────────────────────────────────────────────────────────

def _print_help() -> None:
    """
    Print a user-friendly help guide.

    Invoked when the user runs `burp2har help`.
    Distinct from `--help` (Typer's auto-generated flag):
      --help   → terse machine-friendly option list (Typer default)
      help     → full user-friendly guide with examples and notes
    """
    if _HAS_RICH:
        _console.print()
        _console.print(
            Panel(
                f"[bold cyan]{PROJECT_NAME}[/bold cyan]  [dim]v{VERSION}[/dim]\n\n"
                "Converte file XML esportati da Burp Suite nel formato [bold]HAR[/bold] "
                "(HTTP Archive).\n"
                f"[dim]{PROJECT_URL}[/dim]",
                expand=False,
                border_style="cyan",
                padding=(1, 2),
            )
        )

        # ── Uso base ──────────────────────────────────────────────────────────
        _console.print("\n[bold]USO BASE[/bold]")
        _console.print("  [cyan]burp2har[/cyan] [yellow]<file.xml>[/yellow]\n")

        # ── Opzioni ───────────────────────────────────────────────────────────
        tbl = Table(
            show_header=True,
            header_style="bold",
            box=None,
            padding=(0, 2),
            show_edge=False,
        )
        tbl.add_column("Opzione / Argomento",  style="cyan",  no_wrap=True)
        tbl.add_column("Tipo",                 style="dim",   no_wrap=True)
        tbl.add_column("Descrizione")
        tbl.add_column("Default",              style="dim")

        rows = [
            ("<file.xml>",           "PATH",  "File XML esportato da Burp Suite (richiesto)",                     "—"),
            ("--output  -o",         "PATH",  "Percorso del file .har di output",                                 "stessa dir, .har"),
            ("--check-updates",      "flag",  "Controlla se è disponibile una versione più recente",              "off"),
            ("--auto-check-updates", "flag",  "Silenzioso: avvisa solo se esiste un aggiornamento",               "off"),
            ("--verbose  -v",        "flag",  "Mostra stack trace completo in caso di errore",                    "off"),
            ("--help",               "flag",  "Mostra l'help sintetico di Typer ed esci",                         "—"),
            ("help",                 "cmd",   "Mostra questa guida dettagliata ed esci",                           "—"),
        ]
        for row in rows:
            tbl.add_row(*row)

        _console.print("[bold]OPZIONI[/bold]")
        _console.print(tbl)

        # ── Esempi ────────────────────────────────────────────────────────────
        _console.print("\n[bold]ESEMPI[/bold]")
        examples = [
            ("Conversione base (output nella stessa dir)", "burp2har burp_export.xml"),
            ("Output personalizzato",                      "burp2har session.xml -o /tmp/session.har"),
            (r"Output personalizzato (Windows)",           r"burp2har C:\captures\export.xml -o C:\out\traffic.har"),
            ("Controlla aggiornamenti",                    "burp2har export.xml --check-updates"),
            ("Aggiornamenti silenziosi",                   "burp2har export.xml --auto-check-updates"),
            ("Debug — mostra stack trace",                 "burp2har export.xml --verbose"),
            ("Senza installazione (da repo root)",         "python -m burp2har.cli export.xml"),
        ]
        for desc, cmd in examples:
            _console.print(f"  [dim]{desc}:[/dim]")
            _console.print(f"    [bold cyan]{cmd}[/bold cyan]\n")

        # ── Note importanti ───────────────────────────────────────────────────
        _console.print("[bold]NOTE IMPORTANTI[/bold]")
        notes = [
            "L'output .har viene salvato nella stessa dir del file di input (se ometti -o)",
            "Il file di input deve essere XML da Burp (Proxy → HTTP history → Save items)",
            "Se il formato XML non è compatibile con questa versione, controlla:",
            f"  [cyan]{RELEASES_PAGE_URL}[/cyan]",
            f"Per bug report e feature request: [cyan]{PROJECT_URL}/issues[/cyan]",
        ]
        for note in notes:
            _console.print(f"  • {note}")
        _console.print()

    else:
        # ── Plain-text fallback ───────────────────────────────────────────────
        W = 62
        sep = "─" * W
        print(f"\n  {PROJECT_NAME}  v{VERSION}")
        print(f"  Converte XML Burp Suite → HAR (HTTP Archive)")
        print(f"  {PROJECT_URL}")
        print(f"\n  {sep}")

        print("\n  USO BASE")
        print("    burp2har <file.xml>\n")

        print("  OPZIONI")
        opts = [
            ("<file.xml>",            "File XML di Burp Suite (richiesto)"),
            ("--output, -o PATH",     "Percorso del file .har di output"),
            ("--check-updates",       "Controlla aggiornamenti disponibili"),
            ("--auto-check-updates",  "Silenziosa: avvisa solo se c'è un update"),
            ("--verbose, -v",         "Stack trace completo in caso di errore"),
            ("--help",                "Help sintetico Typer ed esci"),
            ("help",                  "Questa guida dettagliata ed esci"),
        ]
        for opt, desc in opts:
            print(f"    {opt:<26}  {desc}")

        print("\n  ESEMPI")
        print("    burp2har burp_export.xml")
        print("    burp2har session.xml -o /tmp/session.har")
        print("    burp2har export.xml --check-updates")
        print("    burp2har export.xml --auto-check-updates")
        print("    python -m burp2har.cli export.xml")

        print("\n  NOTE")
        print("    - Output nella stessa dir del file di input (default)")
        print("    - Input: XML da Burp  Proxy → HTTP history → Save items")
        print(f"    - Incompatibilità XML? Controlla: {RELEASES_PAGE_URL}")
        print(f"    - Bug / feature: {PROJECT_URL}/issues")
        print(f"\n  {sep}\n")


# ── `burp2har help` intercept (before Typer runs) ──────────────────────────────

def _intercept_help_command() -> None:
    """
    If the user typed `burp2har help`, print the guide and exit.

    This runs *before* Typer parses argv, so the single-command pattern
    (`burp2har file.xml`) is preserved without restructuring the app.
    """
    if len(sys.argv) == 2 and sys.argv[1].lower() == "help":
        _print_help()
        raise SystemExit(0)


# ── Command ────────────────────────────────────────────────────────────────────

@app.command()
def main(
    filename: pathlib.Path = typer.Argument(
        ...,
        help="File XML esportato da Burp Suite (Save items → XML).",
        show_default=False,
    ),
    output: Optional[pathlib.Path] = typer.Option(
        None,
        "--output", "-o",
        help=(
            "Percorso del file HAR di output. "
            "Default: stessa cartella del file di input, stessa base name con estensione .har"
        ),
        show_default=False,
    ),
    check_updates: bool = typer.Option(
        False,
        "--check-updates",
        help="Controlla online se è disponibile una versione più recente.",
    ),
    auto_check_updates: bool = typer.Option(
        False,
        "--auto-check-updates",
        help=(
            "Controlla silenziosamente gli aggiornamenti: "
            "mostra un avviso solo se esiste una versione più recente, "
            "non stampa nulla se sei già aggiornato."
        ),
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Mostra stack trace completo in caso di errore.",
    ),
):
    """
    Converti un file XML esportato da Burp Suite in formato HAR.

    \b
    Esempi:
        burp2har burp_export.xml
        burp2har burp_export.xml --output /tmp/traffic.har
        burp2har burp_export.xml --check-updates
        burp2har burp_export.xml --auto-check-updates
        python -m burp2har.cli burp_export.xml -o output.har -v

    \b
    Suggerimento: esegui  burp2har help  per la guida dettagliata.
    """
    _banner()

    # ── 1. Controllo aggiornamenti ────────────────────────────────────────────
    _do_check = check_updates or auto_check_updates
    _silent   = auto_check_updates and not check_updates  # silent mode

    if _do_check:
        if not _silent:
            _step("Controllo aggiornamenti")

        result = check_for_updates()

        if result["error"]:
            if not _silent:
                _warn(
                    f"Impossibile verificare aggiornamenti "
                    f"(modalità offline?): {result['error']}"
                )
        elif result["available"]:
            _info_box(
                "Aggiornamento disponibile",
                [
                    f"Nuova versione : {result['latest_version']}",
                    f"Versione attuale: {result['current_version']}",
                    result["releases_url"],
                ],
            )
        elif not _silent:
            _ok(f"Sei aggiornato (ultima versione: {result['latest_version']})")

    # ── 2. Verifica file di input ─────────────────────────────────────────────
    _step("Verifica file di input")

    if not filename.exists():
        _error(f"File non trovato: {filename}")
        raise typer.Exit(1)

    if not filename.is_file():
        _error(f"Il percorso non punta a un file: {filename}")
        raise typer.Exit(1)

    if filename.suffix.lower() != ".xml":
        _warn(f"'{filename.name}' non ha estensione .xml — continuo comunque")

    file_size = filename.stat().st_size
    _ok(f"File trovato: {filename}  ({file_size:,} byte)")

    # ── 3. Lettura e validazione XML ──────────────────────────────────────────
    _step("Validazione formato XML")

    try:
        xml_text = filename.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        _warn("Encoding UTF-8 fallito, tentativo con latin-1")
        try:
            xml_text = filename.read_text(encoding="latin-1")
        except Exception as exc:
            _error(f"Impossibile leggere il file: {exc}")
            raise typer.Exit(1)
    except Exception as exc:
        _error(f"Impossibile leggere il file: {exc}")
        raise typer.Exit(1)

    validation = validate_xml(xml_text)

    if validation.status == CompatibilityStatus.MALFORMED:
        _error(
            "Il file XML è malformato e non può essere elaborato.\n"
            f"    Dettaglio tecnico: {validation.message}"
        )
        raise typer.Exit(2)

    if validation.status == CompatibilityStatus.INCOMPATIBLE:
        _error(
            "Il formato XML esportato da Burp Suite non è compatibile con "
            "questa versione del converter.\n"
            "    È possibile che Burp abbia aggiornato il formato di "
            "esportazione XML.\n"
            f"    Controlla l'ultima versione disponibile qui: {RELEASES_PAGE_URL}\n"
            f"\n    Dettaglio tecnico: {validation.message}"
        )
        raise typer.Exit(2)

    if validation.status == CompatibilityStatus.PARTIALLY_COMPATIBLE:
        _warn(f"Formato parzialmente compatibile: {validation.message}")
        for w in validation.warnings[:5]:
            _warn(w)
        if len(validation.warnings) > 5:
            _warn(f"... e altri {len(validation.warnings) - 5} avvisi omessi")
        print("    → Conversione in corso: potrebbero essere ignorati alcuni item")
    else:
        _ok(f"Formato compatibile — {validation.item_count} item trovati")

    # ── 4. Percorso di output ─────────────────────────────────────────────────
    if output is None:
        output = filename.parent / (filename.stem + ".har")

    # ── 5. Conversione ────────────────────────────────────────────────────────
    _step("Conversione XML → HAR")
    if _HAS_RICH:
        _console.print(f"    Input:  [dim]{filename}[/dim]")
        _console.print(f"    Output: [dim]{output}[/dim]")
    else:
        print(f"    Input:  {filename}")
        print(f"    Output: {output}")

    try:
        converted = burp2har_run(filename, output, xml_text=xml_text)
    except Exception as exc:
        _error(f"Errore durante la conversione: {exc}")
        if verbose:
            traceback.print_exc()
        raise typer.Exit(3)

    # ── 6. Riepilogo finale ───────────────────────────────────────────────────
    _separator()

    if _HAS_RICH:
        _console.print(f"\n  [bold green]Conversione completata.[/bold green]")
        _console.print(f"  Output HAR: [cyan]{output}[/cyan]")
        if converted is not None:
            _console.print(
                f"  Richieste elaborate: [green]{converted['entries']}[/green]"
                f"  |  Ignorate: [yellow]{converted['skipped']}[/yellow]"
            )
    else:
        print(f"\n  Conversione completata.")
        print(f"  Output HAR: {output}")
        if converted is not None:
            print(
                f"  Richieste elaborate: {converted['entries']}"
                f"  |  Ignorate: {converted['skipped']}"
            )
    print()


# ── Entry point ────────────────────────────────────────────────────────────────

def run():
    """
    Main entry point called by the `burp2har` console script.

    Intercepts `burp2har help` before handing off to Typer, so the
    single-command pattern (`burp2har file.xml`) is preserved intact.
    """
    _intercept_help_command()
    app()


if __name__ == "__main__":
    run()
