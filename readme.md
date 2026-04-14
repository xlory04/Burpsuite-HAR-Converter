# BurpSuite-HAR-Exporter

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.2.0-orange.svg)](https://github.com/JoryPein/BurpSuite-HAR-Exporter/releases)

**BurpSuite-HAR-Exporter** (`bpi2har`) is a command-line tool that converts HTTP traffic exported from Burp Suite (XML format) into the standard **HAR** (HTTP Archive) format.

## Table of Contents

- [What is this?](#what-is-this)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Windows](#windows)
  - [Linux](#linux)
  - [macOS](#macos)
- [Exporting from Burp Suite](#exporting-from-burp-suite)
- [Usage](#usage)
- [Options](#options)
- [Examples](#examples)
- [Output](#output)
- [XML Compatibility](#xml-compatibility)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [Differences from Original Project](#differences-from-original-project)
- [Credits](#credits)
- [Contributing](#contributing)
- [License](#license)

---

## What is this?

Burp Suite (Professional and Community) lets you export captured HTTP requests and responses as an XML file via **Proxy → HTTP history → Save items**.

Many analysis tools (browser DevTools importers, performance analyzers, security scanners, Postman, Insomnia, mitmproxy, etc.) work with the **HAR** format — not with Burp's proprietary XML.

`bpi2har` bridges that gap: it reads the Burp XML export and produces a valid `.har` file that any HAR-compatible tool can open.

**Typical use cases:**

- Importing Burp traffic into browser DevTools for replay or inspection
- Feeding captured traffic into performance analysis tools
- Sharing traffic captures in a tool-agnostic format
- Integrating Burp captures into automated pipelines or CI security checks

---

## Requirements

| Requirement | Minimum version |
|---|---|
| Python | 3.8 |
| Typer | 0.9.0 |
| Rich | 10.0.0 |
| Burp Suite | Community or Professional (any recent version) |

**Operating systems:** Windows 10/11, Linux (any distribution), macOS 12+

No internet connection is required for normal operation. An optional `--check-updates` flag queries the GitHub releases API only when explicitly requested.

---

## Installation

### Windows

**1. Install Python 3.8 or later**

Download from [python.org/downloads](https://www.python.org/downloads/).
During installation, check **"Add Python to PATH"**.

Verify the installation:

```cmd
python --version
```

**2. (Recommended) Create a virtual environment**

```cmd
python -m venv venv
venv\Scripts\activate
```

**3. Install bpi2har**

```cmd
pip install bpi2har
```

Or install directly from source:

```cmd
git clone https://github.com/xlory04/BurpSuite-HAR-Exporter.git
cd BurpSuite-HAR-Exporter
pip install .
```

**4. Verify**

```cmd
bpi2har --help
```

---

### Linux

**1. Install Python 3.8+**

Debian / Ubuntu:

```bash
sudo apt update && sudo apt install python3 python3-pip python3-venv
```

Fedora / RHEL / CentOS:

```bash
sudo dnf install python3 python3-pip
```

**2. Create a virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install bpi2har**

```bash
pip install bpi2har
```

Or from source:

```bash
git clone https://github.com/xlory04/BurpSuite-HAR-Exporter.git
cd BurpSuite-HAR-Exporter
pip install .
```

**4. Verify**

```bash
bpi2har --help
```

---

### macOS

**1. Install Python 3.8+ via Homebrew**

```bash
brew install python
```

Or download from [python.org/downloads](https://www.python.org/downloads/macos/).

**2. Create a virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install bpi2har**

```bash
pip install bpi2har
```

Or from source:

```bash
git clone https://github.com/xlory04/BurpSuite-HAR-Exporter.git
cd BurpSuite-HAR-Exporter
pip install .
```

**4. Verify**

```bash
bpi2har --help
```

---

## Exporting from Burp Suite

1. Open **Burp Suite** and navigate to **Proxy → HTTP history** (or **Target → Site map**).
2. Select the requests you want to export (use `Ctrl+A` to select all).
3. Right-click → **Save items**.
4. In the dialog, ensure the format is set to **XML** and save the file (e.g. `burp_export.xml`).

> **Note:** The exported XML contains base64-encoded request and response bodies. `bpi2har` decodes these automatically.

---

## Usage

```bash
# Basic usage — output file is placed next to the input file
bpi2har burp_export.xml

# Specify a custom output path
bpi2har burp_export.xml --output /path/to/output.har

# Run as a Python module (no installation required)
python -m bpi2har.cli burp_export.xml

# Check for updates before converting
bpi2har burp_export.xml --check-updates

# Silent update check — only prints if a new version exists
bpi2har burp_export.xml --auto-check-updates

# Verbose mode — shows full stack trace on errors
bpi2har burp_export.xml --verbose
```

### Getting help

There are two help commands with different purposes:

```bash
# Typer's auto-generated flag — terse option list
bpi2har --help

# Full user-friendly guide with examples and notes
bpi2har help
```

`bpi2har help` prints:
- What the tool does and its input/output
- All available options with descriptions
- Practical examples (Linux, macOS, Windows)
- Important notes and links

---

## Options

| Flag / Argument | Short | Description | Default |
|---|---|---|---|
| `<filename>` | | Path to the Burp Suite XML export file | *(required)* |
| `--output PATH` | `-o` | Destination `.har` file path | Same directory as input, `.har` extension |
| `--check-updates` | | Query GitHub releases API for a newer version | `False` |
| `--auto-check-updates` | | Silent update check — only warns if a newer version exists | `False` |
| `--verbose` | `-v` | Print full stack trace on conversion errors | `False` |
| `--help` | | Show Typer's terse help and exit | |
| `help` | | Show the full user-friendly guide and exit | |

### `--check-updates` vs `--auto-check-updates`

| Flag | Prints when up-to-date | Prints when update available | Prints on network error |
|---|---|---|---|
| `--check-updates` | ✓ (confirms version) | ✓ (shows new version) | ✓ (shows warning) |
| `--auto-check-updates` | silent | ✓ (shows new version) | silent |

`--auto-check-updates` is designed for use in shell aliases or scripts where you want to be notified of updates passively without cluttering the output on every run.

---

## Examples

**Convert a single export:**

```bash
bpi2har burp_export.xml
# Output: burp_export.har (same directory)
```

**Specify output path:**

```bash
bpi2har /home/user/captures/session.xml --output /tmp/session.har
```

**Windows:**

```cmd
bpi2har C:\captures\burp_export.xml -o C:\captures\traffic.har
```

**Check for updates:**

```bash
bpi2har burp_export.xml --check-updates
```

**Silent update check (useful in aliases):**

```bash
bpi2har burp_export.xml --auto-check-updates
```

**Show the user-friendly guide:**

```bash
bpi2har help
```

**Run without installing (from the repo root):**

```bash
python -m bpi2har.cli burp_export.xml
```

**Expected terminal output (conversion):**

```
  BurpSuite-HAR-Exporter  v0.2.0
  ────────────────────────────────────────────

  ► Verifica file di input
    ✓  File trovato: burp_export.xml  (142,318 byte)

  ► Validazione formato XML
    ✓  Formato compatibile — 237 item trovati

  ► Conversione XML → HAR
    Input:  burp_export.xml
    Output: burp_export.har
  ────────────────────────────────────────────

  Conversione completata.
  Output HAR: burp_export.har
  Richieste elaborate: 231  |  Ignorate: 6
```

**Expected output of `bpi2har help`:**

```
╭─────────────────────────────────────────────────────╮
│  BurpSuite-HAR-Exporter  v0.2.0                     │
│                                                     │
│  Converte file XML esportati da Burp Suite nel      │
│  formato HAR (HTTP Archive).                        │
╰─────────────────────────────────────────────────────╯

USO BASE
  bpi2har <file.xml>

OPZIONI
  Opzione / Argomento     Tipo  Descrizione                            Default
  ─────────────────────────────────────────────────────────────────────────────
  <file.xml>              PATH  File XML di Burp Suite (richiesto)     —
  --output  -o            PATH  Percorso del file .har di output       stessa dir, .har
  --check-updates         flag  Controlla aggiornamenti disponibili    off
  --auto-check-updates    flag  Silenzioso: avvisa solo se c'è update  off
  --verbose  -v           flag  Stack trace completo in caso di errore off
  --help                  flag  Help sintetico Typer ed esci           —
  help                    cmd   Questa guida dettagliata ed esci       —

ESEMPI
  Conversione base:
    bpi2har burp_export.xml

  Output personalizzato:
    bpi2har session.xml -o /tmp/session.har
  ...

NOTE IMPORTANTI
  • L'output .har viene salvato nella stessa dir del file di input (se ometti -o)
  • Il file di input deve essere XML da Burp (Proxy → HTTP history → Save items)
  • Se il formato XML non è compatibile, controlla:
    https://github.com/xlory04/BurpSuite-HAR-Exporter/releases
```

---

## Output

The tool produces a single `.har` file containing:

- All captured HTTP requests (method, URL, headers, body, query string, cookies)
- All captured HTTP responses (status, headers, content — plain text or base64 for binary)
- Server IP addresses (when present in the Burp export)
- Timestamps derived from Burp's export metadata

The HAR file follows the [HAR 1.2 specification](http://www.softwareishard.com/blog/har-12-spec/) and can be imported by:

- Chrome / Firefox DevTools (`Network → Import HAR`)
- [HAR Analyzer](https://toolbox.googleapps.com/apps/har_analyzer/)
- Postman, Insomnia
- mitmproxy, Charles Proxy
- Any other HAR-compatible tool

---

## XML Compatibility

`bpi2har` validates the XML structure before conversion and reports three distinct failure modes:

### Malformed XML

The file cannot be parsed as XML at all (truncated file, encoding issue, etc.).

```
  ✗  ERRORE: Il file XML è malformato e non può essere elaborato.
     Dettaglio tecnico: XML malformato — syntax error: line 1, col 0
```

**Fix:** Re-export the file from Burp Suite. If the file is large, ensure disk space was sufficient during export.

### Incompatible XML

The XML is valid but does not contain the expected Burp structure (e.g. wrong file type, or Burp changed its export format in a future version).

```
  ✗  ERRORE: Il formato XML esportato da Burp Suite non è compatibile con questa versione del converter.
     E' possibile che Burp abbia aggiornato il formato di esportazione XML.
     Controlla l'ultima versione disponibile qui: https://github.com/JoryPein/BurpSuite-HAR-Exporter/releases
```

**Fix:** Check if a newer version of `bpi2har` is available (`--check-updates`). If you are on the latest version and the issue persists, please [open an issue](https://github.com/JoryPein/BurpSuite-HAR-Exporter/issues) with a sanitised sample of the XML.

### Partially compatible XML

The XML has the expected structure but some items are missing required fields. Conversion proceeds; incomplete items are skipped.

```
    !  WARN: Formato parzialmente compatibile: 180/200 item completamente validi, 20 parziali, 0 ignorati.
```

---

## Troubleshooting

**`bpi2har: command not found`**

The package is not on your PATH. Either:
- Activate your virtual environment: `source venv/bin/activate` (Linux/macOS) or `venv\Scripts\activate` (Windows)
- Or run as a module: `python -m bpi2har.cli <file.xml>`

**`UnicodeDecodeError` when reading the XML**

The XML file may use a non-UTF-8 encoding. `bpi2har` attempts a latin-1 fallback automatically. If it still fails, convert the file first:

```bash
iconv -f <source-encoding> -t utf-8 burp_export.xml -o burp_export_utf8.xml
```

**Items are missing from the HAR output**

Some items may have been skipped. Run with `--verbose` to see per-item warnings in the terminal. Common causes:
- The request or response body was not base64-encoded correctly by Burp
- The request line was malformed (unusual HTTP method, non-standard version string)

**The HAR file is not valid JSON**

This should not happen. If it does, please [open an issue](https://github.com/JoryPein/BurpSuite-HAR-Exporter/issues) with the XML that caused it.

**`--check-updates` always reports an error**

The tool requires outbound HTTPS to `api.github.com`. If you are on a restricted network, this check will fail gracefully and conversion will proceed normally.

---

## Project Structure

```
BurpSuite-HAR-Exporter/
├── bpi2har/
│   ├── __init__.py      # Exposes __version__
│   ├── config.py        # Centralized version, project URL, API endpoints
│   ├── validator.py     # XML structure validation (pre-flight check)
│   ├── harlog.py        # XML parsing and HAR structure construction
│   ├── functions.py     # Public API entry point
│   ├── updater.py       # Optional update checker (stdlib only, no extra deps)
│   └── cli.py           # Typer CLI — argument parsing and user output
├── pyproject.toml
├── setup.py
└── README.md
```

---

## Differences from Original Project

This project started from [JoryPein/BurpSuite-HAR-Exporter](https://github.com/JoryPein/BurpSuite-HAR-Exporter) and has been significantly extended. The goal was not to create a cosmetic fork, but to make the tool more robust, maintainable and usable in real-world workflows.

### What changed

| Area | Original | This version |
|---|---|---|
| **Code structure** | Single file (`harlog.py`) containing all logic | Separated into `config`, `validator`, `harlog`, `updater`, `functions`, `cli` |
| **XML validation** | None — parse errors surfaced as raw exceptions | Pre-flight structural check before conversion |
| **Error categories** | Generic exception | Malformed / Incompatible / Partially compatible — each with a clear user message |
| **Incompatibility message** | None | Explicit message with link to latest release when Burp's XML format is unrecognised |
| **CLI output** | Minimal | Step-by-step progress, item count, skipped count, output path |
| **CLI options** | `filename` only | Added `--output`, `--check-updates`, `--verbose` |
| **Version management** | Hardcoded string in `harlog.py` | Single `VERSION` constant in `config.py`, used everywhere |
| **Update checker** | None | Optional `--check-updates` flag; network-free by default; graceful offline fallback |
| **Encoding handling** | UTF-8 only | UTF-8 with automatic latin-1 fallback in CLI |
| **Conversion stats** | Not returned | `generate_har` returns `{'entries': N, 'skipped': N}` |
| **Disk reads** | XML read twice (validation + conversion) | Single read shared between pre-flight check and converter |
| **`__version__`** | Not exposed | Available via `import bpi2har; bpi2har.__version__` |
| **Documentation** | Minimal README | Full README with platform-specific install, options table, troubleshooting, compatibility guide |

### Design intent

The original project is a working, self-contained converter. This version adds layers of defensiveness around it — so that when Burp Suite changes its XML format (which it does, occasionally), the user gets a clear actionable message instead of a raw Python traceback, and maintainers have a clean separation of concerns to update only the affected module.

This is an evolution, not a rewrite. The core HTTP parsing and HAR construction logic in `harlog.py` is derived from the original work.

---

## Credits

This project is based on the original work by **JoryPein**.

| | |
|---|---|
| **Original project** | [JoryPein/BurpSuite-HAR-Exporter](https://github.com/JoryPein/BurpSuite-HAR-Exporter) |
| **Original author** | [JoryPein](https://github.com/JoryPein) |
| **This fork** | [xlory04/BurpSuite-HAR-Exporter](https://github.com/xlory04/BurpSuite-HAR-Exporter) |
| **Maintainer** | Lorenzo Surico |

The original codebase provided the foundation for XML parsing, base64 decoding, and HAR structure construction. All additions — modular architecture, XML validator, CLI improvements, update checker, and documentation — were written independently on top of that base.

The original project is distributed under the MIT License. This fork retains the same license. Full attribution is preserved in the [LICENSE](LICENSE) file.

---

## Contributing

Bug reports, feature requests and pull requests are welcome.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Commit your changes: `git commit -m "Add my change"`
4. Push to the branch: `git push origin feature/my-change`
5. Open a pull request

If Burp Suite has updated its XML export format and the tool no longer works, please open an issue and attach a sanitised sample of the new XML so the parser can be updated.

---

## License

MIT License — Copyright (c) 2026 Lorenzo Surico.

Based on original work by [JoryPein](https://github.com/JoryPein), used and modified under the MIT License.

See [LICENSE](LICENSE) for the full text.
