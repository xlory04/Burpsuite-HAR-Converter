# burp2har

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.3.0-orange.svg)](https://github.com/xlory04/Burpsuite-HAR-Converter/releases)

**burp2har** is a command-line tool that converts HTTP traffic exported from Burp Suite (XML format) into the standard **HAR** (HTTP Archive) format.

---

## Table of Contents

- [What is this?](#what-is-this)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Exporting from Burp Suite](#exporting-from-burp-suite)
- [Usage](#usage)
- [Examples](#examples)
- [Update System](#update-system)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [Differences from Original Project](#differences-from-original-project)
- [Credits](#credits)
- [License](#license)

---

## What is this?

Burp Suite (Professional and Community) lets you export captured HTTP requests and responses as an XML file via **Proxy → HTTP history → Save items**.

Many analysis tools (browser DevTools importers, performance analyzers, security scanners, Postman, Insomnia, mitmproxy, etc.) work with the **HAR** format — not with Burp's proprietary XML.

`burp2har` bridges that gap: it reads the Burp XML export and produces a valid `.har` file that any HAR-compatible tool can open.

**Typical use cases:**

- Importing Burp traffic into browser DevTools for replay or inspection
- Feeding captured traffic into performance analysis tools
- Sharing traffic captures in a tool-agnostic format
- Integrating Burp captures into automated pipelines or CI security checks

---

## Features

| Feature | Description |
|---|---|
| **convert** | Convert Burp XML → HAR with a progress summary |
| **validate** | Pre-flight XML compatibility check without conversion |
| **info** | Inspect a Burp export: methods, hosts, status codes, MIME types |
| **update** | Check GitHub for a newer version and install it interactively |
| **help** | Detailed user guide with examples |
| **Shorthand** | `burp2har file.xml` works as a shortcut for `burp2har convert file.xml` |
| **First-run check** | Silently checks for updates on first execution |
| **Offline safe** | All network operations are optional and fail gracefully |
| **Encoding fallback** | UTF-8 with automatic latin-1 fallback for non-standard exports |
| **Format detection** | Distinguishes malformed XML, incompatible XML, and partial exports |
| **Rich output** | Colored, structured terminal output (falls back to plain text if Rich is unavailable) |

---

## Requirements

| Requirement | Minimum version |
|---|---|
| Python | 3.8 |
| Typer | 0.9.0 |
| Rich | 10.0.0 |
| Burp Suite | Community or Professional (any recent version) |

**Operating systems:** Windows 10/11, Linux (any distribution), macOS 12+

No internet connection is required for normal operation. An optional `burp2har update` command and `--check-updates` flag query the GitHub releases API only when explicitly requested.

---

## Installation

### Windows

**1. Install Python 3.8 or later**

Download from [python.org/downloads](https://www.python.org/downloads/).
During installation, check **"Add Python to PATH"**.

Verify:
```cmd
python --version
```

**2. (Recommended) Create a virtual environment**

```cmd
python -m venv venv
venv\Scripts\activate
```

**3. Install burp2har**

From source (recommended — always gets the latest code):
```cmd
pip install git+https://github.com/xlory04/Burpsuite-HAR-Converter.git
```

Or clone and install locally:
```cmd
git clone https://github.com/xlory04/Burpsuite-HAR-Converter.git
cd Burpsuite-HAR-Converter
pip install .
```

**4. Verify**

```cmd
burp2har --version
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

**3. Install burp2har**

```bash
pip install git+https://github.com/xlory04/Burpsuite-HAR-Converter.git
```

Or from source:
```bash
git clone https://github.com/xlory04/Burpsuite-HAR-Converter.git
cd Burpsuite-HAR-Converter
pip install .
```

**4. Verify**

```bash
burp2har --version
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

**3. Install burp2har**

```bash
pip install git+https://github.com/xlory04/Burpsuite-HAR-Converter.git
```

**4. Verify**

```bash
burp2har --version
```

---

## Exporting from Burp Suite

1. Open **Burp Suite** and navigate to **Proxy → HTTP history** (or **Target → Site map**).
2. Select the requests you want to export (use `Ctrl+A` to select all).
3. Right-click → **Save items**.
4. In the dialog, ensure the format is set to **XML** and save the file (e.g. `export.xml`).

> The exported XML contains base64-encoded request and response bodies. `burp2har` decodes these automatically.

---

## Usage

### convert

Convert a Burp Suite XML export to HAR format.

```bash
burp2har convert export.xml
burp2har convert export.xml --output /path/to/output.har
burp2har convert export.xml --verbose
burp2har convert export.xml --check-updates
```

Options:

| Option | Short | Description | Default |
|---|---|---|---|
| `--output PATH` | `-o` | Destination `.har` file | Same directory as input, `.har` extension |
| `--check-updates` | | Verbose update check before converting | off |
| `--auto-check-updates` | | Silent update check — warns only if newer | off |
| `--verbose` | `-v` | Show full stack trace on errors | off |

---

### validate

Validate a Burp Suite XML export without converting it.

```bash
burp2har validate export.xml
```

Outputs one of:
- `✓ COMPATIBLE` — file is ready to convert
- `! PARTIALLY COMPATIBLE` — some items may be skipped during conversion
- `✗ INCOMPATIBLE` — valid XML but not a Burp Suite export, or format has changed
- `✗ MALFORMED` — file cannot be parsed as XML

Exit codes: `0` = compatible/partial, `2` = incompatible/malformed.

---

### info

Show metadata and statistics from a Burp Suite XML export without converting.

```bash
burp2har info export.xml
```

Shows:
- File size and item count
- HTTP methods breakdown
- Response status codes
- Protocols (http / https)
- Unique hosts (top 15)
- MIME types

---

### update

Check for a newer version of `burp2har` on GitHub and install it interactively.

```bash
burp2har update
```

Behavior:
1. Queries the GitHub releases API
2. If a newer version exists, shows current and latest version
3. Asks for confirmation before installing
4. Runs `pip install --upgrade git+<repo>` in the active Python environment
5. If offline or the API is unavailable, reports the error and exits cleanly

---

### help

Show the full user guide.

```bash
burp2har help
burp2har --help   # terse Typer option list
```

---

### Shorthand

If the first argument looks like a file path (not a subcommand), `burp2har` treats it as `convert`:

```bash
burp2har export.xml
# equivalent to:
burp2har convert export.xml
```

---

### Run without installing

```bash
python -m burp2har.cli convert export.xml
python -m burp2har.cli validate export.xml
python -m burp2har.cli info export.xml
```

---

## Examples

### Basic conversion

```
$ burp2har convert export.xml

  BurpSuite HAR Converter  v0.3.0
  ────────────────────────────────────────────

  ► Checking input file
    ✓  Found: export.xml  (75,328,782 bytes)

  ► Validating XML format
    ✓  Compatible — 238 items found

  ► Converting XML → HAR
    Input:  export.xml
    Output: export.har
  ────────────────────────────────────────────

  Conversion complete.
  Output: export.har
  Converted: 238  |  Skipped: 0
```

### Validate

```
$ burp2har validate export.xml

  BurpSuite HAR Converter  v0.3.0
  ────────────────────────────────────────────

  ► Validation result
    ✓ COMPATIBLE  —  238 items found, all valid.
```

### Info

```
$ burp2har info export.xml

  BurpSuite HAR Converter  v0.3.0
  ────────────────────────────────────────────

  ► File
    ✓  Path          : export.xml
    ✓  Size          : 75,328,782 bytes  (71.8 MB)
    ✓  Total items   : 238
    ✓  Compatibility : compatible

  ► HTTP Methods
    GET             192
    POST             41
    HEAD              3
    OPTIONS           2

  ► Response Status Codes
    200             151
    206              37
    302              10
    204               4
    400              36

  ► Protocols
    https           238

  ► Hosts  (12 unique)
    example.com                                    45 reqs
    api.example.com                                38 reqs
    ...
```

### Update

```
$ burp2har update

  BurpSuite HAR Converter  v0.3.0
  ────────────────────────────────────────────

  ► Checking for updates
  ╭─ Update Available ──────────────────────────────────╮
  │ Current version : v0.3.0                            │
  │ Latest version  : v0.4.0                            │
  │ Release page    : https://github.com/...            │
  ╰─────────────────────────────────────────────────────╯
  Install the update now? [Y/n]: y

  ► Installing update
  Running: pip install --upgrade git+https://github.com/...
    ✓  Update installed successfully.

  Restart your shell or run 'burp2har --version' to confirm.
```

### Incompatible XML

```
$ burp2har convert old_export.xml

  ✗  ERROR: The XML format exported from Burp Suite is not compatible with this version.
     Burp Suite may have updated its XML export format.
     Check the latest release here: https://github.com/xlory04/Burpsuite-HAR-Converter/releases
```

---

## Update System

### First-run check

On the **first execution** of `burp2har`, the tool silently checks GitHub for a newer version. If one is found, a notice is printed before the command output. If the check fails (offline, API unavailable), it is silently skipped and the command proceeds normally.

The first-run state is stored in `~/.burp2har/initialized` — a plain empty marker file with no sensitive data.

### Manual update

Run `burp2har update` at any time. The command:
1. Checks the GitHub releases API (requires internet access)
2. Compares against the installed version
3. Prompts for confirmation before making any changes
4. Runs `pip install --upgrade git+<repo>` if confirmed

### Fallback scripts

If the CLI update command is unavailable (e.g. broken install), use the scripts in `scripts/`:

**Windows:**
```powershell
powershell -ExecutionPolicy Bypass -File scripts\update_windows.ps1
```

**Linux / macOS:**
```bash
bash scripts/update_unix.sh
```

### Offline behavior

All update-related operations fail gracefully without breaking the tool:
- The first-run check is silently skipped when offline
- `--check-updates` prints a warning and continues with conversion
- `--auto-check-updates` is completely silent on failure
- `burp2har update` prints an error and exits with code 1

Conversion, validation, and `info` always work without internet access.

---

## Troubleshooting

**`burp2har: command not found`**

The package is not on your PATH. Either:
- Activate your virtual environment: `source venv/bin/activate` (Linux/macOS) or `venv\Scripts\activate` (Windows)
- Or run as a module: `python -m burp2har.cli <subcommand> <file.xml>`

**`UnicodeDecodeError` when reading the XML**

`burp2har` automatically tries latin-1 if UTF-8 fails. If both fail, convert the file first:
```bash
iconv -f <source-encoding> -t utf-8 export.xml -o export_utf8.xml
```

**Items are missing from the HAR output**

Run `burp2har validate export.xml` first to check compatibility. Then run `burp2har convert export.xml --verbose` to see per-item warnings. Common causes:
- The request body was not base64-encoded correctly by Burp
- The request line was malformed (unusual HTTP method or non-standard version string)

**The XML format is reported as incompatible**

Burp Suite occasionally updates its XML export format. Run `burp2har update` to install the latest version of the converter.

**`burp2har update` fails**

If pip cannot install from the git URL, use the fallback scripts or install manually:
```bash
pip install git+https://github.com/xlory04/Burpsuite-HAR-Converter.git
```

**Windows: `ExecutionPolicy` error when running the PowerShell script**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**`--check-updates` always reports a connection error**

The tool requires outbound HTTPS to `api.github.com`. If you are on a restricted network, the check fails gracefully and conversion proceeds normally.

---

## Project Structure

```
Burpsuite-HAR-Converter/
├── burp2har/
│   ├── __init__.py       — exposes __version__
│   ├── config.py         — VERSION, URLs, local config paths
│   ├── exceptions.py     — custom exception types
│   ├── first_run.py      — first-run detection and marker
│   ├── validator.py      — XML structure pre-flight check
│   ├── harlog.py         — XML parsing and HAR construction
│   ├── functions.py      — public programmatic API
│   ├── updater.py        — update checker and pip installer
│   └── cli.py            — Typer CLI (convert, validate, info, update, help)
├── scripts/
│   ├── update_windows.ps1
│   └── update_unix.sh
├── tests/
├── pyproject.toml
├── setup.py
├── README.md
└── LICENSE
```

---

## Differences from Original Project

This project started from [JoryPein/BurpSuite-HAR-Exporter](https://github.com/JoryPein/BurpSuite-HAR-Exporter) and has been substantially extended and rewritten by Lorenzo Surico.

| Area | Original | This version |
|---|---|---|
| **Code structure** | Single file (`harlog.py`) | Modular: `config`, `exceptions`, `first_run`, `validator`, `harlog`, `updater`, `functions`, `cli` |
| **CLI** | Single `main` command | Subcommands: `convert`, `validate`, `info`, `update`, `help` |
| **Shorthand** | `bpi2har file.xml` | `burp2har file.xml` (auto-injected as `convert`) |
| **XML validation** | None | Pre-flight check with four distinct status levels |
| **Incompatibility message** | Raw Python exception | Clear message with link to latest release |
| **First-run check** | None | Silent update check on first execution |
| **Update command** | None | `burp2har update` — GitHub API check + interactive pip install |
| **Update scripts** | None | `scripts/update_windows.ps1`, `scripts/update_unix.sh` |
| **`info` command** | None | HTTP methods, hosts, status codes, MIME types |
| **Timezone handling** | Hardcoded `CST` — crashes on CEST/EDT/BST | Strips timezone token before parsing |
| **Header truncation** | `split(b': ')` without maxsplit — truncates CSP headers | `split(b': ', 1)` — preserves full header values |
| **Empty responses** | `isinstance` check bypassed by empty string | Falsy check handles both `None` and `''` |
| **postData** | Never generated | Built for all requests with non-empty bodies |
| **Binary/media handling** | Undefined for video/audio | Skips body embedding for video/audio, records size only |
| **Version management** | Hardcoded in `harlog.py` | Single `VERSION` constant in `config.py` |
| **HAR creator name** | `bpi2har` | `burp2har` |
| **Exit codes** | Inconsistent | `0` success, `1` file error, `2` XML error, `3` conversion error |
| **Command name** | `bpi2har` | `burp2har` |

---

## Credits

This project is based on the original work by **JoryPein**.

| | |
|---|---|
| **Original project** | [JoryPein/BurpSuite-HAR-Exporter](https://github.com/JoryPein/BurpSuite-HAR-Exporter) |
| **Original author** | [JoryPein](https://github.com/JoryPein) |
| **This fork** | [xlory04/Burpsuite-HAR-Converter](https://github.com/xlory04/Burpsuite-HAR-Converter) |
| **Maintainer** | Lorenzo Surico |

The original codebase provided the foundation for XML parsing, base64 decoding, and HAR structure construction. All additions — modular architecture, XML validator, subcommand CLI, update system, first-run check, `info` command, and documentation — were written independently on top of that base.

The original project is distributed under the MIT License. This fork retains the same license.

---

## License

MIT License — Copyright (c) 2026 Lorenzo Surico.

Based on original work by [JoryPein](https://github.com/JoryPein), used and modified under the MIT License.

See [LICENSE](LICENSE) for the full text.
