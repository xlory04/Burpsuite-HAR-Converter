"""
Update checker and installer for burp2har.

Design constraints:
- Never raises exceptions to the caller — all errors are returned as dicts.
- Uses only the Python standard library for the network check (no extra deps).
- `perform_update` uses sys.executable so it always targets the active Python env.
- Network access is never attempted unless the user explicitly requests it.
"""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .config import PROJECT_URL, RELEASES_API_URL, RELEASES_PAGE_URL, VERSION

_TIMEOUT = 5  # seconds

# Install / upgrade URL — always points at the canonical branch on GitHub
_INSTALL_URL = f"git+{PROJECT_URL}.git"


# ── Public API ────────────────────────────────────────────────────────────────

def check_for_updates(timeout: int = _TIMEOUT) -> Dict[str, Any]:
    """
    Query the GitHub releases API and compare the latest tag against VERSION.

    Return dict keys
    ----------------
    available        bool  — True when a newer release exists on GitHub
    latest_version   str   — tag without leading 'v', or None on error
    current_version  str   — local VERSION constant
    releases_url     str   — human-readable page to download the release
    error            str   — error description, or None on success
    """
    try:
        req = urllib.request.Request(
            RELEASES_API_URL,
            headers={"User-Agent": f"burp2har/{VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data: Dict[str, Any] = json.loads(resp.read().decode("utf-8"))

        latest_raw: str = data.get("tag_name", "")
        latest = latest_raw.lstrip("v").strip()

        if not latest:
            return _result(False, None, error="GitHub API response is missing 'tag_name'.")

        return _result(_is_newer(latest, VERSION), latest)

    except urllib.error.URLError as exc:
        return _result(False, None, error=f"Connection failed: {exc.reason}")
    except Exception as exc:  # noqa: BLE001
        return _result(False, None, error=str(exc))


def perform_update() -> Dict[str, Any]:
    """
    Install the latest version from GitHub using pip.

    Uses ``sys.executable -m pip`` so the correct Python environment is always
    targeted, even inside a virtualenv or when pip is not on the PATH.

    Return dict keys
    ----------------
    success  bool — True when pip exited with code 0
    output   str  — pip stdout (may be empty)
    error    str  — pip stderr or exception message, or None on success
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", _INSTALL_URL],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return {"success": True, "output": result.stdout, "error": None}
        return {"success": False, "output": result.stdout, "error": result.stderr}

    except subprocess.TimeoutExpired:
        return {"success": False, "output": "", "error": "Update timed out after 120 seconds."}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "output": "", "error": str(exc)}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _result(
    available: bool,
    latest: Optional[str],
    error: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "available":       available,
        "latest_version":  latest,
        "current_version": VERSION,
        "releases_url":    RELEASES_PAGE_URL,
        "error":           error,
    }


def _is_newer(candidate: str, current: str) -> bool:
    """Return True if *candidate* version tuple is strictly greater than *current*."""
    try:
        def _parse(v: str):
            return tuple(int(x) for x in v.split("."))
        return _parse(candidate) > _parse(current)
    except ValueError:
        return False
