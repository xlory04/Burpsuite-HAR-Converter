"""
Optional update checker for burp2har.

- Never raises exceptions to the caller — all network errors are captured and
  returned as {'error': '...'} so the CLI can degrade gracefully.
- Uses only the Python standard library (urllib) — no extra dependencies.
- Connection is never attempted unless the user explicitly passes --check-updates.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict

from .config import RELEASES_API_URL, RELEASES_PAGE_URL, VERSION

# Seconds to wait for the GitHub API before giving up
_TIMEOUT = 5


def check_for_updates(timeout: int = _TIMEOUT) -> Dict[str, Any]:
    """
    Query the GitHub releases API and compare the latest tag against VERSION.

    Return value keys
    -----------------
    available       bool   — True when a newer release exists
    latest_version  str    — tag name without leading 'v', or None on error
    current_version str    — local VERSION constant
    releases_url    str    — human-readable page to download the update
    error           str    — error description, or None on success
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
            return _result(False, None, error="Risposta API non contiene 'tag_name'.")

        if _is_newer(latest, VERSION):
            return _result(True, latest)

        return _result(False, latest)

    except urllib.error.URLError as exc:
        return _result(False, None, error=f"Connessione fallita: {exc.reason}")
    except Exception as exc:  # noqa: BLE001
        return _result(False, None, error=str(exc))


# ── helpers ───────────────────────────────────────────────────────────────────

def _result(
    available: bool,
    latest: str | None,
    error: str | None = None,
) -> Dict[str, Any]:
    return {
        "available":       available,
        "latest_version":  latest,
        "current_version": VERSION,
        "releases_url":    RELEASES_PAGE_URL,
        "error":           error,
    }


def _is_newer(candidate: str, current: str) -> bool:
    """Return True if *candidate* version is strictly greater than *current*."""
    try:
        def _parse(v: str):
            return tuple(int(x) for x in v.split("."))
        return _parse(candidate) > _parse(current)
    except ValueError:
        return False
