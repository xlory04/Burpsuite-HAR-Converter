"""
First-run detection for burp2har.

On the very first execution a marker file is created under ~/.burp2har/.
Subsequent runs detect the file and skip the first-run logic entirely.

The marker file is intentionally small and contains no sensitive data.
All filesystem errors are silently swallowed so a permission issue never
breaks normal operation.
"""
from __future__ import annotations

from .config import CONFIG_DIR, FIRST_RUN_FILE


def is_first_run() -> bool:
    """Return True if burp2har has never been executed on this machine."""
    return not FIRST_RUN_FILE.exists()


def mark_initialized() -> None:
    """
    Create the marker file that prevents future first-run checks.
    Safe to call multiple times (idempotent).
    Fails silently if the config directory cannot be created.
    """
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        FIRST_RUN_FILE.touch(exist_ok=True)
    except OSError:
        # Non-critical — silently skip if the filesystem is read-only
        # or the home directory is unavailable.
        pass
