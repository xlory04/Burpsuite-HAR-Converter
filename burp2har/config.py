"""
Centralized configuration for burp2har.
All version strings, URLs, project metadata, and local paths live here.
"""
from __future__ import annotations

import pathlib

VERSION = "0.3.0"

# Human-readable name used in banners and panels
DISPLAY_NAME = "BurpSuite HAR Converter"

# Package / command name
PROJECT_NAME = "burp2har"

MAINTAINER          = "Lorenzo Surico"
ORIGINAL_AUTHOR     = "JoryPein"

PROJECT_URL          = "https://github.com/xlory04/Burpsuite-HAR-Converter"
RELEASES_PAGE_URL    = "https://github.com/xlory04/Burpsuite-HAR-Converter/releases"
RELEASES_API_URL     = "https://api.github.com/repos/xlory04/Burpsuite-HAR-Converter/releases/latest"
ORIGINAL_PROJECT_URL = "https://github.com/JoryPein/BurpSuite-HAR-Exporter"

# Local config directory — stores first-run marker and future settings.
# Located in the user's home directory, never inside the project tree.
CONFIG_DIR     = pathlib.Path.home() / ".burp2har"
FIRST_RUN_FILE = CONFIG_DIR / "initialized"
