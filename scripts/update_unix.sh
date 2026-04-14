#!/usr/bin/env bash
# burp2har — Unix Update Script  (Linux / macOS)
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   bash scripts/update_unix.sh
#   chmod +x scripts/update_unix.sh && ./scripts/update_unix.sh
#
# What it does:
#   Installs (or upgrades) burp2har from the GitHub repository using pip.
#   Requires Python 3.8+ and internet access.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

REPO_URL="https://github.com/xlory04/Burpsuite-HAR-Converter.git"
INSTALL_SPEC="git+${REPO_URL}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

echo ""
echo -e "  ${CYAN}${BOLD}burp2har — Update Script (Unix)${RESET}"
echo    "  ────────────────────────────────────────────────────"
echo ""

# ── Find Python ───────────────────────────────────────────────────────────────
PY=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PY="$cmd"
        break
    fi
done

if [[ -z "$PY" ]]; then
    echo -e "  ${RED}ERROR: Python 3 is not installed or not in PATH.${RESET}"
    echo    ""
    echo    "  Install Python:"
    echo    "    Debian/Ubuntu : sudo apt install python3 python3-pip"
    echo    "    Fedora/RHEL   : sudo dnf install python3 python3-pip"
    echo    "    macOS         : brew install python"
    echo    ""
    exit 1
fi

PY_VERSION=$("$PY" --version 2>&1)
echo -e "  ${GREEN}Python found: ${PY_VERSION}${RESET}"

# ── Confirm ───────────────────────────────────────────────────────────────────
echo ""
read -r -p "  Install the latest burp2har from GitHub? [Y/n] " CONFIRM
case "$CONFIRM" in
    [nN]*) echo -e "\n  ${YELLOW}Aborted.${RESET}\n"; exit 0 ;;
esac

# ── Install ───────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${YELLOW}Running: pip install --upgrade ${INSTALL_SPEC}${RESET}"
echo ""

"$PY" -m pip install --upgrade "${INSTALL_SPEC}"

echo ""
echo -e "  ${GREEN}✓ Update complete!${RESET}"
echo -e "  Run ${CYAN}burp2har --version${RESET} to confirm the installed version."
echo ""
