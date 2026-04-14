# burp2har — Windows Update Script
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   Right-click this file → "Run with PowerShell"
#   Or from a terminal:  powershell -ExecutionPolicy Bypass -File scripts\update_windows.ps1
#
# What it does:
#   Installs (or upgrades) burp2har from the GitHub repository using pip.
#   Requires Python 3.8+ and internet access.
# ─────────────────────────────────────────────────────────────────────────────

param(
    [switch]$Force   # Skip the confirmation prompt
)

$RepoUrl     = "https://github.com/xlory04/Burpsuite-HAR-Converter.git"
$InstallSpec = "git+$RepoUrl"

Write-Host ""
Write-Host "  burp2har — Update Script (Windows)" -ForegroundColor Cyan
Write-Host "  ────────────────────────────────────────────────────"
Write-Host ""

# ── Check Python ──────────────────────────────────────────────────────────────
$PythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $PythonCmd = $cmd
        break
    }
}

if (-not $PythonCmd) {
    Write-Host "  ERROR: Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "  Download Python from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "  During installation, check 'Add Python to PATH'." -ForegroundColor Yellow
    exit 1
}

$PythonVersion = & $PythonCmd --version 2>&1
Write-Host "  Python found: $PythonVersion" -ForegroundColor Green

# ── Confirm ───────────────────────────────────────────────────────────────────
if (-not $Force) {
    $confirm = Read-Host "`n  Install the latest burp2har from GitHub? [Y/n]"
    if ($confirm -match "^[Nn]") {
        Write-Host "`n  Aborted.`n" -ForegroundColor Yellow
        exit 0
    }
}

# ── Install ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Running: pip install --upgrade $InstallSpec" -ForegroundColor Yellow
Write-Host ""

& $PythonCmd -m pip install --upgrade $InstallSpec

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "  ✓ Update complete!" -ForegroundColor Green
    Write-Host "  Run 'burp2har --version' to confirm the installed version." -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "  ✗ Update failed. Review the pip output above." -ForegroundColor Red
    Write-Host "  You can also download the latest release from:" -ForegroundColor Yellow
    Write-Host "  https://github.com/xlory04/Burpsuite-HAR-Converter/releases" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}
