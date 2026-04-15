"""
CLI tests for burp2har.

Uses Typer's CliRunner to invoke the ``app`` object directly (bypassing the
``run()`` entry point so first-run checks and sys.argv injection are not
triggered).

Coverage:
  - --version: output format and version string
  - convert: exit codes 0, 1, 2; output file creation
  - validate: exit codes 0, 2
  - validate-har: exit codes 0, 2
  - entry point: ``python -m burp2har`` and ``burp2har`` console script
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from burp2har import __version__
from burp2har.cli import app, _SUBCOMMANDS

runner = CliRunner()


# ─── --version and command set ────────────────────────────────────────────────

class TestVersionAndCommandSet:

    def test_version_flag_exit_code_0(self):
        """--version must exit with code 0."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_version_flag_output_contains_version_string(self):
        """--version output must contain the version from burp2har.__version__."""
        result = runner.invoke(app, ["--version"])
        assert __version__ in result.output, (
            f"Expected version '{__version__}' in output, got: {result.output!r}"
        )

    def test_version_flag_output_contains_command_name(self):
        """--version output must mention 'burp2har'."""
        result = runner.invoke(app, ["--version"])
        assert "burp2har" in result.output

    def test_all_expected_subcommands_registered(self):
        """_SUBCOMMANDS must include all commands exposed by the app."""
        expected = {"convert", "validate", "validate-har", "info", "update", "help"}
        assert expected == _SUBCOMMANDS, (
            f"Subcommand set mismatch.\n"
            f"  Missing from _SUBCOMMANDS : {expected - _SUBCOMMANDS}\n"
            f"  Extra in _SUBCOMMANDS     : {_SUBCOMMANDS - expected}"
        )


# ─── convert ─────────────────────────────────────────────────────────────────

class TestConvertCommand:

    def test_valid_xml_exit_code_0(self, xml_file, simple_get_xml, tmp_path):
        """Converting a valid Burp XML must exit with code 0."""
        f = xml_file(simple_get_xml)
        out = tmp_path / "out.har"
        result = runner.invoke(app, ["convert", str(f), "-o", str(out)])
        assert result.exit_code == 0

    def test_valid_xml_creates_output_file(self, xml_file, simple_get_xml, tmp_path):
        """A successful conversion must write the .har file to disk."""
        f = xml_file(simple_get_xml)
        out = tmp_path / "out.har"
        runner.invoke(app, ["convert", str(f), "-o", str(out)])
        assert out.exists()

    def test_output_file_is_valid_json(self, xml_file, simple_get_xml, tmp_path):
        """The produced .har file must be parseable as JSON with a 'log' key."""
        f = xml_file(simple_get_xml)
        out = tmp_path / "out.har"
        runner.invoke(app, ["convert", str(f), "-o", str(out)])
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "log" in data
        assert len(data["log"]["entries"]) == 1

    def test_missing_input_file_exit_code_1(self, tmp_path):
        """A non-existent input file must exit with code 1."""
        result = runner.invoke(app, ["convert", str(tmp_path / "ghost.xml")])
        assert result.exit_code == 1

    def test_malformed_xml_exit_code_2(self, xml_file, fixtures_dir, tmp_path):
        """Malformed XML must exit with code 2."""
        malformed = (fixtures_dir / "malformed.xml").read_text(encoding="utf-8")
        f = xml_file(malformed, name="malformed.xml")
        out = tmp_path / "out.har"
        result = runner.invoke(app, ["convert", str(f), "-o", str(out)])
        assert result.exit_code == 2

    def test_incompatible_xml_exit_code_2(self, xml_file, fixtures_dir, tmp_path):
        """XML with no <item> elements (incompatible) must exit with code 2."""
        no_items = (fixtures_dir / "no_items.xml").read_text(encoding="utf-8")
        f = xml_file(no_items, name="no_items.xml")
        out = tmp_path / "out.har"
        result = runner.invoke(app, ["convert", str(f), "-o", str(out)])
        assert result.exit_code == 2

    def test_default_output_path(self, xml_file, simple_get_xml, tmp_path):
        """When -o is omitted, the .har file must be created next to the input."""
        f = xml_file(simple_get_xml, name="export.xml")
        runner.invoke(app, ["convert", str(f)])
        expected = f.parent / "export.har"
        assert expected.exists()

    def test_only_method_filter(self, xml_file, multi_item_xml, tmp_path):
        """--only-method GET must keep only GET entries in the output HAR."""
        f = xml_file(multi_item_xml)
        out = tmp_path / "out.har"
        runner.invoke(app, ["convert", str(f), "-o", str(out), "--only-method", "GET"])
        data = json.loads(out.read_text(encoding="utf-8"))
        for entry in data["log"]["entries"]:
            assert entry["request"]["method"] == "GET"

    def test_only_status_filter(self, xml_file, multi_item_xml, tmp_path):
        """--only-status 200 must keep only the 200 entry in the output HAR."""
        f = xml_file(multi_item_xml)
        out = tmp_path / "out.har"
        runner.invoke(app, ["convert", str(f), "-o", str(out), "--only-status", "200"])
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data["log"]["entries"]) == 1
        assert data["log"]["entries"][0]["response"]["status"] == 200

    def test_anonymize_flag_redacts_authorization(self, xml_file, simple_get_xml, tmp_path):
        """--anonymize must redact the Authorization header in the output HAR."""
        f = xml_file(simple_get_xml)
        out = tmp_path / "out.har"
        runner.invoke(app, ["convert", str(f), "-o", str(out), "--anonymize"])
        data = json.loads(out.read_text(encoding="utf-8"))
        headers = {
            h["name"]: h["value"]
            for h in data["log"]["entries"][0]["request"]["headers"]
        }
        assert headers.get("authorization") == "[REDACTED]"


# ─── validate ────────────────────────────────────────────────────────────────

class TestValidateCommand:

    def test_valid_xml_exit_code_0(self, xml_file, simple_get_xml):
        """Validating a compatible Burp XML must exit with code 0."""
        f = xml_file(simple_get_xml)
        result = runner.invoke(app, ["validate", str(f)])
        assert result.exit_code == 0

    def test_malformed_xml_exit_code_2(self, fixtures_dir):
        """Validating a malformed XML file must exit with code 2."""
        result = runner.invoke(app, ["validate", str(fixtures_dir / "malformed.xml")])
        assert result.exit_code == 2

    def test_incompatible_xml_exit_code_2(self, fixtures_dir):
        """Validating an XML file with no <item> elements must exit with code 2."""
        result = runner.invoke(app, ["validate", str(fixtures_dir / "no_items.xml")])
        assert result.exit_code == 2

    def test_missing_file_exit_code_1(self, tmp_path):
        """Validating a non-existent file must exit with code 1."""
        result = runner.invoke(app, ["validate", str(tmp_path / "ghost.xml")])
        assert result.exit_code == 1


# ─── validate-har ────────────────────────────────────────────────────────────

class TestValidateHarCommand:

    def test_valid_har_exit_code_0(self, fixtures_dir):
        """Validating a valid HAR file must exit with code 0."""
        result = runner.invoke(app, ["validate-har", str(fixtures_dir / "valid.har")])
        assert result.exit_code == 0

    def test_partial_har_exit_code_0(self, fixtures_dir):
        """A HAR with only warnings (status=0) must still exit with code 0."""
        result = runner.invoke(app, ["validate-har", str(fixtures_dir / "partial.har")])
        assert result.exit_code == 0

    def test_malformed_har_exit_code_2(self, fixtures_dir):
        """A file that is not valid JSON must exit with code 2."""
        result = runner.invoke(app, ["validate-har", str(fixtures_dir / "malformed.har")])
        assert result.exit_code == 2

    def test_missing_file_exit_code_1(self, tmp_path):
        """Validating a non-existent HAR file must exit with code 1."""
        result = runner.invoke(app, ["validate-har", str(tmp_path / "ghost.har")])
        assert result.exit_code == 1

    def test_converted_har_passes_validate_har(self, xml_file, simple_get_xml, tmp_path):
        """A HAR produced by 'convert' must pass 'validate-har' with exit code 0."""
        f = xml_file(simple_get_xml)
        out = tmp_path / "out.har"
        runner.invoke(app, ["convert", str(f), "-o", str(out)])
        result = runner.invoke(app, ["validate-har", str(out)])
        assert result.exit_code == 0


# ─── entry-point smoke tests ──────────────────────────────────────────────────

class TestEntryPoints:
    """Verify the two public invocation paths work after installation."""

    def test_module_execution_exit_code_0(self):
        """``python -m burp2har --version`` must exit with code 0."""
        proc = subprocess.run(
            [sys.executable, "-m", "burp2har", "--version"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0, (
            f"python -m burp2har --version exited {proc.returncode}\n"
            f"stdout: {proc.stdout!r}\n"
            f"stderr: {proc.stderr!r}"
        )

    def test_module_execution_output_contains_version(self):
        """``python -m burp2har --version`` must print the package version."""
        proc = subprocess.run(
            [sys.executable, "-m", "burp2har", "--version"],
            capture_output=True, text=True,
        )
        assert __version__ in proc.stdout, (
            f"Expected version '{__version__}' in output, got: {proc.stdout!r}"
        )

    def test_console_script_exit_code_0(self):
        """``burp2har --version`` (installed console script) must exit with code 0."""
        # Locate the installed script next to the current Python interpreter so
        # the test works in virtualenvs, editable installs, and CI alike.
        scripts_dir = pathlib.Path(sys.executable).parent
        burp2har_exe = scripts_dir / "burp2har"
        if not burp2har_exe.exists():
            burp2har_exe = scripts_dir / "burp2har.exe"  # Windows
        if not burp2har_exe.exists():
            pytest.skip("burp2har console script not found — run 'pip install -e .' first")

        proc = subprocess.run(
            [str(burp2har_exe), "--version"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0, (
            f"burp2har --version exited {proc.returncode}\n"
            f"stdout: {proc.stdout!r}\n"
            f"stderr: {proc.stderr!r}"
        )
