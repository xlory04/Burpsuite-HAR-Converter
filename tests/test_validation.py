"""
Tests for XML validation (burp2har.validator) and HAR validation (burp2har.har_validator).

Coverage:
  C. HAR validation — VALID, INVALID, VALID_WITH_WARNINGS
  XML validation — COMPATIBLE, INCOMPATIBLE, MALFORMED, PARTIALLY_COMPATIBLE
"""
from __future__ import annotations

import json
import pathlib

import pytest

from burp2har.har_validator import HarValidationStatus, validate_har
from burp2har.validator import CompatibilityStatus, validate_xml

from tests.helpers import make_burp_xml, make_item


# ─── XML validation ───────────────────────────────────────────────────────────

class TestXmlValidation:

    def test_valid_xml_is_compatible(self, simple_get_xml):
        """A well-formed Burp XML with all required fields must return COMPATIBLE."""
        result = validate_xml(simple_get_xml)
        assert result.status == CompatibilityStatus.COMPATIBLE
        assert result.ok
        assert result.item_count >= 1
        assert result.valid_count >= 1

    def test_malformed_xml_returns_malformed(self, fixtures_dir):
        """An XML file that cannot be parsed must return MALFORMED."""
        text = (fixtures_dir / "malformed.xml").read_text(encoding="utf-8")
        result = validate_xml(text)
        assert result.status == CompatibilityStatus.MALFORMED
        assert not result.ok

    def test_no_items_returns_incompatible(self, fixtures_dir):
        """Valid XML with no <item> elements must return INCOMPATIBLE."""
        text = (fixtures_dir / "no_items.xml").read_text(encoding="utf-8")
        result = validate_xml(text)
        assert result.status == CompatibilityStatus.INCOMPATIBLE
        assert not result.ok

    def test_multi_item_all_valid(self, multi_item_xml):
        """An XML with multiple fully valid items must return COMPATIBLE."""
        result = validate_xml(multi_item_xml)
        assert result.status == CompatibilityStatus.COMPATIBLE
        assert result.item_count == 2
        assert result.valid_count == 2

    def test_partially_compatible_xml(self):
        """An XML where some items are missing only one required field must return
        PARTIALLY_COMPATIBLE (some items have <url> but no <request>)."""
        # Craft one fully valid item and one item missing the <request> element
        valid_item = make_item()
        partial_item = "<item><url>http://example.com/broken</url></item>"
        xml = make_burp_xml(valid_item, partial_item)
        result = validate_xml(xml)
        assert result.status == CompatibilityStatus.PARTIALLY_COMPATIBLE
        assert result.ok  # conversion can still proceed
        assert len(result.warnings) > 0

    def test_fully_incompatible_xml(self):
        """Items with neither <url> nor <request> must return INCOMPATIBLE."""
        xml = make_burp_xml("<item><foo>bar</foo></item>", "<item><baz>qux</baz></item>")
        result = validate_xml(xml)
        assert result.status == CompatibilityStatus.INCOMPATIBLE
        assert not result.ok

    def test_validation_result_ok_property(self, simple_get_xml):
        """ValidationResult.ok must be True for COMPATIBLE and PARTIALLY_COMPATIBLE."""
        compatible = validate_xml(simple_get_xml)
        assert compatible.ok

        partial_xml = make_burp_xml(
            make_item(),
            "<item><url>http://x.com/</url></item>",
        )
        partial = validate_xml(partial_xml)
        assert partial.ok

    def test_malformed_result_ok_is_false(self):
        """ValidationResult.ok must be False for MALFORMED."""
        result = validate_xml("<not valid xml")
        assert not result.ok


# ─── HAR validation ───────────────────────────────────────────────────────────

class TestHarValidation:

    def test_valid_har_returns_valid(self, fixtures_dir):
        """A structurally correct HAR file must return VALID."""
        text = (fixtures_dir / "valid.har").read_text(encoding="utf-8")
        result = validate_har(text)
        assert result.status == HarValidationStatus.VALID
        assert result.ok
        assert result.entry_count == 1
        assert result.errors == []
        assert result.warnings == []

    def test_malformed_json_returns_invalid(self, fixtures_dir):
        """A file that is not valid JSON must return INVALID."""
        text = (fixtures_dir / "malformed.har").read_text(encoding="utf-8")
        result = validate_har(text)
        assert result.status == HarValidationStatus.INVALID
        assert not result.ok

    def test_missing_log_key_returns_invalid(self):
        """A JSON object without the top-level 'log' key must return INVALID."""
        text = json.dumps({"entries": []})
        result = validate_har(text)
        assert result.status == HarValidationStatus.INVALID
        assert not result.ok

    def test_missing_entries_key_returns_invalid(self):
        """A log object without 'entries' must return INVALID."""
        text = json.dumps({
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
            }
        })
        result = validate_har(text)
        assert result.status == HarValidationStatus.INVALID
        assert not result.ok
        assert any("entries" in e for e in result.errors)

    def test_partial_har_returns_valid_with_warnings(self, fixtures_dir):
        """A HAR with status=0 (parsing artefact) must return VALID_WITH_WARNINGS."""
        text = (fixtures_dir / "partial.har").read_text(encoding="utf-8")
        result = validate_har(text)
        assert result.status == HarValidationStatus.VALID_WITH_WARNINGS
        assert result.ok
        assert len(result.warnings) > 0
        assert result.errors == []

    def test_entry_missing_request_returns_invalid(self):
        """An entry without a 'request' object must be flagged as INVALID."""
        text = json.dumps({
            "log": {
                "version": "1.2",
                "creator": {"name": "t", "version": "1"},
                "entries": [
                    {
                        "startedDateTime": "2025-01-01T00:00:00.000Z",
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "httpVersion": "HTTP/1.1",
                            "headers": [],
                        },
                    }
                ],
            }
        })
        result = validate_har(text)
        assert result.status == HarValidationStatus.INVALID
        assert not result.ok

    def test_entry_missing_response_returns_invalid(self):
        """An entry without a 'response' object must be flagged as INVALID."""
        text = json.dumps({
            "log": {
                "version": "1.2",
                "creator": {"name": "t", "version": "1"},
                "entries": [
                    {
                        "startedDateTime": "2025-01-01T00:00:00.000Z",
                        "request": {
                            "method": "GET",
                            "url": "http://example.com/",
                            "httpVersion": "HTTP/1.1",
                            "headers": [],
                        },
                    }
                ],
            }
        })
        result = validate_har(text)
        assert result.status == HarValidationStatus.INVALID

    def test_empty_entries_list_is_valid(self):
        """An empty entries list is structurally valid (no entries = no errors)."""
        text = json.dumps({
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": [],
            }
        })
        result = validate_har(text)
        assert result.status == HarValidationStatus.VALID
        assert result.ok
        assert result.entry_count == 0

    def test_har_ok_property(self, fixtures_dir):
        """HarValidationResult.ok must be True for both VALID and VALID_WITH_WARNINGS."""
        valid_text = (fixtures_dir / "valid.har").read_text(encoding="utf-8")
        assert validate_har(valid_text).ok

        partial_text = (fixtures_dir / "partial.har").read_text(encoding="utf-8")
        assert validate_har(partial_text).ok

        invalid_text = (fixtures_dir / "malformed.har").read_text(encoding="utf-8")
        assert not validate_har(invalid_text).ok
