"""
Tests for XML → HAR conversion (burp2har.harlog.HarLog).

Coverage:
  A. Valid Burp XML produces a valid HAR
  B. Edge cases: non-CST timezone, header values with ':', empty response
"""
from __future__ import annotations

import json

import pytest

from burp2har.har_validator import HarValidationStatus, validate_har
from burp2har.harlog import HarLog, HarTimeFormat

from tests.helpers import (
    _encode_request,
    _encode_response,
    make_burp_xml,
    make_item,
    xml_to_source,
)


# ─── A. XML → HAR conversion ──────────────────────────────────────────────────

class TestValidConversion:

    def test_produces_valid_har(self, simple_get_xml):
        """A well-formed Burp XML must produce a HAR that passes har_validator."""
        har_log, _, _ = HarLog().getHarLog(xml_to_source(simple_get_xml))
        result = validate_har(json.dumps(har_log))
        assert result.ok, f"HAR validation failed: {result.errors}"

    def test_har_log_structure(self, simple_get_xml):
        """The HAR log object must have the required top-level keys."""
        har_log, _, _ = HarLog().getHarLog(xml_to_source(simple_get_xml))
        log = har_log["log"]
        assert "version" in log
        assert "creator" in log
        assert "entries" in log
        assert log["version"] == "1.2"

    def test_entry_count_single(self, simple_get_xml):
        """A single-item XML must produce exactly one HAR entry."""
        entries, skipped, _ = HarLog().get_entries(xml_to_source(simple_get_xml))
        assert len(entries) == 1
        assert skipped == 0

    def test_entry_count_multiple(self, multi_item_xml):
        """A two-item XML must produce exactly two HAR entries."""
        entries, skipped, _ = HarLog().get_entries(xml_to_source(multi_item_xml))
        assert len(entries) == 2
        assert skipped == 0

    def test_request_method_get(self, simple_get_xml):
        """The request method must be preserved as 'GET'."""
        entries, _, _ = HarLog().get_entries(xml_to_source(simple_get_xml))
        assert entries[0]["request"]["method"] == "GET"

    def test_request_method_post(self, simple_post_xml):
        """The request method must be preserved as 'POST'."""
        entries, _, _ = HarLog().get_entries(xml_to_source(simple_post_xml))
        assert entries[0]["request"]["method"] == "POST"

    def test_response_status_200(self, simple_get_xml):
        """The response status code must be parsed as the integer 200."""
        entries, _, _ = HarLog().get_entries(xml_to_source(simple_get_xml))
        assert entries[0]["response"]["status"] == 200

    def test_response_status_201(self, simple_post_xml):
        """The response status code must be parsed as the integer 201."""
        entries, _, _ = HarLog().get_entries(xml_to_source(simple_post_xml))
        assert entries[0]["response"]["status"] == 201

    def test_post_has_post_data(self, simple_post_xml):
        """A POST request with a body must include a 'postData' key."""
        entries, _, _ = HarLog().get_entries(xml_to_source(simple_post_xml))
        req = entries[0]["request"]
        assert "postData" in req
        assert req["postData"]["text"] == '{"data": "hello"}'

    def test_get_has_no_post_data(self, simple_get_xml):
        """A GET request with no body must not include a 'postData' key."""
        entries, _, _ = HarLog().get_entries(xml_to_source(simple_get_xml))
        assert "postData" not in entries[0]["request"]

    def test_request_url_preserved(self, simple_get_xml):
        """The full URL (including query string) must be preserved."""
        entries, _, _ = HarLog().get_entries(xml_to_source(simple_get_xml))
        assert "example.com" in entries[0]["request"]["url"]

    def test_generate_har_writes_file(self, simple_get_xml, tmp_path, xml_file):
        """generate_har() must write a HAR file and return the correct stats dict."""
        xml_path = xml_file(simple_get_xml)
        out_path = tmp_path / "out.har"
        stats = HarLog().generate_har(xml_path, out_path, xml_text=simple_get_xml)
        assert out_path.exists()
        assert stats["entries"] == 1
        assert stats["skipped"] == 0
        # Verify the written file is valid JSON with HAR structure
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert "log" in data
        assert len(data["log"]["entries"]) == 1


# ─── B. Edge cases ────────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_non_cst_timezone_does_not_crash(self):
        """Timestamps with non-CST timezone abbreviations must not raise."""
        ht = HarTimeFormat()
        # CEST, EDT, BST, etc. are all stripped before parsing
        for tz in ("CEST", "EDT", "BST", "JST", "AEST"):
            result = ht.transBsToHarTime(f"Tue Apr 14 12:11:45 {tz} 2026")
            assert isinstance(result, str), f"Failed for TZ: {tz}"
            assert "T" in result, f"Not ISO format for TZ: {tz}"
            assert result.endswith("Z"), f"Missing trailing Z for TZ: {tz}"

    def test_malformed_timestamp_falls_back_to_now(self):
        """A timestamp that cannot be parsed must fall back to the current time, not crash."""
        ht = HarTimeFormat()
        result = ht.transBsToHarTime("not a valid timestamp at all")
        # Should return a valid ISO string (current time) rather than raising
        assert isinstance(result, str)
        assert result.endswith("Z")

    def test_header_with_colon_in_value_not_truncated(self):
        """Header values that contain ': ' must not be truncated at the colon."""
        csp_value = "default-src 'self'; img-src: data:; script-src: https://cdn.example.com"
        req_b64 = _encode_request(
            "GET", "/",
            headers=[
                ("Host", "example.com"),
                ("Content-Security-Policy", csp_value),
            ],
        )
        xml = make_burp_xml(make_item(request_b64=req_b64))
        entries, _, _ = HarLog().get_entries(xml_to_source(xml))
        header_map = {h["name"]: h["value"] for h in entries[0]["request"]["headers"]}
        assert header_map.get("content-security-policy") == csp_value

    def test_empty_response_produces_400_placeholder(self, no_response_xml):
        """An item with no <response> element must generate a synthetic HTTP 400 entry."""
        entries, skipped, _ = HarLog().get_entries(xml_to_source(no_response_xml))
        assert len(entries) == 1, "Item with missing response must still produce an entry"
        assert skipped == 0
        assert entries[0]["response"]["status"] == 400

    def test_empty_response_entry_is_har_valid(self, no_response_xml):
        """The synthetic 400 placeholder must still produce a structurally valid HAR entry."""
        har_log, _, _ = HarLog().getHarLog(xml_to_source(no_response_xml))
        result = validate_har(json.dumps(har_log))
        assert result.ok, f"HAR with 400 placeholder failed validation: {result.errors}"

    def test_query_string_parsed(self, simple_get_xml):
        """Query parameters must appear in the HAR queryString list."""
        entries, _, _ = HarLog().get_entries(xml_to_source(simple_get_xml))
        qs = {q["name"]: q["value"] for q in entries[0]["request"]["queryString"]}
        assert "token" in qs
