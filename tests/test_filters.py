"""
Tests for the --only-host / --only-status / --only-method filter logic.

Coverage:
  D. Filtering — individual filters, combined filters (AND across types, OR within a type)

The ``multi_host_xml`` fixture contains three items:
  api.example.com   GET  200
  api.example.com   POST 404
  other.example.com GET  302
"""
from __future__ import annotations

import pytest

from burp2har.harlog import HarLog, _passes_filter

from tests.helpers import xml_to_source


# ─── Unit tests for _passes_filter ────────────────────────────────────────────

class TestPassesFilter:
    """Low-level tests for the filter predicate used inside get_entries."""

    def test_no_filters_passes_all(self):
        assert _passes_filter("example.com", "GET", "200", {}) is True

    def test_host_filter_match(self):
        assert _passes_filter("example.com", "GET", "200", {"host": ["example.com"]}) is True

    def test_host_filter_no_match(self):
        assert _passes_filter("other.com", "GET", "200", {"host": ["example.com"]}) is False

    def test_method_filter_match(self):
        assert _passes_filter("example.com", "POST", "200", {"method": ["POST"]}) is True

    def test_method_filter_no_match(self):
        assert _passes_filter("example.com", "GET", "200", {"method": ["POST"]}) is False

    def test_status_filter_match(self):
        assert _passes_filter("example.com", "GET", "404", {"status": ["404"]}) is True

    def test_status_filter_no_match(self):
        assert _passes_filter("example.com", "GET", "200", {"status": ["404"]}) is False

    def test_or_logic_within_status(self):
        """Multiple values in one filter type use OR logic."""
        f = {"status": ["200", "302"]}
        assert _passes_filter("example.com", "GET", "200", f) is True
        assert _passes_filter("example.com", "GET", "302", f) is True
        assert _passes_filter("example.com", "GET", "404", f) is False

    def test_or_logic_within_method(self):
        f = {"method": ["GET", "POST"]}
        assert _passes_filter("example.com", "GET", "200", f) is True
        assert _passes_filter("example.com", "POST", "200", f) is True
        assert _passes_filter("example.com", "PUT", "200", f) is False

    def test_and_logic_across_types(self):
        """Filters across types use AND logic — both must match."""
        f = {"host": ["example.com"], "method": ["GET"]}
        assert _passes_filter("example.com", "GET", "200", f) is True
        assert _passes_filter("example.com", "POST", "200", f) is False
        assert _passes_filter("other.com", "GET", "200", f) is False


# ─── Integration tests via get_entries ────────────────────────────────────────

class TestGetEntriesWithFilters:
    """Tests that filters are applied correctly by the streaming parser."""

    def test_only_status_200(self, multi_host_xml):
        """--only-status 200 must keep only the one GET 200 item."""
        entries, _, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters={"status": ["200"]},
        )
        assert len(entries) == 1
        assert filtered == 2
        assert entries[0]["response"]["status"] == 200

    def test_only_status_multiple_values(self, multi_host_xml):
        """--only-status 200 --only-status 302 must keep two items (OR logic)."""
        entries, _, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters={"status": ["200", "302"]},
        )
        assert len(entries) == 2
        assert filtered == 1
        statuses = {e["response"]["status"] for e in entries}
        assert statuses == {200, 302}

    def test_only_method_get(self, multi_host_xml):
        """--only-method GET must keep the two GET items."""
        entries, _, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters={"method": ["GET"]},
        )
        assert len(entries) == 2
        assert filtered == 1
        for e in entries:
            assert e["request"]["method"] == "GET"

    def test_only_method_post(self, multi_host_xml):
        """--only-method POST must keep only the one POST item."""
        entries, _, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters={"method": ["POST"]},
        )
        assert len(entries) == 1
        assert filtered == 2
        assert entries[0]["request"]["method"] == "POST"

    def test_only_host_api(self, multi_host_xml):
        """--only-host api.example.com must keep both items from that host."""
        entries, _, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters={"host": ["api.example.com"]},
        )
        assert len(entries) == 2
        assert filtered == 1

    def test_only_host_other(self, multi_host_xml):
        """--only-host other.example.com must keep only the one redirect item."""
        entries, _, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters={"host": ["other.example.com"]},
        )
        assert len(entries) == 1
        assert filtered == 2

    def test_combined_host_and_method(self, multi_host_xml):
        """--only-host api.example.com --only-method POST must match exactly one item."""
        entries, _, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters={"host": ["api.example.com"], "method": ["POST"]},
        )
        assert len(entries) == 1
        assert filtered == 2
        assert entries[0]["request"]["method"] == "POST"

    def test_combined_host_and_status(self, multi_host_xml):
        """--only-host api.example.com --only-status 200 must match exactly one item."""
        entries, _, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters={"host": ["api.example.com"], "status": ["200"]},
        )
        assert len(entries) == 1
        assert filtered == 2

    def test_filter_no_match_returns_empty(self, multi_host_xml):
        """A filter that matches nothing must return an empty entries list."""
        entries, _, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters={"status": ["999"]},
        )
        assert len(entries) == 0
        assert filtered == 3

    def test_no_filters_returns_all(self, multi_host_xml):
        """Passing no filters (None) must return all items."""
        entries, _, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters=None,
        )
        assert len(entries) == 3
        assert filtered == 0

    def test_filtered_count_matches_skipped_items(self, multi_host_xml):
        """entries + filtered_out must equal total item count in the XML."""
        total = 3
        entries, skipped, filtered = HarLog().get_entries(
            xml_to_source(multi_host_xml),
            filters={"method": ["GET"]},
        )
        assert len(entries) + filtered + skipped == total
