"""
Tests for the --anonymize flag (burp2har.harlog._apply_anonymization).

Coverage:
  E. Anonymization
     - Authorization headers are redacted
     - Cookie headers are redacted
     - Cookies list is cleared
     - Sensitive query params (e.g. 'token') are masked
     - Non-sensitive fields are left intact
     - The resulting HAR is still structurally valid
"""
from __future__ import annotations

import json

import pytest

from burp2har.har_validator import validate_har
from burp2har.harlog import (
    HarLog,
    _REDACTED,
    _apply_anonymization,
    _sanitize_headers,
    _sanitize_query,
)

from tests.helpers import xml_to_source

# ─── Unit tests for sanitize helpers ─────────────────────────────────────────

class TestSanitizeHeaders:

    def test_authorization_is_redacted(self):
        headers = [{"name": "authorization", "value": "Bearer secret"}]
        result = _sanitize_headers(headers)
        assert result[0]["value"] == _REDACTED

    def test_cookie_is_redacted(self):
        headers = [{"name": "cookie", "value": "session=abc; id=123"}]
        result = _sanitize_headers(headers)
        assert result[0]["value"] == _REDACTED

    def test_set_cookie_is_redacted(self):
        headers = [{"name": "set-cookie", "value": "id=abc; Path=/; HttpOnly"}]
        result = _sanitize_headers(headers)
        assert result[0]["value"] == _REDACTED

    def test_x_api_key_is_redacted(self):
        headers = [{"name": "x-api-key", "value": "my-secret-api-key"}]
        result = _sanitize_headers(headers)
        assert result[0]["value"] == _REDACTED

    def test_non_sensitive_header_preserved(self):
        headers = [{"name": "content-type", "value": "application/json"}]
        result = _sanitize_headers(headers)
        assert result[0]["value"] == "application/json"

    def test_mixed_headers(self):
        headers = [
            {"name": "host", "value": "example.com"},
            {"name": "authorization", "value": "Bearer tok"},
            {"name": "content-type", "value": "text/html"},
            {"name": "cookie", "value": "s=1"},
        ]
        result = _sanitize_headers(headers)
        by_name = {h["name"]: h["value"] for h in result}
        assert by_name["host"] == "example.com"
        assert by_name["content-type"] == "text/html"
        assert by_name["authorization"] == _REDACTED
        assert by_name["cookie"] == _REDACTED

    def test_original_list_not_mutated(self):
        """_sanitize_headers must return a new list and not modify the original."""
        headers = [{"name": "authorization", "value": "Bearer tok"}]
        original_value = headers[0]["value"]
        _sanitize_headers(headers)
        assert headers[0]["value"] == original_value


class TestSanitizeQuery:

    def test_token_param_is_redacted(self):
        qs = [{"name": "token", "value": "abc123"}]
        result = _sanitize_query(qs)
        assert result[0]["value"] == _REDACTED

    def test_api_key_param_is_redacted(self):
        qs = [{"name": "api_key", "value": "my-key"}]
        result = _sanitize_query(qs)
        assert result[0]["value"] == _REDACTED

    def test_password_param_is_redacted(self):
        qs = [{"name": "password", "value": "hunter2"}]
        result = _sanitize_query(qs)
        assert result[0]["value"] == _REDACTED

    def test_non_sensitive_param_preserved(self):
        qs = [{"name": "page", "value": "1"}, {"name": "sort", "value": "asc"}]
        result = _sanitize_query(qs)
        by_name = {q["name"]: q["value"] for q in result}
        assert by_name["page"] == "1"
        assert by_name["sort"] == "asc"

    def test_mixed_params(self):
        qs = [
            {"name": "q", "value": "hello"},
            {"name": "token", "value": "secret"},
            {"name": "page", "value": "2"},
        ]
        result = _sanitize_query(qs)
        by_name = {q["name"]: q["value"] for q in result}
        assert by_name["q"] == "hello"
        assert by_name["page"] == "2"
        assert by_name["token"] == _REDACTED


# ─── Integration tests via get_entries ────────────────────────────────────────

class TestAnonymizeIntegration:
    """Full-pipeline anonymization tests using get_entries(anonymize=True)."""

    def test_authorization_header_redacted(self, simple_get_xml):
        """Authorization header value must be replaced with [REDACTED]."""
        entries, _, _ = HarLog().get_entries(
            xml_to_source(simple_get_xml), anonymize=True
        )
        headers = {h["name"]: h["value"] for h in entries[0]["request"]["headers"]}
        assert headers.get("authorization") == _REDACTED

    def test_cookie_header_redacted(self, simple_get_xml):
        """Cookie header value must be replaced with [REDACTED]."""
        entries, _, _ = HarLog().get_entries(
            xml_to_source(simple_get_xml), anonymize=True
        )
        headers = {h["name"]: h["value"] for h in entries[0]["request"]["headers"]}
        assert headers.get("cookie") == _REDACTED

    def test_cookies_list_cleared(self, simple_get_xml):
        """The parsed cookies list in request must be empty after anonymization."""
        entries, _, _ = HarLog().get_entries(
            xml_to_source(simple_get_xml), anonymize=True
        )
        assert entries[0]["request"]["cookies"] == []

    def test_sensitive_query_param_redacted(self, simple_get_xml):
        """The 'token' query parameter must be replaced with [REDACTED]."""
        entries, _, _ = HarLog().get_entries(
            xml_to_source(simple_get_xml), anonymize=True
        )
        qs = {q["name"]: q["value"] for q in entries[0]["request"]["queryString"]}
        assert qs.get("token") == _REDACTED

    def test_non_sensitive_headers_intact(self, simple_get_xml):
        """Headers that are not in the sensitive list must not be touched."""
        entries, _, _ = HarLog().get_entries(
            xml_to_source(simple_get_xml), anonymize=True
        )
        headers = {h["name"]: h["value"] for h in entries[0]["request"]["headers"]}
        # 'host' and 'user-agent' are not sensitive
        assert headers.get("host") == "example.com"
        assert "user-agent" in headers
        assert headers["user-agent"] != _REDACTED

    def test_har_structure_valid_after_anonymization(self, simple_get_xml):
        """Anonymized HAR must still pass the HAR structure validator."""
        har_log, _, _ = HarLog().getHarLog(
            xml_to_source(simple_get_xml), anonymize=True
        )
        result = validate_har(json.dumps(har_log))
        assert result.ok, f"Anonymized HAR failed validation: {result.errors}"

    def test_no_anonymize_preserves_original_values(self, simple_get_xml):
        """Without --anonymize, Authorization and Cookie must retain their values."""
        entries, _, _ = HarLog().get_entries(
            xml_to_source(simple_get_xml), anonymize=False
        )
        headers = {h["name"]: h["value"] for h in entries[0]["request"]["headers"]}
        assert headers.get("authorization") != _REDACTED
        assert headers.get("cookie") != _REDACTED

    def test_response_sensitive_headers_redacted(self, simple_get_xml):
        """Set-Cookie in the response must also be redacted when anonymize=True."""
        from tests.helpers import _encode_request, _encode_response, make_item, make_burp_xml
        req_b64 = _encode_request("GET", "/", headers=[("Host", "example.com")])
        resp_b64 = _encode_response(
            200, "OK",
            headers=[
                ("Content-Type", "text/plain"),
                ("Set-Cookie", "session=supersecret; Path=/; HttpOnly"),
            ],
            body=b"OK",
        )
        xml = make_burp_xml(make_item(request_b64=req_b64, response_b64=resp_b64))
        entries, _, _ = HarLog().get_entries(xml_to_source(xml), anonymize=True)
        resp_headers = {h["name"]: h["value"] for h in entries[0]["response"]["headers"]}
        assert resp_headers.get("set-cookie") == _REDACTED
