"""
Shared pytest fixtures for the burp2har test suite.

All fixtures that return XML or HAR content yield *strings* (not file objects)
so unit tests have no I/O dependency and stay fast.  The ``xml_file`` fixture
is the only one that touches the filesystem — it is used only by CLI tests
that require a real path on disk.
"""
from __future__ import annotations

import pathlib
import textwrap

import pytest

from tests.helpers import (
    _encode_request,
    _encode_response,
    make_burp_xml,
    make_item,
    make_item_no_response,
)


# ─── Session-scoped base64 building blocks ────────────────────────────────────

@pytest.fixture(scope="session")
def get_request_b64():
    """GET request with Authorization, Cookie, and a sensitive query param."""
    return _encode_request(
        "GET", "/api/data?token=abc",
        headers=[
            ("Host", "example.com"),
            ("User-Agent", "Mozilla/5.0"),
            ("Authorization", "Bearer secret-token"),
            ("Cookie", "session=xyz"),
        ],
    )


@pytest.fixture(scope="session")
def get_response_b64():
    """200 OK JSON response."""
    return _encode_response(
        200, "OK",
        headers=[
            ("Content-Type", "application/json"),
            ("Content-Length", "13"),
        ],
        body=b'{"ok": true}',
    )


@pytest.fixture(scope="session")
def post_request_b64():
    """POST request with a JSON body."""
    body = b'{"data": "hello"}'
    return _encode_request(
        "POST", "/api/submit",
        headers=[
            ("Host", "example.com"),
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ],
        body=body,
    )


@pytest.fixture(scope="session")
def post_response_b64():
    """201 Created JSON response."""
    return _encode_response(
        201, "Created",
        headers=[("Content-Type", "application/json")],
        body=b'{"id": 1}',
    )


# ─── XML string fixtures ──────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def simple_get_xml(get_request_b64, get_response_b64):
    """Single GET 200 item — carries Authorization, Cookie, and token query param."""
    item = make_item(
        url="http://example.com/api/data?token=abc",
        host="example.com",
        method="GET",
        path="/api/data",
        status="200",
        request_b64=get_request_b64,
        response_b64=get_response_b64,
    )
    return make_burp_xml(item)


@pytest.fixture(scope="session")
def simple_post_xml(post_request_b64, post_response_b64):
    """Single POST 201 item with a JSON body."""
    item = make_item(
        url="http://example.com/api/submit",
        host="example.com",
        method="POST",
        path="/api/submit",
        status="201",
        request_b64=post_request_b64,
        response_b64=post_response_b64,
    )
    return make_burp_xml(item)


@pytest.fixture(scope="session")
def multi_item_xml(get_request_b64, get_response_b64, post_request_b64, post_response_b64):
    """Two items: GET 200 and POST 201."""
    item1 = make_item(
        url="http://example.com/api/data",
        host="example.com",
        method="GET",
        path="/api/data",
        status="200",
        request_b64=get_request_b64,
        response_b64=get_response_b64,
    )
    item2 = make_item(
        url="http://example.com/api/submit",
        host="example.com",
        method="POST",
        path="/api/submit",
        status="201",
        request_b64=post_request_b64,
        response_b64=post_response_b64,
    )
    return make_burp_xml(item1, item2)


@pytest.fixture(scope="session")
def no_response_xml():
    """Item whose ``<response>`` element is absent — triggers the 400 placeholder."""
    return make_burp_xml(make_item_no_response())


@pytest.fixture(scope="session")
def multi_host_xml():
    """Three items from two hosts, spanning different methods and status codes.

    api.example.com   GET  200
    api.example.com   POST 404
    other.example.com GET  302
    """
    item1 = make_item(
        url="http://api.example.com/a",
        host="api.example.com",
        method="GET",
        path="/a",
        status="200",
        request_b64=_encode_request("GET", "/a", headers=[("Host", "api.example.com")]),
        response_b64=_encode_response(200, "OK", headers=[("Content-Type", "text/plain")], body=b"OK"),
    )
    item2 = make_item(
        url="http://api.example.com/b",
        host="api.example.com",
        method="POST",
        path="/b",
        status="404",
        request_b64=_encode_request(
            "POST", "/b",
            headers=[("Host", "api.example.com"), ("Content-Type", "application/json")],
            body=b"{}",
        ),
        response_b64=_encode_response(404, "Not Found", headers=[("Content-Type", "text/plain")], body=b"not found"),
    )
    item3 = make_item(
        url="http://other.example.com/c",
        host="other.example.com",
        method="GET",
        path="/c",
        status="302",
        request_b64=_encode_request("GET", "/c", headers=[("Host", "other.example.com")]),
        response_b64=_encode_response(302, "Found", headers=[("Location", "http://example.com/")]),
    )
    return make_burp_xml(item1, item2, item3)


# ─── Filesystem helper ────────────────────────────────────────────────────────

@pytest.fixture
def xml_file(tmp_path):
    """Return a callable that writes an XML string to a temp file.

    Usage::

        def test_something(xml_file, simple_get_xml):
            path = xml_file(simple_get_xml)  # -> tmp_path / "export.xml"
    """
    def _write(xml: str, name: str = "export.xml") -> pathlib.Path:
        p = tmp_path / name
        p.write_text(xml, encoding="utf-8")
        return p
    return _write


@pytest.fixture(scope="session")
def fixtures_dir() -> pathlib.Path:
    """Absolute path to the static test fixtures directory."""
    return pathlib.Path(__file__).parent / "fixtures"
