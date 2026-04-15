"""
Pure helper functions for building Burp Suite XML fixtures in tests.

These are plain functions (no pytest dependencies) so they can be imported
by both conftest.py and individual test modules without import-order issues.
"""
from __future__ import annotations

import io
import textwrap
from base64 import b64encode
from typing import List, Optional, Tuple


def _encode_request(
    method: str,
    path: str,
    http_version: str = "HTTP/1.1",
    headers: Optional[List[Tuple[str, str]]] = None,
    body: bytes = b"",
) -> str:
    """Return a base64-encoded HTTP request as Burp Suite would export it."""
    lines: List[bytes] = [f"{method} {path} {http_version}".encode()]
    for name, value in (headers or []):
        lines.append(f"{name}: {value}".encode())
    raw = b"\r\n".join(lines) + b"\r\n\r\n" + body
    return b64encode(raw).decode()


def _encode_response(
    status: int,
    status_text: str,
    http_version: str = "HTTP/1.1",
    headers: Optional[List[Tuple[str, str]]] = None,
    body: bytes = b"",
) -> str:
    """Return a base64-encoded HTTP response as Burp Suite would export it."""
    lines: List[bytes] = [f"{http_version} {status} {status_text}".encode()]
    for name, value in (headers or []):
        lines.append(f"{name}: {value}".encode())
    raw = b"\r\n".join(lines) + b"\r\n\r\n" + body
    return b64encode(raw).decode()


def make_item(
    url: str = "http://example.com/",
    host: str = "example.com",
    ip: str = "1.2.3.4",
    method: str = "GET",
    path: str = "/",
    extension: str = "null",
    status: str = "200",
    time_str: str = "Tue Apr 15 10:00:00 CST 2025",
    request_b64: Optional[str] = None,
    response_b64: Optional[str] = None,
) -> str:
    """Return a minimal Burp Suite ``<item>`` XML block as a string."""
    if request_b64 is None:
        request_b64 = _encode_request(method, path, headers=[("Host", host)])
    if response_b64 is None:
        status_int = int(status) if status.isdigit() else 200
        response_b64 = _encode_response(
            status_int, "OK",
            headers=[("Content-Type", "text/plain"), ("Content-Length", "2")],
            body=b"OK",
        )
    return textwrap.dedent(f"""\
        <item>
          <time>{time_str}</time>
          <url>{url}</url>
          <host ip="{ip}">{host}</host>
          <port>80</port>
          <protocol>http</protocol>
          <method>{method}</method>
          <path>{path}</path>
          <extension>{extension}</extension>
          <request base64="true">{request_b64}</request>
          <status>{status}</status>
          <response base64="true">{response_b64}</response>
          <comment></comment>
        </item>""")


def make_item_no_response(
    url: str = "http://example.com/",
    host: str = "example.com",
    method: str = "GET",
    path: str = "/",
    time_str: str = "Tue Apr 15 10:00:00 CST 2025",
) -> str:
    """Return a ``<item>`` block with no ``<response>`` element."""
    req_b64 = _encode_request(method, path, headers=[("Host", host)])
    return textwrap.dedent(f"""\
        <item>
          <time>{time_str}</time>
          <url>{url}</url>
          <host ip="1.2.3.4">{host}</host>
          <port>80</port>
          <protocol>http</protocol>
          <method>{method}</method>
          <path>{path}</path>
          <extension>null</extension>
          <request base64="true">{req_b64}</request>
          <status></status>
          <comment></comment>
        </item>""")


def make_burp_xml(*items: str) -> str:
    """Wrap one or more ``<item>`` blocks in a ``<items>`` root element."""
    body = "\n".join(items)
    return f'<?xml version="1.0"?>\n<items burpVersion="2023.1">\n{body}\n</items>'


def xml_to_source(xml: str) -> io.BytesIO:
    """Wrap an XML string in BytesIO so ``HarLog.get_entries`` can stream it."""
    return io.BytesIO(xml.encode("utf-8"))
