"""
Core XML-to-HAR converter for burp2har.

Key design decisions:
- get_entries() uses iterparse + root.clear() to process one <item> at a time,
  avoiding building a full DOM tree in memory (critical for files > 100 MB).
- Filters are evaluated on raw XML text values before the expensive base64 decode.
- Anonymization replaces sensitive header/query values with '[REDACTED]' in-place
  after entry construction, without altering the HAR structure.
"""
from __future__ import annotations

import io
import json
import sys
import time
import xml.etree.ElementTree as ET
from base64 import b64decode, b64encode
from datetime import datetime
from http import cookies
from typing import Dict, FrozenSet, List, Optional, Tuple, Union
from urllib import parse

from .config import VERSION


# ─── Logging helpers ──────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(f"[burp2har] {msg}", file=sys.stderr)

def _warn(msg: str) -> None:
    print(f"[burp2har] WARNING: {msg}", file=sys.stderr)


# ─── Anonymization constants and helpers ──────────────────────────────────────

# Header names (lowercase) whose values are fully redacted when --anonymize is on.
_SENSITIVE_HEADERS: FrozenSet[str] = frozenset({
    'authorization',
    'proxy-authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'x-auth-token',
    'x-access-token',
    'x-csrf-token',
})

# Query-parameter names (lowercase) whose values are masked when --anonymize is on.
_SENSITIVE_QUERY_PARAMS: FrozenSet[str] = frozenset({
    'token',
    'access_token',
    'refresh_token',
    'id_token',
    'api_key',
    'apikey',
    'api_token',
    'auth_token',
    'session',
    'sessionid',
    'session_id',
    'jsessionid',
    'key',
    'secret',
    'client_secret',
    'password',
    'passwd',
    'pwd',
})

_REDACTED = '[REDACTED]'


def _sanitize_headers(headers: List[Dict]) -> List[Dict]:
    """
    Return a copy of *headers* with values of sensitive headers replaced by
    ``'[REDACTED]'``.  Non-sensitive headers are returned unchanged (same dict).
    """
    result = []
    for h in headers:
        if h.get('name', '').lower() in _SENSITIVE_HEADERS:
            result.append({'name': h['name'], 'value': _REDACTED})
        else:
            result.append(h)
    return result


def _sanitize_query(query_list: List[Dict]) -> List[Dict]:
    """
    Return a copy of *query_list* with values of sensitive parameters replaced
    by ``'[REDACTED]'``.
    """
    result = []
    for q in query_list:
        if q.get('name', '').lower() in _SENSITIVE_QUERY_PARAMS:
            result.append({'name': q['name'], 'value': _REDACTED})
        else:
            result.append(q)
    return result


def _apply_anonymization(entry: Dict) -> None:
    """
    Mutate *entry* in-place: redact sensitive headers, query parameters, and
    cookie lists from both the request and response sections.
    """
    req = entry.get('request', {})
    req['headers']     = _sanitize_headers(req.get('headers', []))
    req['queryString'] = _sanitize_query(req.get('queryString', []))
    req['cookies']     = []   # cookies already captured in 'cookie' header above

    resp = entry.get('response', {})
    resp['headers'] = _sanitize_headers(resp.get('headers', []))


# ─── Filter helper ────────────────────────────────────────────────────────────

def _passes_filter(
    item_host:   str,
    item_method: str,
    item_status: str,
    filters:     Dict,
) -> bool:
    """
    Return True if the item passes all active filters (AND logic across types,
    OR logic within each type's value list).

    Parameters
    ----------
    item_host   : value of the XML <host> element, already lowercased
    item_method : value of the XML <method> element, already uppercased
    item_status : value of the XML <status> element as string
    filters     : dict with optional keys 'host', 'method', 'status',
                  each mapping to a list of normalised strings to match against
    """
    if 'host' in filters and item_host not in filters['host']:
        return False
    if 'method' in filters and item_method not in filters['method']:
        return False
    if 'status' in filters and item_status not in filters['status']:
        return False
    return True


# ─── Time helpers ─────────────────────────────────────────────────────────────

class HarTimeFormat:

    @staticmethod
    def timestampToHarTime(timestamp: float) -> str:
        """Convert a UNIX timestamp to HAR ISO-8601 format: '2021-05-02T11:38:56.000Z'."""
        return datetime.fromtimestamp(timestamp).isoformat(timespec='milliseconds') + 'Z'

    def transBsToHarTime(self, bs_timeformat: str) -> str:
        """
        Translate Burp Suite time format into HAR ISO-8601 format.

        Burp exports timestamps like 'Tue Apr 14 12:11:45 CEST 2026'.
        The timezone token varies (CST, CEST, EDT, BST, …) and Python's
        strptime does not parse arbitrary timezone abbreviations, so we
        strip it and parse the rest as local time.
        """
        parts = bs_timeformat.split()
        if len(parts) != 6:
            _warn(f"Unexpected time format '{bs_timeformat}', using current time")
            return self.getNowHarTime()
        # Remove the timezone abbreviation (index 4) before parsing
        t_no_tz = ' '.join(parts[:4] + [parts[5]])
        try:
            timestamp = time.mktime(time.strptime(t_no_tz, '%a %b %d %X %Y'))
        except ValueError:
            _warn(f"Could not parse time '{bs_timeformat}', using current time")
            return self.getNowHarTime()
        return self.timestampToHarTime(timestamp)

    def getNowHarTime(self) -> str:
        return self.timestampToHarTime(time.time())


# ─── HAR structure builders ───────────────────────────────────────────────────

class HarLogStructure:

    def constructEntryRequest(
        self,
        request_method: str,
        request_url: str,
        request_httpVersion: str,
        request_headers: List[Dict],
        request_queryString: List[Dict],
        request_cookies: List[Dict],
        request_headersSize: int,
        request_bodySize: int,
        request_postData: Optional[Dict] = None,
    ) -> Dict:
        req: Dict = {
            'method':      request_method,
            'url':         request_url,
            'httpVersion': request_httpVersion,
            'headers':     request_headers,
            'queryString': request_queryString,
            'cookies':     request_cookies,
            'headersSize': request_headersSize,
            'bodySize':    request_bodySize,
        }
        if request_postData is not None:
            req['postData'] = request_postData
        return req

    def constructEntryResponse(
        self,
        data_status: int,
        data_statusText: str,
        data_httpVersion: str,
        data_headers: List[Dict],
        data_content: Dict,
        data_headersSize: int,
        data_bodySize: int,
    ) -> Dict:
        return {
            'status':        data_status,
            'statusText':    data_statusText,
            'httpVersion':   data_httpVersion,
            'headers':       data_headers,
            'cookies':       [],
            'content':       data_content,
            'redirectURL':   '',
            'headersSize':   data_headersSize,
            'bodySize':      data_bodySize,
            '_transferSize': data_bodySize,
            '_error':        None,
        }

    def constructEntry(
        self,
        entry_resourceType: str,
        entry_request: Dict,
        entry_response: Dict,
        entry_serverIPAddress: Optional[str],
        entry_startedDateTime: str,
    ) -> Dict:
        return {
            '_initiator':      {'type': 'other'},
            '_priority':       'VeryHigh',
            '_resourceType':   entry_resourceType,
            'cache':           {},
            'pageref':         'page_1',
            'request':         entry_request,
            'response':        entry_response,
            'serverIPAddress': entry_serverIPAddress or '',
            'startedDateTime': entry_startedDateTime,
            'time':            0,
            'timings': {
                'send':    0,
                'wait':    0,
                'receive': 0,
            },
        }

    def constructHarLog(
        self,
        pages_startedDateTime: str,
        pages_title: str,
        entries: List[Dict],
    ) -> Dict:
        return {
            'log': {
                'version': '1.2',
                'creator': {
                    'name':    'burp2har',
                    'version': VERSION,
                },
                'pages': [
                    {
                        'startedDateTime': pages_startedDateTime,
                        'id':              'page_1',
                        'title':           pages_title,
                        'pageTimings':     {},
                    }
                ],
                'entries': entries,
            }
        }


# ─── Main converter ───────────────────────────────────────────────────────────

# Type alias for the source accepted by get_entries / iterparse
_Source = Union[str, 'os.PathLike[str]', io.BytesIO]


class HarLog(HarLogStructure):

    def __init__(self) -> None:
        super().__init__()

        # Content-types treated as plain text (stored as UTF-8 in HAR)
        self.plains = [
            'application/json',
            'application/javascript',
            'application/x-javascript',
            'application/manifest+json',
            'text/css',
            'text/html',
            'text/plain',
            'text/xml',
            'text/javascript',
        ]
        # Content-types treated as binary (base64-encoded in HAR)
        self.binaries = [
            'image/x-icon',
            'image/png',
            'image/gif',
            'image/jpeg',
            'image/webp',
            'image/svg+xml',
            'application/pdf',
            'application/octet-stream',
            'application/binary',
        ]
        # Extension -> mimeType fallback when Content-Type header is absent
        self.ext_mime = {
            'json':  'application/json',
            'js':    'application/javascript',
            'css':   'text/css',
            'html':  'text/html',
            'htm':   'text/html',
            'txt':   'text/plain',
            'xml':   'text/xml',
            'icon':  'image/x-icon',
            'ico':   'image/x-icon',
            'png':   'image/png',
            'gif':   'image/gif',
            'jpg':   'image/jpeg',
            'jpeg':  'image/jpeg',
            'webp':  'image/webp',
            'svg':   'image/svg+xml',
            'pdf':   'application/pdf',
            'mp4':   'video/mp4',
            'webm':  'video/webm',
            'mp3':   'audio/mpeg',
        }

    # ── Header parsing ────────────────────────────────────────────────────────

    @staticmethod
    def getHeadersList(headers_text: List[bytes]) -> List[Dict]:
        """
        Parse raw HTTP header lines (bytes) into HAR header dicts.
        Uses maxsplit=1 so header values that contain ': ' are preserved intact
        (important for headers like Content-Security-Policy).
        """
        headers_dict: List[Dict] = []
        for headers_item in headers_text:
            if not headers_item:
                continue
            parts = headers_item.split(b': ', 1)
            if len(parts) < 2:
                _warn(f"Skipping malformed header line: {headers_item[:80]!r}")
                continue
            headers_dict.append({
                'name':  parts[0].decode('utf-8', errors='replace').lower(),
                'value': parts[1].decode('utf-8', errors='replace'),
            })
        return headers_dict

    @staticmethod
    def getQueryList(url: str) -> List[Dict]:
        """Parse URL query string into a HAR queryString list."""
        query_list: List[Dict] = []
        try:
            for item in parse.parse_qsl(parse.urlparse(url).query):
                query_list.append({'name': item[0], 'value': parse.quote_plus(item[1])})
        except Exception as e:
            _warn(f"Could not parse query string from '{url}': {e}")
        return query_list

    @staticmethod
    def getCookiesList(cookiesText: str) -> List[Dict]:
        """Parse a Cookie header value into a HAR cookies list."""
        simple_cookie = cookies.SimpleCookie()
        cookiesList: List[Dict] = []
        if not cookiesText:
            return cookiesList
        try:
            simple_cookie.load(cookiesText)
            for name in simple_cookie:
                cookiesList.append({
                    'name':     name,
                    'value':    simple_cookie[name].value,
                    'expires':  None,
                    'httpOnly': False,
                    'secure':   False,
                })
        except Exception as e:
            _warn(f"Could not parse cookies '{cookiesText[:80]}': {e}")
        return cookiesList

    @staticmethod
    def getCookiesText(headers_list: List[Dict]) -> str:
        """Extract the raw Cookie header value from a headers list."""
        for item in headers_list:
            if item['name'] == 'cookie':
                return item['value']
        return ''

    @staticmethod
    def getDictValueByKey(dict_: List[Dict], key: str) -> Optional[str]:
        """Return the first part (before ';') of a header value by name."""
        for item in dict_:
            if item['name'] == key:
                return item['value'].split(';', 1)[0].strip()
        return None

    @staticmethod
    def getResourceType(extension: str) -> str:
        """Map a file extension to the HAR _resourceType label."""
        if extension in ('js',):
            return 'script'
        elif extension in ('css',):
            return 'stylesheet'
        elif extension in ('ico', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'):
            return 'image'
        elif extension in ('mp4', 'webm', 'mp3', 'ogg'):
            return 'media'
        elif extension in ('json',):
            return 'xhr'
        else:
            return 'document'

    @staticmethod
    def saveJsonFile(filename, data: Dict) -> None:
        with open(filename, 'w', encoding='utf-8') as fp:
            json.dump(data, fp, indent=2, ensure_ascii=False)

    @staticmethod
    def readFile(filename) -> str:
        with open(filename, 'r', encoding='utf-8') as fp:
            return fp.read()

    # ── Request parsing ───────────────────────────────────────────────────────

    def getRequestDict(self, item_request: str, item_url: str) -> Tuple:
        """
        Decode a base64-encoded Burp request and return a tuple of all fields
        needed by constructEntryRequest.
        """
        raw = b64decode(item_request)

        if b'\r\n\r\n' not in raw:
            _warn(f"Request for {item_url} has no header/body separator — treating as empty body")
            raw += b'\r\n\r\n'

        headers_items, body = raw.split(b'\r\n\r\n', 1)
        headers_items_split = headers_items.split(b'\r\n')
        first_line = headers_items_split[0]

        parts = first_line.split(b' ', 2)
        if len(parts) < 3:
            _warn(f"Malformed request line: {first_line!r}")
            parts = parts + [b''] * (3 - len(parts))

        method, _url, version = parts

        request_method      = method.decode('utf-8', errors='replace')
        request_url         = item_url
        request_httpVersion = version.decode('utf-8', errors='replace')
        request_headers     = self.getHeadersList(headers_items_split[1:])
        request_queryString = self.getQueryList(item_url)
        request_cookies     = self.getCookiesList(self.getCookiesText(request_headers))
        request_headersSize = len(headers_items) + 4  # +4 for \r\n\r\n separator
        request_bodySize    = len(body)

        # Build postData for requests with a non-empty body (POST, PUT, PATCH, etc.)
        post_data: Optional[Dict] = None
        if body:
            content_type = self.getDictValueByKey(request_headers, 'content-type') or ''
            post_data = {
                'mimeType': content_type,
                'text':     body.decode('utf-8', errors='replace'),
            }

        return (request_method, request_url, request_httpVersion,
                request_headers, request_queryString, request_cookies,
                request_headersSize, request_bodySize, post_data)

    # ── Response parsing ──────────────────────────────────────────────────────

    def makeResponseContent(
        self,
        body: bytes,
        content_type: Optional[str],
        item_extension: Optional[str],
    ) -> Dict:
        """
        Build the HAR 'content' object for a response body.

        Text types are stored as UTF-8 strings; binary types are base64-encoded;
        large media (video/audio) have their body omitted to avoid bloating the HAR.
        """
        responseContent: Dict = {
            'size':        len(body),
            'compression': 0,
        }

        # Normalise item_extension — Burp exports "null" as a literal string
        if not item_extension or item_extension == 'null':
            item_extension = None

        # Determine mimeType: prefer Content-Type header, fall back to extension
        mime = content_type or self.ext_mime.get(item_extension, 'application/octet-stream')
        responseContent['mimeType'] = mime

        if mime in self.plains:
            try:
                responseContent['text'] = body.decode('utf-8')
            except UnicodeDecodeError:
                # Fallback to base64 for mis-labelled binary content
                responseContent['text']     = b64encode(body).decode('utf-8')
                responseContent['encoding'] = 'base64'
        elif mime in self.binaries or (
            item_extension and item_extension in ('png', 'gif', 'jpg', 'jpeg', 'ico', 'pdf')
        ):
            responseContent['text']     = b64encode(body).decode('utf-8')
            responseContent['encoding'] = 'base64'
        elif mime.startswith('video/') or mime.startswith('audio/'):
            # Large media: skip embedding the body, record size via comment only
            responseContent['comment'] = f'Body not embedded ({len(body)} bytes, {mime})'
        else:
            # Unknown type — try UTF-8, fall back to base64
            try:
                responseContent['text'] = body.decode('utf-8')
            except UnicodeDecodeError:
                responseContent['text']     = b64encode(body).decode('utf-8')
                responseContent['encoding'] = 'base64'

        return responseContent

    def getResponseDict(self, item_response: Optional[str], item_extension: str) -> Tuple:
        """
        Decode a base64-encoded Burp response and return a tuple of all fields
        needed by constructEntryResponse.

        Missing or empty responses (ET.findtext returns '' for empty elements)
        are replaced with a synthetic HTTP/1.1 400 placeholder so the HAR entry
        remains structurally valid.
        """
        if not item_response:
            _warn("Response is missing — using synthetic 400 placeholder")
            item_response = b64encode(
                b'HTTP/1.1 400 \r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
            ).decode('utf-8')

        raw = b64decode(item_response)

        if b'\r\n\r\n' not in raw:
            _warn("Response has no header/body separator — treating as empty body")
            raw += b'\r\n\r\n'

        headers_items, body = raw.split(b'\r\n\r\n', 1)
        headers_items_split = headers_items.split(b'\r\n')
        first_line          = headers_items_split[0]
        headers_text        = headers_items_split[1:]

        parts = first_line.split(b' ', 2)
        if len(parts) < 3:
            _warn(f"Malformed response status line: {first_line!r}")
            parts = parts + [b''] * (3 - len(parts))

        httpVersion, status, statusText = parts

        try:
            data_status = int(status.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            _warn(f"Non-integer status code '{status!r}', defaulting to 0")
            data_status = 0

        data_httpVersion = httpVersion.decode('utf-8', errors='replace')
        data_statusText  = statusText.decode('utf-8', errors='replace')
        data_headers     = self.getHeadersList(headers_text)
        data_content     = self.makeResponseContent(
            body,
            self.getDictValueByKey(data_headers, 'content-type'),
            item_extension,
        )
        data_headersSize = len(headers_items) + 4
        data_bodySize    = len(body)

        return (data_status, data_statusText, data_httpVersion,
                data_headers, data_content, data_headersSize, data_bodySize)

    # ── Entry assembly (streaming) ────────────────────────────────────────────

    def get_entries(
        self,
        source: _Source,
        filters: Optional[Dict] = None,
        anonymize: bool = False,
    ) -> Tuple[List[Dict], int, int]:
        """
        Stream-parse <item> elements from *source* using iterparse.

        Items are processed one at a time.  After each item is handled,
        ``root_elem.clear()`` frees its memory so the DOM never grows beyond
        a single item, regardless of file size.

        Filters are applied before the expensive base64 decode, so filtered
        items incur almost no CPU cost.

        Parameters
        ----------
        source    : file path (str / Path) or io.BytesIO wrapping xml_text
        filters   : optional dict with keys 'host', 'method', 'status',
                    each a list of normalised strings (already lowercased /
                    uppercased by the caller)
        anonymize : when True, redact sensitive headers and query params

        Returns
        -------
        (entries, skipped, filtered_out)
          entries      — list of converted HAR entry dicts
          skipped      — items that failed to convert (missing request, errors)
          filtered_out — items excluded by active filters
        """
        entries: List[Dict] = []
        skipped      = 0
        filtered_out = 0
        item_count   = 0
        root_elem    = None

        # When source is BytesIO (pre-loaded xml_text), force UTF-8 parsing so
        # any <?xml encoding="..."?> declaration in the original file is ignored.
        if isinstance(source, io.BytesIO):
            parser = ET.XMLParser(encoding='utf-8')
        else:
            parser = None  # let iterparse read the encoding declaration from file

        try:
            ctx = ET.iterparse(source, events=('start', 'end'), parser=parser)
            for event, elem in ctx:
                # Capture the root element on first 'start' event
                if event == 'start' and root_elem is None:
                    root_elem = elem
                    continue

                if event != 'end' or elem.tag != 'item':
                    continue

                item_count += 1
                url = elem.findtext('url') or ''

                # ── Fast filter check (no base64 decode) ──────────────────────
                if filters:
                    item_host   = (elem.findtext('host')   or '').lower()
                    item_method = (elem.findtext('method') or '').upper()
                    item_status =  elem.findtext('status') or ''
                    if not _passes_filter(item_host, item_method, item_status, filters):
                        filtered_out += 1
                        if root_elem is not None:
                            root_elem.clear()
                        continue

                # ── Full processing ────────────────────────────────────────────
                try:
                    item_extension = elem.findtext('extension') or 'null'
                    item_request   = elem.findtext('request')
                    item_response  = elem.findtext('response')
                    host_node      = elem.find('host')
                    item_ip        = host_node.attrib.get('ip') if host_node is not None else None
                    item_time      = elem.findtext('time') or ''

                    if not item_request:
                        _warn(f"Item {item_count} ({url}): missing request, skipping")
                        skipped += 1
                    else:
                        if not item_response:
                            _warn(f"Item {item_count} ({url}): missing response — will use placeholder")

                        entry_resourceType = self.getResourceType(
                            item_extension if item_extension != 'null' else ''
                        )
                        entry_request = self.constructEntryRequest(
                            *self.getRequestDict(item_request, url)
                        )
                        entry_response = self.constructEntryResponse(
                            *self.getResponseDict(item_response, item_extension)
                        )
                        entry = self.constructEntry(
                            entry_resourceType,
                            entry_request,
                            entry_response,
                            item_ip,
                            HarTimeFormat().transBsToHarTime(item_time),
                        )

                        if anonymize:
                            _apply_anonymization(entry)

                        entries.append(entry)

                except Exception as exc:
                    _warn(f"Item {item_count} ({url}): unexpected error — {exc!r}, skipping")
                    skipped += 1

                finally:
                    # Free the item from the in-memory tree regardless of outcome
                    if root_elem is not None:
                        root_elem.clear()

        except ET.ParseError as exc:
            print(f"[burp2har] ERROR: XML parse failed — {exc}", file=sys.stderr)
            raise

        filter_note = f" ({filtered_out} filtered out)" if filtered_out else ""
        _log(f"Found {item_count} item(s) in XML{filter_note}")
        _log(
            f"Converted {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} "
            f"({skipped} skipped)"
        )
        return entries, skipped, filtered_out

    # ── Top-level ─────────────────────────────────────────────────────────────

    def getHarLog(
        self,
        source: _Source,
        filters: Optional[Dict] = None,
        anonymize: bool = False,
    ) -> Tuple[Dict, int, int]:
        """Build the full HAR log dict from *source*. Returns (har_log, skipped, filtered_out)."""
        entries, skipped, filtered_out = self.get_entries(
            source, filters=filters, anonymize=anonymize
        )
        now = HarTimeFormat().getNowHarTime()
        return self.constructHarLog(now, now, entries), skipped, filtered_out

    def generate_har(
        self,
        xml_path,
        result_path,
        xml_text:  Optional[str]  = None,
        filters:   Optional[Dict] = None,
        anonymize: bool           = False,
    ) -> Dict:
        """
        Convert *xml_path* to a HAR file written at *result_path*.

        Parameters
        ----------
        xml_path    : path to the Burp Suite XML export (used if xml_text is None)
        result_path : destination .har file path
        xml_text    : pre-read XML string — when provided the file is not re-read,
                      and the string is wrapped in BytesIO for streaming iterparse
        filters     : optional filter dict (see _passes_filter for schema)
        anonymize   : when True, apply _apply_anonymization to each entry

        Returns
        -------
        dict with keys: 'entries' (int), 'skipped' (int), 'filtered' (int)
        """
        if xml_text is not None:
            # Wrap the pre-loaded string as BytesIO so iterparse can stream it
            # without building a full DOM tree.
            source: _Source = io.BytesIO(xml_text.encode('utf-8'))
        else:
            # Stream directly from disk — most memory-efficient for large files.
            _log(f"Streaming XML from file: {xml_path}")
            source = xml_path

        har_log, skipped, filtered_out = self.getHarLog(
            source, filters=filters, anonymize=anonymize
        )

        self.saveJsonFile(result_path, har_log)
        _log(f"HAR written to: {result_path}")

        return {
            "entries":  len(har_log["log"]["entries"]),
            "skipped":  skipped,
            "filtered": filtered_out,
        }
