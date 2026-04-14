from __future__ import annotations

import json
import sys
import time
import xml.etree.ElementTree as ET
from base64 import b64decode, b64encode
from datetime import datetime
from http import cookies
from typing import Optional
from urllib import parse

from .config import VERSION


# ─── Logging helpers ──────────────────────────────────────────────────────────

def _log(msg):
    print(f"[bpi2har] {msg}", file=sys.stderr)

def _warn(msg):
    print(f"[bpi2har] WARNING: {msg}", file=sys.stderr)


# ─── Time helpers ─────────────────────────────────────────────────────────────

class HarTimeFormat:

    @staticmethod
    def timestampToHarTime(timestamp):
        # '2021-05-02T11:38:56.000Z'
        return datetime.fromtimestamp(timestamp).isoformat(timespec='milliseconds') + 'Z'

    def transBsToHarTime(self, bs_timeformat):
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

    def getNowHarTime(self):
        return self.timestampToHarTime(time.time())


# ─── HAR structure builders ───────────────────────────────────────────────────

class HarLogStructure:

    def constructEntryRequest(self, request_method, request_url, request_httpVersion,
            request_headers, request_queryString, request_cookies,
            request_headersSize, request_bodySize, request_postData=None):
        req = {
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

    def constructEntryResponse(self, data_status, data_statusText, data_httpVersion,
            data_headers, data_content, data_headersSize, data_bodySize):
        return {
            'status':      data_status,
            'statusText':  data_statusText,
            'httpVersion': data_httpVersion,
            'headers':     data_headers,
            'cookies':     [],
            'content':     data_content,
            'redirectURL': '',
            'headersSize': data_headersSize,
            'bodySize':    data_bodySize,
            '_transferSize': data_bodySize,
            '_error': None,
        }

    def constructEntry(self, entry_resourceType, entry_request, entry_response,
            entry_serverIPAddress, entry_startedDateTime):
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

    def constructHarLog(self, pages_startedDateTime, pages_title, entries):
        return {
            'log': {
                'version': '1.2',
                'creator': {
                    'name':    'bpi2har',
                    'version': VERSION,
                },
                'pages': [
                    {
                        'startedDateTime': pages_startedDateTime,
                        'id':    'page_1',
                        'title': pages_title,
                        'pageTimings': {},
                    }
                ],
                'entries': entries,
            }
        }


# ─── Main converter ───────────────────────────────────────────────────────────

class HarLog(HarLogStructure):

    def __init__(self):
        super(HarLog, self).__init__()

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
        # Extension → mimeType fallback when Content-Type header is absent
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
    def getHeadersList(headers_text):
        """
        Parse raw HTTP header lines (bytes) into HAR header dicts.
        Uses maxsplit=1 so header values that contain ': ' are preserved intact.
        """
        headers_dict = []
        for headers_item in headers_text:
            if not headers_item:
                continue
            # maxsplit=1 prevents truncating values that contain ': '
            parts = headers_item.split(b': ', 1)
            if len(parts) < 2:
                # header line without a ': ' separator — skip silently
                _warn(f"Skipping malformed header line: {headers_item[:80]!r}")
                continue
            headers_dict.append({
                'name':  parts[0].decode('utf-8', errors='replace').lower(),
                'value': parts[1].decode('utf-8', errors='replace'),
            })
        return headers_dict

    @staticmethod
    def getQueryList(url):
        query_list = []
        try:
            for item in parse.parse_qsl(parse.urlparse(url).query):
                query_list.append({'name': item[0], 'value': parse.quote_plus(item[1])})
        except Exception as e:
            _warn(f"Could not parse query string from '{url}': {e}")
        return query_list

    @staticmethod
    def getCookiesList(cookiesText):
        simple_cookie = cookies.SimpleCookie()
        cookiesList = []
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
    def getCookiesText(headers_list):
        for item in headers_list:
            if item['name'] == 'cookie':
                return item['value']
        return ''

    @staticmethod
    def getDictValueByKey(dict_, key):
        """Return the first part (before ';') of a header value by name."""
        for item in dict_:
            if item['name'] == key:
                return item['value'].split(';', 1)[0].strip()
        return None

    @staticmethod
    def getResourceType(extension):
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
    def saveJsonFile(filename, data):
        with open(filename, 'w', encoding='utf-8') as fp:
            json.dump(data, fp, indent=2, ensure_ascii=False)

    @staticmethod
    def readFile(filename):
        with open(filename, 'r', encoding='utf-8') as fp:
            return fp.read()

    # ── Request parsing ───────────────────────────────────────────────────────

    def getRequestDict(self, item_request, item_url):
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
        request_headersSize = len(headers_items) + 4  # +4 for \r\n\r\n
        request_bodySize    = len(body)

        # Build postData for requests with a body (e.g. POST, PUT, PATCH)
        post_data = None
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

    def makeResponseContent(self, body, content_type, item_extension):
        responseContent = {
            'size':        len(body),
            'compression': 0,
        }

        # Normalise item_extension — Burp exports "null" as a literal string
        if not item_extension or item_extension == 'null':
            item_extension = None

        # Determine mimeType: prefer Content-Type header, fall back to extension
        mime = content_type or self.ext_mime.get(item_extension, 'application/octet-stream')
        responseContent['mimeType'] = mime

        # Decide how to encode the body
        if mime in self.plains:
            try:
                responseContent['text'] = body.decode('utf-8')
            except UnicodeDecodeError:
                # Fallback to base64 for mis-labelled binary content
                responseContent['text']     = b64encode(body).decode('utf-8')
                responseContent['encoding'] = 'base64'
        elif mime in self.binaries or (item_extension and item_extension in ('png', 'gif', 'jpg', 'jpeg', 'ico', 'pdf')):
            responseContent['text']     = b64encode(body).decode('utf-8')
            responseContent['encoding'] = 'base64'
        elif mime.startswith('video/') or mime.startswith('audio/'):
            # Large media: skip embedding body, record size only
            responseContent['comment'] = f'Body not embedded ({len(body)} bytes, {mime})'
        else:
            # Unknown type — try UTF-8, fall back to base64
            try:
                responseContent['text'] = body.decode('utf-8')
            except UnicodeDecodeError:
                responseContent['text']     = b64encode(body).decode('utf-8')
                responseContent['encoding'] = 'base64'

        return responseContent

    def getResponseDict(self, item_response, item_extension):
        # Missing response → synthesise a minimal 400 placeholder
        # Note: ET.findtext() returns '' (empty str) for elements with no text,
        # so we must check for both None and empty string here.
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

    # ── Entry assembly ────────────────────────────────────────────────────────

    def get_entries(self, xml_text):
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            print(f"[bpi2har] ERROR: XML parse failed — {e}", file=sys.stderr)
            raise

        all_items = list(root.iter('item'))
        _log(f"Found {len(all_items)} item(s) in XML")

        entries = []
        skipped = 0

        for idx, item in enumerate(all_items):
            url = item.findtext('url') or ''
            try:
                item_extension    = item.findtext('extension') or 'null'
                item_url          = url
                item_request      = item.findtext('request')
                item_response     = item.findtext('response')
                item_ip           = item.find('host').attrib.get('ip') if item.find('host') is not None else None
                item_time         = item.findtext('time') or ''

                if not item_request:
                    _warn(f"Item {idx} ({url}): missing request, skipping")
                    skipped += 1
                    continue

                if not item_response:
                    _warn(f"Item {idx} ({url}): missing response — will use placeholder")

                entry_resourceType    = self.getResourceType(item_extension if item_extension != 'null' else '')
                entry_request         = self.constructEntryRequest(*self.getRequestDict(item_request, item_url))
                entry_response        = self.constructEntryResponse(*self.getResponseDict(item_response, item_extension))
                entry_serverIPAddress = item_ip
                entry_startedDateTime = HarTimeFormat().transBsToHarTime(item_time)

                entry = self.constructEntry(
                    entry_resourceType, entry_request, entry_response,
                    entry_serverIPAddress, entry_startedDateTime,
                )
                entries.append(entry)

            except Exception as e:
                _warn(f"Item {idx} ({url}): unexpected error — {e!r}, skipping")
                skipped += 1
                continue

        _log(f"Converted {len(entries)} entr{'y' if len(entries)==1 else 'ies'} "
             f"({skipped} skipped)")
        return entries, skipped

    # ── Top-level ─────────────────────────────────────────────────────────────

    def getHarLog(self, xml_text):
        entries, skipped = self.get_entries(xml_text)
        now = HarTimeFormat().getNowHarTime()
        return self.constructHarLog(now, now, entries), skipped

    def generate_har(
        self,
        xml_path,
        result_path,
        xml_text: Optional[str] = None,
    ) -> dict:
        """
        Convert *xml_path* to a HAR file at *result_path*.

        If *xml_text* is provided (e.g. already read by the CLI for validation),
        the file is not read a second time.

        Returns a dict with conversion stats: {'entries': int, 'skipped': int}.
        """
        if xml_text is None:
            _log(f"Reading XML: {xml_path}")
            xml_text = self.readFile(xml_path)
            _log(f"Loaded {len(xml_text):,} bytes")

        har_log, skipped = self.getHarLog(xml_text)

        self.saveJsonFile(result_path, har_log)
        _log(f"HAR written to: {result_path}")

        return {"entries": len(har_log["log"]["entries"]), "skipped": skipped}
