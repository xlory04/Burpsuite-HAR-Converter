"""
HAR file validator for burp2har.

Distinguishes three states so the CLI can give actionable, targeted feedback:

  VALID               : file passes all structural checks
  VALID_WITH_WARNINGS : structurally sound but has non-critical issues
  INVALID             : JSON is malformed or required HAR fields are absent

Design note
-----------
HAR files produced by this project must never be marked INVALID due to this
validator.  Optional fields (timings, serverIPAddress, cache, etc.) are
intentionally not checked.  The only warnings that may fire against
burp2har-generated output are for genuine data-quality artefacts inherited
from the source Burp XML (e.g. status code 0 when Burp omitted the status
line, or missing response when Burp did not capture one).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple


# Maximum per-category issues to collect before stopping per-entry iteration.
# Avoids unbounded output for pathological files.
_MAX_ERRORS   = 50
_MAX_WARNINGS = 50

# HTTP methods that are expected to carry a request body.
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


# ─── Result types ─────────────────────────────────────────────────────────────

class HarValidationStatus(Enum):
    VALID               = "valid"
    VALID_WITH_WARNINGS = "valid_with_warnings"
    INVALID             = "invalid"


@dataclass
class HarValidationResult:
    status:      HarValidationStatus
    message:     str       = ""
    entry_count: int       = 0
    errors:      List[str] = field(default_factory=list)
    warnings:    List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True for VALID and VALID_WITH_WARNINGS (exit code 0)."""
        return self.status != HarValidationStatus.INVALID


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _check_headers(headers: object, location: str) -> Tuple[List[str], List[str]]:
    """
    Validate a HAR headers array.

    Each element must be an object containing both 'name' and 'value'.
    An absent or non-list headers field is an error; an empty list is not.

    Returns (errors, warnings).
    """
    errors:   List[str] = []
    warnings: List[str] = []

    if not isinstance(headers, list):
        errors.append(
            f"{location}: 'headers' must be a list, got {type(headers).__name__}"
        )
        return errors, warnings

    for i, h in enumerate(headers):
        if not isinstance(h, dict):
            errors.append(f"{location}.headers[{i}]: must be an object")
            continue
        if "name" not in h:
            errors.append(f"{location}.headers[{i}]: missing 'name'")
        if "value" not in h:
            errors.append(f"{location}.headers[{i}]: missing 'value'")

    return errors, warnings


def _check_entry(idx: int, entry: object) -> Tuple[List[str], List[str]]:
    """
    Validate a single HAR entry object.

    Hard errors (structural):
    - entry is not an object
    - missing startedDateTime
    - missing / non-object request or response
    - request missing method or url
    - response missing status, or status is not numeric
    - malformed header objects (missing name / value)

    Warnings (non-fatal):
    - response.status == 0  (parsing artefact)
    - response.status outside 100–599
    - body-method (POST/PUT/PATCH) with bodySize > 0 but no postData
    - response.content present but mimeType missing or empty

    Returns (errors, warnings).
    """
    errors:   List[str] = []
    warnings: List[str] = []
    loc = f"entries[{idx}]"

    if not isinstance(entry, dict):
        errors.append(f"{loc}: must be an object, got {type(entry).__name__}")
        return errors, warnings

    # ── startedDateTime ───────────────────────────────────────────────────────
    if "startedDateTime" not in entry:
        errors.append(f"{loc}: missing 'startedDateTime'")

    # ── request ───────────────────────────────────────────────────────────────
    req = entry.get("request")
    if req is None:
        errors.append(f"{loc}: missing 'request'")
    elif not isinstance(req, dict):
        errors.append(f"{loc}.request: must be an object, got {type(req).__name__}")
    else:
        if "method" not in req:
            errors.append(f"{loc}.request: missing 'method'")
        if "url" not in req:
            errors.append(f"{loc}.request: missing 'url'")

        if "headers" in req:
            e, w = _check_headers(req["headers"], f"{loc}.request")
            errors.extend(e)
            warnings.extend(w)

        # Warn when a body-method declares a non-zero body but omits postData.
        method    = req.get("method", "").upper()
        body_size = req.get("bodySize")
        if (
            method in _BODY_METHODS
            and isinstance(body_size, (int, float))
            and body_size > 0
            and "postData" not in req
        ):
            warnings.append(
                f"{loc}.request: {method} with bodySize={int(body_size)}"
                " but 'postData' is absent"
            )

    # ── response ──────────────────────────────────────────────────────────────
    resp = entry.get("response")
    if resp is None:
        errors.append(f"{loc}: missing 'response'")
    elif not isinstance(resp, dict):
        errors.append(f"{loc}.response: must be an object, got {type(resp).__name__}")
    else:
        status = resp.get("status")
        if status is None:
            errors.append(f"{loc}.response: missing 'status'")
        elif not isinstance(status, (int, float)):
            errors.append(
                f"{loc}.response.status: must be numeric,"
                f" got {type(status).__name__}"
            )
        else:
            status_int = int(status)
            if status_int == 0:
                warnings.append(
                    f"{loc}.response.status: 0 — likely a parsing artefact"
                    " (Burp XML missing status line)"
                )
            elif not (100 <= status_int <= 599):
                warnings.append(
                    f"{loc}.response.status: {status_int} is outside"
                    " the valid HTTP 1xx–5xx range"
                )

        if "headers" in resp:
            e, w = _check_headers(resp["headers"], f"{loc}.response")
            errors.extend(e)
            warnings.extend(w)

        content = resp.get("content")
        if isinstance(content, dict):
            mime = content.get("mimeType", "")
            if not mime:
                warnings.append(
                    f"{loc}.response.content: 'mimeType' is missing or empty"
                )

    return errors, warnings


# ─── Public API ───────────────────────────────────────────────────────────────

def validate_har(har_text: str) -> HarValidationResult:
    """
    Validate a HAR file given as a string and return a HarValidationResult.

    The check covers JSON validity, the mandatory HAR top-level structure, and
    per-entry required fields.  Optional fields (timings, cache, pages, etc.)
    are not checked so that valid HAR files from any generator are accepted.

    Parameters
    ----------
    har_text : raw UTF-8 text content of the .har file

    Returns
    -------
    HarValidationResult with status, message, errors, and warnings.
    """

    # ── Step 1: JSON validity ─────────────────────────────────────────────────
    try:
        data = json.loads(har_text)
    except json.JSONDecodeError as exc:
        return HarValidationResult(
            status=HarValidationStatus.INVALID,
            message=f"File is not valid JSON — {exc}",
        )

    if not isinstance(data, dict):
        return HarValidationResult(
            status=HarValidationStatus.INVALID,
            message=(
                f"Top-level JSON value must be an object,"
                f" got {type(data).__name__}"
            ),
        )

    # ── Step 2: mandatory top-level HAR structure ─────────────────────────────
    log = data.get("log")
    if log is None:
        return HarValidationResult(
            status=HarValidationStatus.INVALID,
            message="Missing required top-level key 'log'",
        )
    if not isinstance(log, dict):
        return HarValidationResult(
            status=HarValidationStatus.INVALID,
            message=f"'log' must be an object, got {type(log).__name__}",
        )

    structural_errors: List[str] = []
    for key in ("version", "creator", "entries"):
        if key not in log:
            structural_errors.append(f"log: missing required key '{key}'")

    if structural_errors:
        return HarValidationResult(
            status=HarValidationStatus.INVALID,
            message="Missing required fields in 'log' object.",
            errors=structural_errors,
        )

    entries = log["entries"]
    if not isinstance(entries, list):
        return HarValidationResult(
            status=HarValidationStatus.INVALID,
            message=(
                f"'log.entries' must be a list, got {type(entries).__name__}"
            ),
        )

    # ── Step 3: per-entry structural checks ───────────────────────────────────
    all_errors:   List[str] = []
    all_warnings: List[str] = []
    entry_count = len(entries)

    for idx, entry in enumerate(entries):
        # Stop collecting once both caps are hit — no point iterating further.
        if len(all_errors) >= _MAX_ERRORS and len(all_warnings) >= _MAX_WARNINGS:
            break
        e_errors, e_warnings = _check_entry(idx, entry)
        all_errors.extend(e_errors)
        all_warnings.extend(e_warnings)

    # ── Step 4: determine final status ───────────────────────────────────────
    if all_errors:
        n = len(all_errors)
        return HarValidationResult(
            status=HarValidationStatus.INVALID,
            message=(
                f"{n} structural error{'s' if n != 1 else ''} found"
                f" across {entry_count} entries."
            ),
            entry_count=entry_count,
            errors=all_errors,
            warnings=all_warnings,
        )

    if all_warnings:
        n = len(all_warnings)
        return HarValidationResult(
            status=HarValidationStatus.VALID_WITH_WARNINGS,
            message=(
                f"{entry_count} entries — "
                f"{n} warning{'s' if n != 1 else ''}."
            ),
            entry_count=entry_count,
            warnings=all_warnings,
        )

    return HarValidationResult(
        status=HarValidationStatus.VALID,
        message=f"{entry_count} entries — all checks passed.",
        entry_count=entry_count,
    )
