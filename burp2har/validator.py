"""
XML compatibility validator for Burp Suite export files.

Distinguishes four states so the CLI can give actionable, targeted feedback:

  MALFORMED            : file cannot be parsed as XML at all
  INCOMPATIBLE         : valid XML that lacks the expected Burp structure,
                         or every <item> is missing all required fields
  PARTIALLY_COMPATIBLE : structure is present but some items are incomplete
  COMPATIBLE           : structure looks correct — conversion can proceed
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class CompatibilityStatus(Enum):
    COMPATIBLE           = "compatible"
    PARTIALLY_COMPATIBLE = "partially_compatible"
    INCOMPATIBLE         = "incompatible"
    MALFORMED            = "malformed"


@dataclass
class ValidationResult:
    status:      CompatibilityStatus
    message:     str = ""
    item_count:  int = 0
    valid_count: int = 0
    warnings:    List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when conversion can proceed (compatible or partially compatible)."""
        return self.status in (
            CompatibilityStatus.COMPATIBLE,
            CompatibilityStatus.PARTIALLY_COMPATIBLE,
        )


# Minimum sub-elements that every usable Burp item must have
_REQUIRED_FIELDS = ("url", "request")


def validate_xml(xml_text: str) -> ValidationResult:
    """
    Validate a Burp Suite XML export string and return a ValidationResult.

    The check is intentionally lightweight — it does not decode base64 bodies
    or deep-parse HTTP messages. Its sole purpose is to detect structural
    mismatches early, before the converter iterates over potentially thousands
    of entries.
    """

    # ── Step 1: basic XML parse ───────────────────────────────────────────────
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return ValidationResult(
            status=CompatibilityStatus.MALFORMED,
            message=f"XML is malformed — {exc}",
        )

    # ── Step 2: locate <item> elements ───────────────────────────────────────
    items = list(root.iter("item"))
    if not items:
        return ValidationResult(
            status=CompatibilityStatus.INCOMPATIBLE,
            message=(
                "No <item> elements found in the document. "
                "This does not appear to be a Burp Suite XML export."
            ),
        )

    # ── Step 3: inspect each item for required fields ─────────────────────────
    valid_count   = 0
    partial_count = 0
    warnings: List[str] = []

    for idx, item in enumerate(items):
        missing = [f for f in _REQUIRED_FIELDS if item.find(f) is None]
        if not missing:
            valid_count += 1
        elif len(missing) < len(_REQUIRED_FIELDS):
            partial_count += 1
            warnings.append(f"Item {idx}: missing field(s): {', '.join(missing)}")
        # else: item is completely empty — counted as broken below

    total  = len(items)
    broken = total - valid_count - partial_count

    if valid_count == 0 and partial_count == 0:
        return ValidationResult(
            status=CompatibilityStatus.INCOMPATIBLE,
            message=(
                f"Found {total} <item> element(s) but none contain the expected "
                f"fields ({', '.join(_REQUIRED_FIELDS)}). "
                "The XML format is not compatible with this version of the converter. "
                "Burp Suite may have updated its export format."
            ),
            item_count=total,
        )

    if valid_count == 0:
        return ValidationResult(
            status=CompatibilityStatus.PARTIALLY_COMPATIBLE,
            message=(
                f"{partial_count}/{total} items are partially compatible — "
                "none are fully valid."
            ),
            item_count=total,
            valid_count=0,
            warnings=warnings,
        )

    if partial_count > 0 or broken > 0:
        if broken:
            warnings.append(f"{broken} item(s) contain no recognized fields.")
        return ValidationResult(
            status=CompatibilityStatus.PARTIALLY_COMPATIBLE,
            message=(
                f"{valid_count}/{total} items fully valid, "
                f"{partial_count} partial, {broken} unrecognized."
            ),
            item_count=total,
            valid_count=valid_count,
            warnings=warnings,
        )

    return ValidationResult(
        status=CompatibilityStatus.COMPATIBLE,
        message=f"{total} items found, all valid.",
        item_count=total,
        valid_count=valid_count,
    )
