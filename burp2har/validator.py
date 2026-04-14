"""
XML compatibility validator for Burp Suite export files.

Distinguishes three failure modes so the CLI can give actionable feedback:
  - MALFORMED          : XML that cannot be parsed at all
  - INCOMPATIBLE       : valid XML that lacks the expected Burp structure
  - PARTIALLY_COMPATIBLE : items present but missing required sub-elements
  - COMPATIBLE         : structure looks correct, conversion can proceed
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class CompatibilityStatus(Enum):
    COMPATIBLE             = "compatible"
    PARTIALLY_COMPATIBLE   = "partially_compatible"
    INCOMPATIBLE           = "incompatible"
    MALFORMED              = "malformed"


@dataclass
class ValidationResult:
    status:     CompatibilityStatus
    message:    str = ""
    item_count: int = 0
    valid_count: int = 0
    warnings:   List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status in (
            CompatibilityStatus.COMPATIBLE,
            CompatibilityStatus.PARTIALLY_COMPATIBLE,
        )


# Required sub-elements that every valid Burp item must expose
_REQUIRED_FIELDS = ("url", "request")


def validate_xml(xml_text: str) -> ValidationResult:
    """
    Validate a Burp Suite XML export string and return a ValidationResult.

    The check is intentionally lightweight — it does not decode base64 bodies
    or deep-parse HTTP.  Its sole purpose is to detect structural mismatches
    early, before the converter tries to process thousands of entries.
    """

    # ── Step 1: basic XML parse ───────────────────────────────────────────────
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return ValidationResult(
            status=CompatibilityStatus.MALFORMED,
            message=f"XML malformato — {exc}",
        )

    # ── Step 2: locate <item> elements ───────────────────────────────────────
    items = list(root.iter("item"))
    if not items:
        return ValidationResult(
            status=CompatibilityStatus.INCOMPATIBLE,
            message=(
                "Nessun elemento <item> trovato nel documento XML. "
                "Il formato XML esportato da Burp Suite non è compatibile "
                "con questa versione del converter."
            ),
        )

    # ── Step 3: inspect item structure ───────────────────────────────────────
    valid_count   = 0
    partial_count = 0
    warnings: List[str] = []

    for idx, item in enumerate(items):
        missing = [f for f in _REQUIRED_FIELDS if item.find(f) is None]
        if not missing:
            valid_count += 1
        elif len(missing) < len(_REQUIRED_FIELDS):
            partial_count += 1
            warnings.append(
                f"Item {idx}: campo/i mancante/i: {', '.join(missing)}"
            )
        # else: totally empty item — counted below

    total = len(items)
    broken = total - valid_count - partial_count

    if valid_count == 0 and partial_count == 0:
        return ValidationResult(
            status=CompatibilityStatus.INCOMPATIBLE,
            message=(
                f"Trovati {total} elementi <item> ma nessuno contiene "
                f"i campi attesi ({', '.join(_REQUIRED_FIELDS)}). "
                "Il formato XML non è compatibile con questa versione del converter."
            ),
            item_count=total,
        )

    if valid_count == 0:
        return ValidationResult(
            status=CompatibilityStatus.PARTIALLY_COMPATIBLE,
            message=(
                f"{partial_count}/{total} item parzialmente compatibili, "
                "nessuno completamente valido."
            ),
            item_count=total,
            valid_count=0,
            warnings=warnings,
        )

    if partial_count > 0 or broken > 0:
        if broken:
            warnings.append(f"{broken} item privi di qualsiasi campo riconosciuto.")
        return ValidationResult(
            status=CompatibilityStatus.PARTIALLY_COMPATIBLE,
            message=(
                f"{valid_count}/{total} item completamente validi, "
                f"{partial_count} parziali, {broken} ignorati."
            ),
            item_count=total,
            valid_count=valid_count,
            warnings=warnings,
        )

    return ValidationResult(
        status=CompatibilityStatus.COMPATIBLE,
        message=f"{total} item trovati, tutti validi.",
        item_count=total,
        valid_count=valid_count,
    )
