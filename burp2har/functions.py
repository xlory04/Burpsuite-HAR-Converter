from __future__ import annotations

import pathlib
from typing import Optional

from .harlog import HarLog


def burp2har_run(
    xml_path: pathlib.Path,
    result_path: pathlib.Path,
    xml_text: Optional[str] = None,
) -> Optional[dict]:
    """
    Convert *xml_path* to a HAR file at *result_path*.

    Parameters
    ----------
    xml_path    : path to the Burp Suite XML export
    result_path : destination .har file
    xml_text    : pre-read XML string (avoids a second disk read when the
                  caller already has the content, e.g. after validation)

    Returns
    -------
    dict with 'entries' and 'skipped' counts, or None on unexpected failure.
    """
    return HarLog().generate_har(xml_path, result_path, xml_text=xml_text)
