"""
Custom exceptions for burp2har.
Using specific exception types allows callers to distinguish error categories
without parsing error message strings.
"""


class BurpHarError(Exception):
    """Base exception for all burp2har errors."""


class MalformedXMLError(BurpHarError):
    """Raised when the input file cannot be parsed as XML at all."""


class IncompatibleXMLError(BurpHarError):
    """Raised when the XML is valid but lacks the expected Burp Suite structure."""


class ConversionError(BurpHarError):
    """Raised when a recoverable error occurs during HAR entry construction."""


class UpdateError(BurpHarError):
    """Raised when the update check or installation step fails unrecoverably."""
