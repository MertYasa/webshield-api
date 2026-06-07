# src/api/validators.py
"""URL validation helpers for the WebShield API."""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Maximum URL length accepted by the API
MAX_URL_LENGTH = 2048

# Only these schemes are analysed
ALLOWED_SCHEMES = {"http", "https"}

# Simple check for obviously malformed URLs (no host after scheme)
_NO_HOST_RE = re.compile(r"^https?://\s*$", re.IGNORECASE)


class URLValidationError(ValueError):
    """Raised when a URL fails validation checks."""


def validate_url(url: str) -> str:
    """
    Validate and lightly normalise an incoming URL.

    Returns the stripped URL on success.
    Raises URLValidationError with a human-readable message on failure.
    """
    if not isinstance(url, str):
        raise URLValidationError("URL must be a string.")

    url = url.strip()

    if not url:
        raise URLValidationError("URL must not be empty.")

    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError(
            f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."
        )

    # Require a scheme so urlparse works reliably
    if "://" not in url:
        raise URLValidationError(
            "URL must include a scheme (http:// or https://)."
        )

    try:
        parsed = urlparse(url)
    except Exception:
        raise URLValidationError("URL could not be parsed.")

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise URLValidationError(
            f"Unsupported scheme '{parsed.scheme}'. Only http and https are accepted."
        )

    if not parsed.netloc or _NO_HOST_RE.match(url):
        raise URLValidationError("URL does not contain a valid host.")

    return url


def sanitize_url_for_logging(url: str) -> str:
    """
    Mask query parameters in a URL to prevent logging PII.
    E.g. https://example.com/path?token=123 -> https://example.com/path?***
    """
    if not isinstance(url, str):
        return ""
    try:
        parsed = urlparse(url)
        if parsed.query:
            # Reconstruct URL without query string, but indicate it was there
            safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?***"
            if parsed.fragment:
                safe_url += f"#{parsed.fragment}"
            return safe_url
        return url
    except Exception:
        return "<invalid-url>"
