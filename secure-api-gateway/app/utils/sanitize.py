"""
Input sanitization utilities.

Defense-in-depth: even with Pydantic validation on models, we provide
standalone sanitizers for cases where raw strings arrive outside of
a Pydantic model (e.g. query parameters, path segments).
"""

from __future__ import annotations

import re


def strip_dangerous_chars(value: str) -> str:
    """Remove null bytes and control characters that can confuse parsers."""
    # Null byte injection is a classic attack against C-backed libraries
    value = value.replace("\x00", "")
    # Strip ASCII control chars except common whitespace
    return re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)


def is_safe_identifier(value: str) -> bool:
    """Check that a string is a safe alphanumeric identifier."""
    return bool(re.match(r"^[a-zA-Z0-9_]+$", value))
