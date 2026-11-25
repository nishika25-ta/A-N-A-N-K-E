"""Synthetic identifier and resource validation (docs/policy-spec.md section 3).

MVP resources are synthetic identifiers such as ``ticket:demo-42``, never filesystem paths.
Matching is exact. Anything ambiguous is rejected (fail closed) rather than normalized.
"""

from __future__ import annotations

import re
import unicodedata

# Identifiers: principal_id, rule_id, tool_id, operation, session ids, etc.
_IDENT = re.compile(r"[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*")
# Resource: <namespace>:<name>. ASCII only, no '/', '\\', '..', '*', '?', whitespace, '%'.
_RESOURCE = re.compile(
    r"(?P<ns>[a-z][a-z0-9]*(?:-[a-z0-9]+)*)"
    r":(?P<name>[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)"
)
MAX_LEN = 128


class InvalidIdentifierError(ValueError):
    """Identifier or resource failed strict validation."""


def validate_identifier(value: str, kind: str = "identifier") -> str:
    if not isinstance(value, str) or not (1 <= len(value) <= MAX_LEN):
        raise InvalidIdentifierError(f"{kind}: must be a 1..{MAX_LEN} char string")
    if _IDENT.fullmatch(value) is None:
        raise InvalidIdentifierError(f"{kind}: {value!r} is not a valid lowercase identifier")
    return value


def validate_resource(value: str) -> str:
    """Validate an exact synthetic resource identifier ``namespace:name``."""
    if not isinstance(value, str) or not (3 <= len(value) <= MAX_LEN):
        raise InvalidIdentifierError(f"resource: must be a 3..{MAX_LEN} char string")
    if not value.isascii():
        raise InvalidIdentifierError("resource: non-ASCII characters are not allowed")
    if ".." in value:
        raise InvalidIdentifierError("resource: '..' is not allowed")
    if _RESOURCE.fullmatch(value) is None:
        raise InvalidIdentifierError(f"resource: {value!r} is not '<namespace>:<name>'")
    return value


MAX_TEXT_LEN = 200


def validate_text(value: str, max_len: int = MAX_TEXT_LEN) -> str:
    """Validate short free text (e.g. an operator reason).

    Must be NFC, at most ``max_len`` characters, and contain no control (Cc) or format (Cf)
    characters. Cf covers bidi overrides and zero-width characters used to disguise text.
    """
    if not isinstance(value, str) or len(value) > max_len:
        raise InvalidIdentifierError(f"text: must be a string of at most {max_len} characters")
    if unicodedata.normalize("NFC", value) != value:
        raise InvalidIdentifierError("text: must be NFC-normalized")
    for ch in value:
        if unicodedata.category(ch) in {"Cc", "Cf", "Cs", "Co", "Cn"}:
            raise InvalidIdentifierError(f"text: disallowed character U+{ord(ch):04X}")
    return value
