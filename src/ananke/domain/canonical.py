"""Canonical JSON serialization and SHA-256 digests for authority records.

Rules (canonicalization version ``ananke-cjson-1``; see docs/policy-spec.md section 6):

* Allowed value types: ``dict`` (keys must be ``str``), ``list``, ``str``, ``int``, ``bool``,
  ``None``. Floats are rejected outright (no unstable floats in authority records), as are
  tuples, sets, bytes and any other type.
* Integers must lie within the IEEE-754 safe range ``|n| <= 2**53 - 1`` so other languages can
  reproduce digests.
* Strings (values and keys) must already be Unicode NFC and must be encodable as UTF-8 (no lone
  surrogates). We reject instead of silently normalizing: silent normalization would let two
  distinct inputs share a digest.
* Output: UTF-8, object keys sorted by code point, no insignificant whitespace,
  non-ASCII emitted literally.

A digest is integrity evidence, not a signature and not proof of truth.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

CANONICALIZATION_VERSION = "ananke-cjson-1"
MAX_SAFE_INT = 2**53 - 1
MAX_DEPTH = 32


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonically serialized. Callers must fail closed."""


def _check_str(s: str, where: str) -> None:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"{where}: string is not valid UTF-8") from exc
    if unicodedata.normalize("NFC", s) != s:
        raise CanonicalizationError(f"{where}: string is not NFC-normalized")


def _validate(value: Any, path: str, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"{path}: nesting deeper than {MAX_DEPTH}")
    # bool must be checked before int (bool is a subclass of int).
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalizationError(f"{path}: integer outside safe range")
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"{path}: floats are not allowed in authority records")
    if isinstance(value, str):
        _check_str(value, path)
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _validate(item, f"{path}[{i}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object key {key!r} is not a string")
            _check_str(key, f"{path}.<key>")
            _validate(item, f"{path}.{key}", depth + 1)
        return
    raise CanonicalizationError(f"{path}: unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 encoding of ``value`` or raise CanonicalizationError."""
    _validate(value, "$", 0)
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def digest(value: Any) -> str:
    """Return ``"sha256:<hex>"`` over the canonical bytes of ``value``."""
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()
