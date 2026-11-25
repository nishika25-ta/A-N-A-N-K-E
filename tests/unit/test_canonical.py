import hashlib
import json

import pytest

from ananke.domain import CanonicalizationError, canonical_bytes, digest


def test_sorted_compact_utf8() -> None:
    assert canonical_bytes({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'


def test_non_ascii_emitted_literally_as_utf8() -> None:
    assert canonical_bytes({"k": "é"}) == '{"k":"é"}'.encode()


def test_digest_matches_independent_sha256() -> None:
    value = {"z": 0, "a": "ticket:demo-42"}
    expected = hashlib.sha256(b'{"a":"ticket:demo-42","z":0}').hexdigest()
    assert digest(value) == "sha256:" + expected


def test_roundtrip_is_lossless() -> None:
    value = {"n": -(2**53 - 1), "l": [1, [2, {"x": False}]], "s": ""}
    assert json.loads(canonical_bytes(value)) == value


@pytest.mark.parametrize(
    "bad",
    [
        {"x": float("nan")},
        {"x": float("inf")},
        {"x": 1.0},  # floats rejected entirely
        {"x": 2**53},  # outside safe integer range
        {"x": (1, 2)},  # tuple
        {"x": {1, 2}},  # set
        {"x": b"bytes"},
        {1: "non-string key"},
        {"x": "é"},  # decomposed (not NFC)
        {"é": 1},  # non-NFC key
        {"x": "\ud800"},  # lone surrogate
    ],
)
def test_rejects_non_canonicalizable(bad: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_bytes(bad)


def test_rejects_excessive_depth() -> None:
    value: object = 0
    for _ in range(40):
        value = [value]
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


def test_bool_not_confused_with_int() -> None:
    assert digest({"x": True}) != digest({"x": 1})
