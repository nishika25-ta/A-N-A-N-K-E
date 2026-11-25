import json
import random
import unicodedata

from hypothesis import given, settings
from hypothesis import strategies as st

from ananke.domain import canonical_bytes, digest
from ananke.domain.canonical import MAX_SAFE_INT

nfc_text = st.text(max_size=12).filter(lambda s: unicodedata.is_normalized("NFC", s))
scalars = st.none() | st.booleans() | st.integers(-MAX_SAFE_INT, MAX_SAFE_INT) | nfc_text
json_values = st.recursive(
    scalars,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(nfc_text, children, max_size=4)
    ),
    max_leaves=20,
)


def _shuffle_keys(value: object, rng: random.Random) -> object:
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {k: _shuffle_keys(v, rng) for k, v in items}
    if isinstance(value, list):
        return [_shuffle_keys(v, rng) for v in value]
    return value


@settings(max_examples=300, deadline=None)
@given(json_values, st.integers(0, 2**32))
def test_digest_independent_of_key_insertion_order(value: object, seed: int) -> None:
    shuffled = _shuffle_keys(value, random.Random(seed))
    assert canonical_bytes(shuffled) == canonical_bytes(value)
    assert digest(shuffled) == digest(value)


@settings(max_examples=300, deadline=None)
@given(json_values)
def test_roundtrip(value: object) -> None:
    assert json.loads(canonical_bytes(value).decode("utf-8")) == value
