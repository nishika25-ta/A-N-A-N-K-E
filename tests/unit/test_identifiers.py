import pytest

from ananke.domain import InvalidIdentifierError, validate_identifier, validate_resource


@pytest.mark.parametrize(
    "ok", ["ticket:demo-42", "report:q3.summary", "artifact:A1_b2", "ticket-archive:x"]
)
def test_valid_resources(ok: str) -> None:
    assert validate_resource(ok) == ok


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "ticket",
        "ticket:",
        ":demo",
        "ticket:../demo",
        "ticket:demo..42",
        "ticket:*",
        "ticket:demo*",
        "ticket:demo?",
        "ticket:demo/42",
        "ticket:demo\\42",
        "ticket:demo 42",
        " ticket:demo",
        "ticket:demo%2F42",
        "Ticket:demo",
        "ticket:d\u0435mo",  # Cyrillic small ie homoglyph
        "ticket:demo-",
        "ticket:-demo",
        "ticket:demo:42",
        "/etc/passwd",
        "ticket:" + "a" * 200,
    ],
)
def test_rejects_ambiguous_resources(bad: str) -> None:
    with pytest.raises(InvalidIdentifierError):
        validate_resource(bad)


@pytest.mark.parametrize("ok", ["agent-lab-01", "grant-001", "ticket", "read", "publish_mock"])
def test_valid_identifiers(ok: str) -> None:
    assert validate_identifier(ok) == ok


@pytest.mark.parametrize("bad", ["", "Agent", "a b", "a--b", "-a", "a-", "1abc", "a.b", "a:b"])
def test_rejects_bad_identifiers(bad: str) -> None:
    with pytest.raises(InvalidIdentifierError):
        validate_identifier(bad)
