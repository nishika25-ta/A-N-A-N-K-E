import pytest
from pydantic import ValidationError

from ananke.domain import PolicyChange, PolicyEventKind, validate_text
from ananke.domain.identifiers import InvalidIdentifierError

BASE = {
    "kind": "GRANT",
    "rule_id": "grant-001",
    "principal_id": "agent-lab-01",
    "tool_id": "ticket",
    "operation": "read",
    "resource_scope": "ticket:demo-42",
    "valid_from": 0,
    "valid_until": 20,
}


def test_valid_grant_from_json_and_python() -> None:
    c = PolicyChange.model_validate(BASE)
    assert c.kind is PolicyEventKind.GRANT
    assert PolicyChange.model_validate_json(c.model_dump_json()) == c


@pytest.mark.parametrize(
    ("patch", "why"),
    [
        ({"valid_from": 1.0}, "float tick"),
        ({"valid_from": "0"}, "string tick"),
        ({"valid_from": -1}, "negative tick"),
        ({"valid_until": 0}, "valid_until == valid_from"),
        ({"requires_approval": "false"}, "string bool"),
        ({"requires_approval": 0}, "int bool"),
        ({"extra": 1}, "unknown field"),
        ({"schema_version": "ananke.policy/1"}, "unknown schema version"),
        ({"kind": "ESCALATE"}, "unknown kind"),
        ({"rule_id": None}, "missing rule_id"),
        ({"resource_scope": "ticket:*"}, "wildcard resource"),
        ({"principal_id": "Agent"}, "bad identifier"),
        ({"target_rule_id": "grant-000"}, "target on GRANT"),
        ({"reason": "ok‮gnp.exe"}, "bidi override in reason"),
        ({"reason": "x" * 201}, "reason too long"),
    ],
)
def test_grant_rejections(patch: dict[str, object], why: str) -> None:
    with pytest.raises(ValidationError):
        PolicyChange.model_validate({**BASE, **patch})


def test_deny_cannot_require_approval() -> None:
    with pytest.raises(ValidationError):
        PolicyChange.model_validate({**BASE, "kind": "DENY", "requires_approval": True})


def test_revoke_shape() -> None:
    ok = PolicyChange.model_validate({"kind": "REVOKE", "target_rule_id": "grant-001"})
    assert ok.rule_id is None
    for bad in (
        {"kind": "REVOKE"},
        {"kind": "REVOKE", "target_rule_id": "grant-001", "rule_id": "grant-002"},
        {"kind": "REVOKE", "target_rule_id": "grant-001", "tool_id": "ticket"},
        {"kind": "REVOKE", "target_rule_id": "grant-001", "requires_approval": True},
        {"kind": "REVOKE", "target_rule_id": "grant-001", "valid_until": 5},
    ):
        with pytest.raises(ValidationError):
            PolicyChange.model_validate(bad)


def test_supersede_shape() -> None:
    ok = PolicyChange.model_validate(
        {**BASE, "kind": "SUPERSEDE", "rule_id": "grant-002", "target_rule_id": "grant-001"}
    )
    assert ok.target_rule_id == "grant-001"
    with pytest.raises(ValidationError):
        PolicyChange.model_validate({**BASE, "kind": "SUPERSEDE"})  # no target
    with pytest.raises(ValidationError):
        PolicyChange.model_validate({**BASE, "kind": "SUPERSEDE", "target_rule_id": "grant-001"})


def test_models_are_immutable() -> None:
    c = PolicyChange.model_validate(BASE)
    with pytest.raises(ValidationError):
        c.rule_id = "other"  # type: ignore[misc]


@pytest.mark.parametrize("bad", ["a\x00b", "a​b", "a‮b", "é", ""])
def test_text_validator_rejects(bad: str) -> None:
    with pytest.raises(InvalidIdentifierError):
        validate_text(bad)


def test_text_validator_accepts_plain_unicode() -> None:
    assert validate_text("Révocation à 10 h") == "Révocation à 10 h"
