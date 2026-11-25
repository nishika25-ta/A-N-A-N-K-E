from __future__ import annotations

import pytest

from ananke.domain import PolicyChange, ReasonCode
from ananke.ledger import EMPTY_STATE, PolicyState, apply_event, build_event
from ananke.policy import evaluate
from ananke_testkit import AGENT, deny, grant, revoke, seq_ids, supersede

IDS = seq_ids(11)


def state_of(*changes: PolicyChange) -> PolicyState:
    s = EMPTY_STATE
    for c in changes:
        s = apply_event(s, build_event(s, c, event_id=IDS(), actor_id="op", recorded_at=0))
    return s


def ev(
    s: PolicyState,
    now: int = 5,
    *,
    principal: str = AGENT,
    tool: str = "ticket",
    op: str = "read",
    res: str = "ticket:demo-42",
):
    return evaluate(s, principal_id=principal, tool_id=tool, operation=op, resource=res, now=now)


def test_default_deny_on_empty_policy() -> None:
    v = ev(EMPTY_STATE)
    assert (v.permitted, v.reason, v.matched_rule_ids) == (False, ReasonCode.NO_MATCHING_GRANT, ())


def test_grant_allows_exact_match_only() -> None:
    s = state_of(grant("g1"))
    assert ev(s).permitted
    for kw in (
        {"principal": "agent-other"},
        {"tool": "report", "res": "report:demo-42"},
        {"op": "update"},
        {"res": "ticket:demo-420"},
        {"res": "ticket:demo-4"},
    ):
        assert ev(s, **kw).reason is ReasonCode.NO_MATCHING_GRANT, kw


def test_deny_wins_over_grant_regardless_of_order() -> None:
    for s in (state_of(grant("g1"), deny("d1")), state_of(deny("d1"), grant("g1"))):
        v = ev(s)
        assert (v.permitted, v.reason, v.matched_rule_ids) == (
            False,
            ReasonCode.EXPLICIT_DENY,
            ("d1",),
        )


def test_expired_deny_no_longer_blocks() -> None:
    s = state_of(grant("g1"), deny("d1", vu=3))
    assert ev(s, now=2).reason is ReasonCode.EXPLICIT_DENY
    assert ev(s, now=3).permitted


@pytest.mark.parametrize(
    ("now", "reason"),
    [
        (4, ReasonCode.NO_MATCHING_GRANT),  # not yet valid
        (5, ReasonCode.ALLOWED),
        (9, ReasonCode.ALLOWED),
        (10, ReasonCode.GRANT_EXPIRED),  # valid_until is exclusive
        (99, ReasonCode.GRANT_EXPIRED),
    ],
)
def test_expiry_boundaries(now: int, reason: ReasonCode) -> None:
    assert ev(state_of(grant("g1", vf=5, vu=10)), now=now).reason is reason


def test_revoked_and_superseded_report_grant_revoked() -> None:
    assert ev(state_of(grant("g1"), revoke("g1"))).reason is ReasonCode.GRANT_REVOKED
    s = state_of(grant("g1"), supersede("g1", "g2", res="ticket:demo-43"))
    v = ev(s)
    assert (v.reason, v.matched_rule_ids) == (ReasonCode.GRANT_REVOKED, ("g1",))
    assert ev(s, res="ticket:demo-43").permitted  # narrowed scope works


def test_revoked_takes_precedence_over_expired_in_diagnostics() -> None:
    s = state_of(grant("g1", vu=3), grant("g2"), revoke("g2"))
    assert ev(s, now=4).reason is ReasonCode.GRANT_REVOKED


def test_regrant_with_new_id_restores_access() -> None:
    s = state_of(grant("g1"), revoke("g1"), grant("g2"))
    v = ev(s)
    assert v.permitted and v.matched_rule_ids == ("g2",)


def test_approval_required_if_any_applicable_grant_requires_it() -> None:
    s = state_of(grant("g1"), grant("g2", approval=True))
    v = ev(s)
    assert v.permitted and v.approval_required and v.matched_rule_ids == ("g1", "g2")
    assert not ev(state_of(grant("g1"))).approval_required


def test_revoked_deny_does_not_block_and_is_not_reported() -> None:
    s = state_of(grant("g1"), deny("d1"), revoke("d1"))
    assert ev(s).permitted
    assert ev(state_of(deny("d1"), revoke("d1"))).reason is ReasonCode.NO_MATCHING_GRANT


def test_evaluation_is_pure() -> None:
    s = state_of(grant("g1"))
    before = s.state_digest()
    for now in range(10):
        ev(s, now=now)
    assert s.state_digest() == before
