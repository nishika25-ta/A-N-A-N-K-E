from __future__ import annotations

import pytest

from ananke.domain import GENESIS_HASH, PolicyChange, PolicyEvent, RuleStatus
from ananke.ledger import (
    EMPTY_STATE,
    PolicyState,
    PolicyTransitionError,
    TransitionError,
    apply_event,
    build_event,
    reduce_events,
)
from ananke_testkit import deny, grant, revoke, seq_ids, supersede

IDS = seq_ids()


def chain(changes: list[PolicyChange], ticks: list[int] | None = None) -> list[PolicyEvent]:
    state, events = EMPTY_STATE, []
    ticks = ticks or [0] * len(changes)
    for change, t in zip(changes, ticks, strict=True):
        e = build_event(state, change, event_id=IDS(), actor_id="op-admin", recorded_at=t)
        state = apply_event(state, e)
        events.append(e)
    return events


def test_empty_state() -> None:
    assert EMPTY_STATE.epoch == 0 and EMPTY_STATE.head_hash == GENESIS_HASH
    assert EMPTY_STATE.active_rules() == ()


def test_grant_revoke_regrant_lifecycle() -> None:
    events = chain([grant("grant-001"), revoke("grant-001"), grant("grant-002")], [0, 10, 12])
    s = reduce_events(events)
    assert s.epoch == 3 and s.last_sequence == 3 and s.head_hash == events[-1].event_hash
    assert s.rules["grant-001"].status is RuleStatus.REVOKED
    assert s.rules["grant-001"].retired_epoch == 2
    assert [r.rule_id for r in s.active_rules()] == ["grant-002"]


def test_supersede_narrows_and_links() -> None:
    events = chain(
        [
            grant("grant-001", res="ticket:demo-42"),
            supersede("grant-001", "grant-002", res="ticket:demo-43"),
        ]
    )
    s = reduce_events(events)
    old, new = s.rules["grant-001"], s.rules["grant-002"]
    assert old.status is RuleStatus.SUPERSEDED and old.replaced_by == "grant-002"
    assert new.status is RuleStatus.ACTIVE and new.resource_scope == "ticket:demo-43"


def test_supersede_keeps_effect_of_target() -> None:
    events = chain([deny("deny-001"), supersede("deny-001", "deny-002", res="ticket:demo-43")])
    s = reduce_events(events)
    assert s.rules["deny-002"].effect.value == "DENY"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ([grant("grant-001"), grant("grant-001")], TransitionError.RULE_ID_REUSED),
        (
            [grant("grant-001"), revoke("grant-001"), grant("grant-001")],
            TransitionError.RULE_ID_REUSED,
        ),
        ([revoke("grant-404")], TransitionError.TARGET_UNKNOWN),
        (
            [grant("grant-001"), revoke("grant-001"), revoke("grant-001")],
            TransitionError.TARGET_NOT_ACTIVE,
        ),
        (
            [grant("grant-001"), supersede("grant-001", "grant-002"), revoke("grant-001")],
            TransitionError.TARGET_NOT_ACTIVE,
        ),
        (
            [grant("grant-001"), supersede("grant-001", "grant-002", principal="agent-other")],
            TransitionError.SUPERSEDE_SCOPE_MISMATCH,
        ),
        (
            [
                grant("grant-001"),
                supersede("grant-001", "grant-002", tool="report", res="report:demo-q3"),
            ],
            TransitionError.SUPERSEDE_SCOPE_MISMATCH,
        ),
        (
            [deny("deny-001"), supersede("deny-001", "deny-002", approval=True)],
            TransitionError.DENY_REQUIRES_APPROVAL,
        ),
    ],
)
def test_invalid_transitions_rejected(changes: list[PolicyChange], code: TransitionError) -> None:
    with pytest.raises(PolicyTransitionError) as info:
        chain(changes)
    assert info.value.code is code


def _tamper(event: PolicyEvent, **update: object) -> PolicyEvent:
    return PolicyEvent.model_validate({**event.model_dump(mode="json"), **update})


def test_chain_checks() -> None:
    e1, e2 = chain([grant("grant-001"), grant("grant-002")], [5, 6])
    s1 = apply_event(EMPTY_STATE, e1)
    cases = {
        TransitionError.SEQUENCE_GAP: _tamper(e2, sequence=3),
        TransitionError.EPOCH_MISMATCH: _tamper(e2, epoch=5),
        TransitionError.PREV_HASH_MISMATCH: _tamper(e2, prev_hash="sha256:" + "1" * 64),
        TransitionError.EVENT_HASH_MISMATCH: _tamper(e2, reason="edited"),
        TransitionError.TIME_REGRESSION: build_event(
            PolicyState(1, 1, e1.event_hash, 0, s1.rules),
            grant("grant-002"),
            event_id=IDS(),
            actor_id="op-admin",
            recorded_at=4,
        ),
    }
    for code, bad in cases.items():
        with pytest.raises(PolicyTransitionError) as info:
            apply_event(s1, bad)
        assert info.value.code is code, code


def test_build_event_rejects_time_regression() -> None:
    (e1,) = chain([grant("grant-001")], [9])
    s1 = apply_event(EMPTY_STATE, e1)
    with pytest.raises(PolicyTransitionError) as info:
        build_event(s1, grant("grant-002"), event_id=IDS(), actor_id="op-admin", recorded_at=8)
    assert info.value.code is TransitionError.TIME_REGRESSION


def test_apply_event_does_not_mutate_input() -> None:
    e1, e2 = chain([grant("grant-001"), revoke("grant-001")])
    s1 = apply_event(EMPTY_STATE, e1)
    before = s1.state_digest()
    apply_event(s1, e2)
    assert s1.state_digest() == before
    assert s1.rules["grant-001"].status is RuleStatus.ACTIVE


def test_state_rules_mapping_is_read_only() -> None:
    s = reduce_events(chain([grant("grant-001")]))
    with pytest.raises(TypeError):
        s.rules["x"] = s.rules["grant-001"]  # type: ignore[index]


@pytest.mark.parametrize(("now", "inside"), [(4, False), (5, True), (9, True), (10, False)])
def test_validity_window_boundaries(now: int, inside: bool) -> None:
    s = reduce_events(chain([grant("grant-001", vf=5, vu=10)]))
    assert s.rules["grant-001"].in_validity_window(now) is inside


def test_unbounded_validity() -> None:
    s = reduce_events(chain([grant("grant-001", vf=3)]))
    assert not s.rules["grant-001"].in_validity_window(2)
    assert s.rules["grant-001"].in_validity_window(2**53 - 1)


def test_snapshot_digest_deterministic_and_epoch_sensitive() -> None:
    events = chain([grant("grant-001"), deny("deny-001", res="ticket:demo-43")])
    s = reduce_events(events)
    a, b = s.snapshot(7), reduce_events(events).snapshot(7)
    assert a == b and a.snapshot_digest == b.snapshot_digest
    assert s.snapshot(8).snapshot_digest != a.snapshot_digest
    assert [r.rule_id for r in a.active_rules] == ["deny-001", "grant-001"]


def test_event_hash_covers_every_field() -> None:
    (e,) = chain([grant("grant-001")])
    payload = e.hash_payload()
    assert set(payload) == set(PolicyEvent.model_fields) - {"event_hash"}
    for key in ("actor_id", "recorded_at", "valid_until", "requires_approval", "reason"):
        assert key in payload
