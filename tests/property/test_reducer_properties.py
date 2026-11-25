"""Property tests: determinism, replay equivalence, monotonicity, no resurrection."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ananke.domain import PolicyChange, PolicyEvent, RuleStatus
from ananke.ledger import (
    EMPTY_STATE,
    PolicyState,
    PolicyTransitionError,
    apply_event,
    build_event,
    reduce_events,
)

RULE_IDS = [f"rule-{i}" for i in range(10)]
PRINCIPALS = ["agent-a", "agent-b"]
TOOLS = ["ticket", "report"]
OPS = ["read", "update"]
RES = {"ticket": ["ticket:t1", "ticket:t2"], "report": ["report:r1"]}


@st.composite
def changes(draw: st.DrawFn) -> PolicyChange:
    kind = draw(st.sampled_from(["GRANT", "DENY", "REVOKE", "SUPERSEDE"]))
    if kind == "REVOKE":
        return PolicyChange(kind="REVOKE", target_rule_id=draw(st.sampled_from(RULE_IDS)))
    tool = draw(st.sampled_from(TOOLS))
    vf = draw(st.integers(0, 20))
    vu = draw(st.none() | st.integers(vf + 1, vf + 20))
    fields = dict(
        kind=kind,
        rule_id=draw(st.sampled_from(RULE_IDS)),
        principal_id=draw(st.sampled_from(PRINCIPALS)),
        tool_id=tool,
        operation=draw(st.sampled_from(OPS)),
        resource_scope=draw(st.sampled_from(RES[tool])),
        valid_from=vf,
        valid_until=vu,
        requires_approval=draw(st.booleans()) if kind != "DENY" else False,
    )
    if kind == "SUPERSEDE":
        target = draw(st.sampled_from(RULE_IDS))
        if target == fields["rule_id"]:
            return PolicyChange(kind="REVOKE", target_rule_id=target)
        fields["target_rule_id"] = target
    return PolicyChange(**fields)  # type: ignore[arg-type]


def _steer(state: PolicyState, c: PolicyChange, i: int) -> PolicyChange:
    """Retarget most REVOKE/SUPERSEDE changes onto active rules, scope-compatible.

    Every 4th change is left untouched so invalid-target and scope-mismatch paths stay covered.
    """
    active = state.active_rules()
    if c.kind.value not in ("REVOKE", "SUPERSEDE") or not active or i % 4 == 0:
        return c
    target = active[i % len(active)]
    data = c.model_dump()
    data["target_rule_id"] = target.rule_id
    if c.kind.value == "SUPERSEDE":
        if data["rule_id"] == target.rule_id:
            return PolicyChange(kind="REVOKE", target_rule_id=target.rule_id)
        data.update(
            principal_id=target.principal_id,
            tool_id=target.tool_id,
            resource_scope=RES[target.tool_id][i % len(RES[target.tool_id])],
        )
        if target.effect.value == "DENY":
            data["requires_approval"] = False
    return PolicyChange(**data)


def build_chain(cs: list[PolicyChange], ticks: list[int]) -> tuple[list[PolicyEvent], int]:
    """Build events for the accepted changes; return (events, rejected_count)."""
    state, events, rejected, t = EMPTY_STATE, [], 0, 0
    for i, c in enumerate(cs):
        t += ticks[i % len(ticks)]
        c = _steer(state, c, i)
        try:
            e = build_event(
                state,
                c,
                event_id=f"00000000-0000-0000-0000-{i:012x}",
                actor_id="op-admin",
                recorded_at=t,
            )
        except PolicyTransitionError:
            rejected += 1
            continue
        state = apply_event(state, e)
        events.append(e)
    return events, rejected


programs = st.tuples(st.lists(changes(), max_size=25), st.lists(st.integers(0, 3), min_size=1))


@settings(max_examples=250, deadline=None)
@given(programs)
def test_fold_equals_batch_and_is_deterministic(
    program: tuple[list[PolicyChange], list[int]],
) -> None:
    events, _ = build_chain(*program)
    folded: PolicyState = EMPTY_STATE
    for e in events:
        folded = apply_event(folded, e)
    batch = reduce_events(events)
    assert folded.state_digest() == batch.state_digest() == reduce_events(events).state_digest()


@settings(max_examples=250, deadline=None)
@given(programs, st.integers(0, 25))
def test_prefix_resume_equals_full_replay(
    program: tuple[list[PolicyChange], list[int]], cut: int
) -> None:
    events, _ = build_chain(*program)
    cut = min(cut, len(events))
    resumed = reduce_events(events[cut:], reduce_events(events[:cut]))
    assert resumed.state_digest() == reduce_events(events).state_digest()


@settings(max_examples=250, deadline=None)
@given(programs)
def test_epoch_counts_accepted_events_and_rules_never_resurrect(
    program: tuple[list[PolicyChange], list[int]],
) -> None:
    events, _ = build_chain(*program)
    state = EMPTY_STATE
    retired: set[str] = set()
    for e in events:
        state = apply_event(state, e)
        for rid, rule in state.rules.items():
            if rule.status is not RuleStatus.ACTIVE:
                retired.add(rid)
            else:
                assert rid not in retired, "a retired rule became active again"
    assert state.epoch == len(events) == state.last_sequence
    ids_created = [e.rule_id for e in events if e.rule_id is not None]
    assert len(ids_created) == len(set(ids_created)), "rule IDs must never be reused"


@settings(max_examples=150, deadline=None)
@given(programs, st.integers(0, 24), st.sampled_from(["reason", "valid_from", "kind"]))
def test_any_single_field_edit_is_detected(
    program: tuple[list[PolicyChange], list[int]], idx: int, field: str
) -> None:
    events, _ = build_chain(*program)
    if not events:
        return
    idx = idx % len(events)
    raw = events[idx].model_dump(mode="json")
    if field == "reason":
        raw["reason"] = raw["reason"] + "x"
    elif field == "valid_from" and raw["valid_from"] is not None:
        raw["valid_from"] = raw["valid_from"] + 1
        if raw["valid_until"] is not None and raw["valid_until"] <= raw["valid_from"]:
            raw["valid_until"] = raw["valid_from"] + 1
    else:
        raw["epoch"] = raw["epoch"] + 1
    tampered = list(events)
    tampered[idx] = PolicyEvent.model_validate(raw)
    if tampered[idx] == events[idx]:
        return
    try:
        reduce_events(tampered)
    except PolicyTransitionError:
        return
    raise AssertionError("tampered chain was accepted")
