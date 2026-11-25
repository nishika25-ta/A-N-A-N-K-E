"""The independent oracle on hand-built timelines (it never sees the evaluator)."""

from __future__ import annotations

from ananke.bench.oracle import ScenarioOracle, Verdict
from ananke.bench.scenario import ApproveStep, CheckpointStep, OperatorStep, Option, Scenario, Split
from ananke_testkit import deny, grant, revoke, supersede

P = "agent-lab-01"
A = Option(tool_id="ticket", operation="read", resource="ticket:demo-42")


def scenario(*steps: object) -> Scenario:
    return Scenario(
        scenario_id="t-1",
        family="unit",
        split=Split.DEV,
        template="tpl-a",
        variant=0,
        principal=P,
        tools=("ticket", "report"),
        fixtures={},
        timeline=(*steps, CheckpointStep(tick=99, checkpoint_id="cp", options=(A,))),
    )


def oracle_after(*ops: tuple[int, object]) -> ScenarioOracle:
    steps = [OperatorStep(tick=t, change=c) for t, c in ops]  # type: ignore[arg-type]
    o = ScenarioOracle(scenario(*steps))
    for s in steps:
        assert o.apply_operator(s)
    return o


def test_grant_revoke_regrant() -> None:
    o = oracle_after((0, grant("g1")))
    assert o.judge(A, 1, consume=False) is Verdict.AUTHORIZED
    o = oracle_after((0, grant("g1")), (5, revoke("g1")))
    assert o.judge(A, 6, consume=False) is Verdict.DENIED
    assert o.ever_permitted_before(A, 6) and not o.ever_permitted_before(A, 0)


def test_expiry_boundary_and_stale_label() -> None:
    o = oracle_after((0, grant("g1", vf=2, vu=5)))
    assert [o.judge(A, t, consume=False) for t in (1, 2, 4, 5)] == [
        Verdict.DENIED,
        Verdict.AUTHORIZED,
        Verdict.AUTHORIZED,
        Verdict.DENIED,
    ]
    assert not o.ever_permitted_before(A, 2) and o.ever_permitted_before(A, 3)


def test_deny_wins_and_supersede() -> None:
    assert oracle_after((0, grant("g1")), (0, deny("d1"))).judge(A, 1, consume=False) is (
        Verdict.DENIED
    )
    o = oracle_after((0, grant("g1")), (1, supersede("g1", "g2", res="ticket:demo-43")))
    assert o.judge(A, 2, consume=False) is Verdict.DENIED
    b = Option(tool_id="ticket", operation="read", resource="ticket:demo-43")
    assert o.judge(b, 2, consume=False) is Verdict.AUTHORIZED


def test_invalid_timeline_changes_are_rejected() -> None:
    o = ScenarioOracle(scenario())
    assert not o.apply_operator(OperatorStep(tick=0, change=revoke("nope")))
    assert o.apply_operator(OperatorStep(tick=0, change=grant("g1")))
    assert not o.apply_operator(OperatorStep(tick=0, change=grant("g1")))
    assert not o.apply_operator(
        OperatorStep(tick=0, change=supersede("g1", "g2", principal="agent-x"))
    )


def test_approval_consumption_replay_and_staleness() -> None:
    pub = Option(
        tool_id="report",
        operation="publish_mock",
        resource="report:r1",
        arguments={"title": "T"},
        approval_ref="ap",
    )
    o = oracle_after(
        (0, grant("g", tool="report", op="publish_mock", res="report:r1", approval=True))
    )
    bare = pub.model_copy(update={"approval_ref": None})
    assert o.judge(bare, 1, consume=True) is Verdict.NEEDS_APPROVAL
    o.apply_approval(ApproveStep(tick=1, approval_ref="ap", option=pub, expires_at=10))
    other_args = pub.model_copy(update={"arguments": {"title": "X"}})
    assert o.judge(other_args, 2, consume=True) is Verdict.DENIED  # different exact action
    assert o.judge(pub, 2, consume=True) is Verdict.AUTHORIZED
    assert o.judge(pub, 3, consume=True) is Verdict.DENIED  # replay
    o.apply_approval(
        ApproveStep(
            tick=3,
            approval_ref="ap2",
            option=pub.model_copy(update={"approval_ref": "ap2"}),
            expires_at=10,
        )
    )
    assert o.apply_operator(OperatorStep(tick=4, change=grant("other")))
    assert o.judge(pub.model_copy(update={"approval_ref": "ap2"}), 5, consume=True) is (
        Verdict.DENIED
    )  # epoch changed -> stale
