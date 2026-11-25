"""Gateway: approvals, idempotency, linearization races, rollback and fail-closed paths."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from ananke.domain import ActionCore, Outcome, ReasonCode
from ananke.lab import read_record
from ananke.ledger import OperatorChannel, open_ledger, verify_ledger
from ananke.ledger.evidence import read_decisions, verify_decisions
from ananke.runtime import AgentPort, Gateway, GatewayUnavailableError
from ananke_testkit import (
    AGENT,
    GatewayLab,
    deny,
    grant,
    raw_attacker_connection,
    restore_triggers,
    revoke,
    seq_ids,
    supersede,
)

R = ReasonCode
PUB = ("report", "publish_mock", "report:demo-q3")
PUB_ARGS = {"title": "Q3 synthetic"}


@pytest.fixture
def lab(tmp_path: Path) -> GatewayLab:
    lab = GatewayLab(tmp_path)
    yield lab  # type: ignore[misc]
    lab.close()


def core(
    tool: str,
    op: str,
    res: str,
    args: dict[str, object] | None = None,
    session: str = "s1",
    principal: str = AGENT,
) -> ActionCore:
    return ActionCore(
        principal_id=principal,
        session_id=session,
        tool_id=tool,
        operation=op,
        resource=res,
        arguments=args or {},
    )


# ------------------------------------------------------------------ flagship lifecycle


def test_revocation_blocks_stale_proposal_and_regrant_allows_alternative(lab: GatewayLab) -> None:
    lab.operator.submit(grant("grant-001", vu=20))
    r = lab.propose("ticket", "read", "ticket:demo-42")
    assert (r.outcome, r.reason_code, r.epoch) == (Outcome.ALLOW, R.ALLOWED, 1)
    assert r.result is not None and r.result["record"]["title"] == "Synthetic ticket 42"

    lab.clock.advance_to(10)
    lab.operator.submit(revoke("grant-001"))
    stale = lab.propose("ticket", "read", "ticket:demo-42")
    assert (stale.outcome, stale.reason_code, stale.epoch) == (Outcome.DENY, R.GRANT_REVOKED, 2)
    assert stale.matched_rule_ids == ("grant-001",)
    assert stale.result is None  # no old content after revocation

    lab.operator.submit(grant("grant-002", tool="report", res="report:demo-q3"))
    alt = lab.propose("report", "read", "report:demo-q3")
    assert (alt.outcome, alt.epoch) == (Outcome.ALLOW, 3)
    assert lab.effects() == [
        ("ticket", "read", "ticket:demo-42"),
        ("report", "read", "report:demo-q3"),
    ]


def test_expiry_at_exact_tick(lab: GatewayLab) -> None:
    lab.operator.submit(grant("grant-001", vf=0, vu=5))
    lab.clock.advance_to(4)
    assert lab.propose("ticket", "read", "ticket:demo-42").outcome is Outcome.ALLOW
    lab.clock.advance_to(5)
    r = lab.propose("ticket", "read", "ticket:demo-42")
    assert (r.outcome, r.reason_code) == (Outcome.DENY, R.GRANT_EXPIRED)


def test_narrowed_scope_via_supersede(lab: GatewayLab) -> None:
    lab.operator.submit(grant("grant-001"))
    lab.operator.submit(supersede("grant-001", "grant-002", res="ticket:demo-43"))
    assert lab.propose("ticket", "read", "ticket:demo-42").reason_code is R.GRANT_REVOKED
    assert lab.propose("ticket", "read", "ticket:demo-43").outcome is Outcome.ALLOW


def test_write_effect_changes_only_target_record(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g-upd", op="update"))
    before = {r: read_record(lab.conn, r) for r in ("ticket:demo-43", "report:demo-q3")}
    r = lab.propose("ticket", "update", "ticket:demo-42", args={"status": "closed", "note": "done"})
    assert r.outcome is Outcome.ALLOW and r.result is None  # writes do not disclose content
    assert read_record(lab.conn, "ticket:demo-42")["status"] == "closed"  # type: ignore[index]
    assert {r: read_record(lab.conn, r) for r in before} == before


# ------------------------------------------------------------------ validation


@pytest.mark.parametrize(
    ("tool", "op", "res", "args", "reason"),
    [
        ("shell", "exec", "shell:x", {}, R.UNKNOWN_TOOL),
        ("ticket", "delete", "ticket:demo-42", {}, R.INVALID_ARGUMENTS),
        ("ticket", "read", "report:demo-q3", {}, R.INVALID_ARGUMENTS),  # namespace mismatch
        ("ticket", "read", "ticket:demo-42", {"x": 1}, R.INVALID_ARGUMENTS),  # extra arg
        ("ticket", "update", "ticket:demo-42", {"status": "deleted"}, R.INVALID_ARGUMENTS),
        ("ticket", "update", "ticket:demo-42", {}, R.INVALID_ARGUMENTS),
        ("report", "publish_mock", "report:demo-q3", {"title": "x" * 81}, R.INVALID_ARGUMENTS),
    ],
)
def test_invalid_actions_fail_closed(
    lab: GatewayLab, tool: str, op: str, res: str, args: dict[str, object], reason: ReasonCode
) -> None:
    lab.operator.submit_many([grant("g1", op="update"), grant("g2")])
    before = lab.lab_state()
    r = lab.propose(tool, op, res, args=args)
    assert (r.outcome, r.reason_code) == (Outcome.DENY, reason)
    assert lab.lab_state() == before and lab.effects() == []


def test_tool_error_after_authorization_rolls_back(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g1", op="update", res="ticket:missing"))
    r = lab.propose("ticket", "update", "ticket:missing", args={"status": "closed"})
    assert (r.outcome, r.reason_code) == (Outcome.DENY, R.INVALID_ARGUMENTS)
    assert lab.effects() == []


# ------------------------------------------------------------------ approvals


def _approval_lab(lab: GatewayLab) -> None:
    lab.operator.submit(
        grant("g-pub", tool="report", op="publish_mock", res="report:demo-q3", approval=True)
    )


def test_approval_lifecycle_single_use(lab: GatewayLab) -> None:
    _approval_lab(lab)
    first = lab.propose(*PUB, args=PUB_ARGS)
    assert (first.outcome, first.reason_code) == (Outcome.NEEDS_APPROVAL, R.APPROVAL_REQUIRED)
    assert lab.effects() == []
    appr = lab.operator.issue_approval(core(*PUB, PUB_ARGS), expires_at=50)
    ok = lab.propose(*PUB, args=PUB_ARGS, approval_id=appr.approval_id)
    assert (ok.outcome, ok.reason_code) == (Outcome.ALLOW, R.ALLOWED)
    replay = lab.propose(*PUB, args=PUB_ARGS, approval_id=appr.approval_id)
    assert (replay.outcome, replay.reason_code) == (Outcome.DENY, R.APPROVAL_REPLAY)
    assert len(lab.effects()) == 1
    rows = lab.conn.execute("SELECT approval_id, decision_id FROM approval_consumptions").fetchall()
    assert rows == [(appr.approval_id, ok.decision_id)]


@pytest.mark.parametrize(
    ("approved", "reason"),
    [
        (core(*PUB, {"title": "a different title"}), R.APPROVAL_INVALID),  # other action digest
        (core(*PUB, PUB_ARGS, session="s2"), R.APPROVAL_INVALID),
        (core(*PUB, PUB_ARGS, principal="agent-other"), R.APPROVAL_INVALID),
    ],
)
def test_approval_bound_to_exact_action_principal_session(
    lab: GatewayLab, approved: ActionCore, reason: ReasonCode
) -> None:
    _approval_lab(lab)
    appr = lab.operator.issue_approval(approved, expires_at=50)
    r = lab.propose(*PUB, args=PUB_ARGS, approval_id=appr.approval_id)
    assert (r.outcome, r.reason_code) == (Outcome.DENY, reason)
    assert lab.effects() == []


def test_unknown_approval_id(lab: GatewayLab) -> None:
    _approval_lab(lab)
    r = lab.propose(*PUB, args=PUB_ARGS, approval_id="00000000-0000-0000-0000-00000000dead")
    assert r.reason_code is R.APPROVAL_INVALID


def test_approval_expires(lab: GatewayLab) -> None:
    _approval_lab(lab)
    appr = lab.operator.issue_approval(core(*PUB, PUB_ARGS), expires_at=3)
    lab.clock.advance_to(3)
    r = lab.propose(*PUB, args=PUB_ARGS, approval_id=appr.approval_id)
    assert (r.outcome, r.reason_code) == (Outcome.DENY, R.APPROVAL_STALE)


def test_any_policy_change_invalidates_outstanding_approval(lab: GatewayLab) -> None:
    _approval_lab(lab)
    appr = lab.operator.issue_approval(core(*PUB, PUB_ARGS), expires_at=50)
    lab.operator.submit(grant("unrelated", tool="artifact", res="artifact:notes"))
    r = lab.propose(*PUB, args=PUB_ARGS, approval_id=appr.approval_id)
    assert (r.outcome, r.reason_code) == (Outcome.DENY, R.APPROVAL_STALE)
    assert lab.conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0] == 0


def test_denied_approval_is_not_consumed(lab: GatewayLab) -> None:
    _approval_lab(lab)
    lab.operator.submit(deny("d-pub", tool="report", op="publish_mock", res="report:demo-q3"))
    appr = lab.operator.issue_approval(core(*PUB, PUB_ARGS), expires_at=50)
    r = lab.propose(*PUB, args=PUB_ARGS, approval_id=appr.approval_id)
    assert r.reason_code is R.EXPLICIT_DENY
    assert lab.conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0] == 0


def test_approval_cannot_be_reused_even_by_direct_sql(lab: GatewayLab) -> None:
    _approval_lab(lab)
    appr = lab.operator.issue_approval(core(*PUB, PUB_ARGS), expires_at=50)
    lab.propose(*PUB, args=PUB_ARGS, approval_id=appr.approval_id)
    for sql in (
        "DELETE FROM approval_consumptions",
        "UPDATE approval_consumptions SET consumed_at = 0",
        "DELETE FROM approvals",
        "UPDATE approvals SET expires_at = 99",
    ):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            lab.conn.execute(sql)
    with pytest.raises(sqlite3.IntegrityError, match=r"UNIQUE|PRIMARY"):
        lab.conn.execute(
            "INSERT INTO approval_consumptions VALUES (?, ?, 0)",
            (appr.approval_id, "00000000-0000-0000-0000-0000000000ff"),
        )


def test_operator_rejects_past_expiry(lab: GatewayLab) -> None:
    _approval_lab(lab)
    lab.clock.advance_to(5)
    with pytest.raises(ValueError, match="future"):
        lab.operator.issue_approval(core(*PUB, PUB_ARGS), expires_at=5)
    assert lab.conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0


# ------------------------------------------------------------------ idempotency


def test_idempotent_repeat_returns_receipt_without_effect_or_content(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g1"))
    first = lab.propose("ticket", "read", "ticket:demo-42", key="same")
    again = lab.propose("ticket", "read", "ticket:demo-42", key="same")
    assert (again.outcome, again.reason_code) == (Outcome.ALLOW, R.DUPLICATE_REQUEST)
    assert again.duplicate_of == first.decision_id and again.result is None
    assert again.effect_id is None and len(lab.effects()) == 1


def test_duplicate_after_revocation_discloses_nothing(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g1"))
    lab.propose("ticket", "read", "ticket:demo-42", key="same")
    lab.operator.submit(revoke("g1"))
    again = lab.propose("ticket", "read", "ticket:demo-42", key="same")
    assert again.reason_code is R.DUPLICATE_REQUEST and again.result is None


def test_same_key_different_action_conflicts(lab: GatewayLab) -> None:
    lab.operator.submit_many([grant("g1"), grant("g2", res="ticket:demo-43")])
    lab.propose("ticket", "read", "ticket:demo-42", key="same")
    r = lab.propose("ticket", "read", "ticket:demo-43", key="same")
    assert (r.outcome, r.reason_code) == (Outcome.DENY, R.IDEMPOTENCY_CONFLICT)
    assert len(lab.effects()) == 1


def test_denied_request_key_is_not_burned(lab: GatewayLab) -> None:
    r1 = lab.propose("ticket", "read", "ticket:demo-42", key="retry")
    assert r1.reason_code is R.NO_MATCHING_GRANT
    lab.operator.submit(grant("g1"))
    r2 = lab.propose("ticket", "read", "ticket:demo-42", key="retry")
    assert r2.outcome is Outcome.ALLOW


def test_concurrent_duplicate_requests_commit_exactly_one_effect(tmp_path: Path) -> None:
    lab = GatewayLab(tmp_path)
    lab.operator.submit(grant("g1", op="update"))
    barrier = threading.Barrier(4)
    outcomes: list[ReasonCode] = []
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        conn = open_ledger(lab.path)
        try:
            gw = Gateway(conn, lab.clock.now, id_factory=seq_ids(100 + n))
            port = AgentPort(gw, principal_id=AGENT, session_id="s1", id_factory=seq_ids(200 + n))
            barrier.wait()
            r = port.propose(
                {
                    "tool_id": "ticket",
                    "operation": "update",
                    "resource": "ticket:demo-42",
                    "arguments": {"status": "closed"},
                    "idempotency_key": "once",
                }
            )
            outcomes.append(r.reason_code)
        except BaseException as exc:  # surfaced below
            errors.append(exc)
        finally:
            conn.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert sorted(outcomes) == sorted([R.ALLOWED] + [R.DUPLICATE_REQUEST] * 3)
    assert len(lab.effects()) == 1
    assert read_record(lab.conn, "ticket:demo-42")["status"] == "closed"  # type: ignore[index]
    lab.close()


# ------------------------------------------------------------------ linearization races


def test_revocation_committed_before_effect_wins(tmp_path: Path) -> None:
    """Proposal formed at epoch 1; revocation commits; then the request reaches the gateway."""
    lab = GatewayLab(tmp_path)
    lab.operator.submit(grant("g1"))
    observed_epoch = lab.operator.current_state().epoch
    lab.operator.submit(revoke("g1"))
    r = lab.port.propose(
        {
            "tool_id": "ticket",
            "operation": "read",
            "resource": "ticket:demo-42",
            "idempotency_key": "k",
            "observed_epoch": observed_epoch,
        }
    )
    assert (r.outcome, r.reason_code, r.epoch) == (Outcome.DENY, R.GRANT_REVOKED, 2)
    lab.close()


def test_revocation_racing_an_in_flight_effect_is_serialized_after_it(tmp_path: Path) -> None:
    """While the gateway holds the write lock, a concurrent revocation must wait.

    Linearization point is COMMIT: the effect is ordered before the revocation, and the very
    next request is denied. No interleaving lets an effect commit under a revoked grant.
    """
    inside, release = threading.Event(), threading.Event()
    order: list[str] = []

    def hold() -> None:
        inside.set()
        assert release.wait(5)

    lab = GatewayLab(tmp_path, hooks={"before_effect": hold})
    lab.operator.submit(grant("g1"))

    def revoker() -> None:
        assert inside.wait(5)
        conn = open_ledger(lab.path)
        try:
            ch = OperatorChannel(conn, "op-admin", lab.clock.now, id_factory=seq_ids(300))
            order.append("revoke-start")
            release_timer = threading.Timer(0.3, release.set)
            release_timer.start()
            ch.submit(revoke("g1"))  # blocks on the write lock until the gateway commits
            order.append("revoke-committed")
        finally:
            conn.close()

    t = threading.Thread(target=revoker)
    t.start()
    r = lab.propose("ticket", "read", "ticket:demo-42")
    order.append("effect-committed")
    t.join(10)
    assert order == ["revoke-start", "effect-committed", "revoke-committed"]
    assert (r.outcome, r.epoch) == (Outcome.ALLOW, 1)
    events = lab.conn.execute("SELECT epoch, kind FROM policy_events ORDER BY sequence").fetchall()
    assert events == [(1, "GRANT"), (2, "REVOKE")]
    after = lab.propose("ticket", "read", "ticket:demo-42")
    assert (after.reason_code, after.epoch) == (R.GRANT_REVOKED, 2)
    lab.close()


# ------------------------------------------------------------------ failure injection


@pytest.mark.parametrize(
    "point", ["policy_loaded", "before_effect", "after_effect", "before_commit"]
)
def test_crash_at_any_point_rolls_back_everything(tmp_path: Path, point: str) -> None:
    def boom() -> None:
        raise RuntimeError(f"injected failure at {point}")

    lab = GatewayLab(tmp_path, hooks={point: boom})
    lab.operator.submit(
        grant("g-pub", tool="report", op="publish_mock", res="report:demo-q3", approval=True)
    )
    appr = lab.operator.issue_approval(core(*PUB, PUB_ARGS), expires_at=50)
    before = lab.lab_state()
    r = lab.propose(*PUB, args=PUB_ARGS, approval_id=appr.approval_id, key="crash")
    assert (r.outcome, r.reason_code) == (Outcome.DENY, R.INTERNAL_ERROR)
    assert lab.lab_state() == before and lab.effects() == []
    assert lab.conn.execute("SELECT COUNT(*) FROM approval_consumptions").fetchone()[0] == 0
    assert lab.conn.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0] == 0
    assert verify_ledger(lab.path).ok
    assert [d.reason_code for d in read_decisions(lab.conn)] == [R.INTERNAL_ERROR]
    lab.close()


def test_corrupted_ledger_denies_everything(tmp_path: Path) -> None:
    lab = GatewayLab(tmp_path)
    lab.operator.submit(grant("g1"))
    conn = raw_attacker_connection(lab.path)
    conn.execute("UPDATE policy_events SET canonical = CAST('{}' AS BLOB) WHERE sequence = 1")
    restore_triggers(conn)
    conn.close()
    fresh = GatewayLab.__new__(GatewayLab)  # new gateway on the same corrupted file
    fresh.conn = open_ledger(lab.path)
    gw = Gateway(fresh.conn, lab.clock.now, id_factory=seq_ids(400))
    port = AgentPort(gw, principal_id=AGENT, session_id="s1", id_factory=seq_ids(401))
    r = port.propose(
        {
            "tool_id": "ticket",
            "operation": "read",
            "resource": "ticket:demo-42",
            "idempotency_key": "k",
        }
    )
    assert (r.outcome, r.reason_code) == (Outcome.DENY, R.POLICY_INVALID)
    assert fresh.conn.execute("SELECT COUNT(*) FROM lab_effects").fetchone()[0] == 0
    fresh.conn.close()
    lab.close()


def test_gateway_raises_when_evidence_cannot_be_recorded(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g1"))
    lab.conn.close()
    with pytest.raises(GatewayUnavailableError):
        lab.propose("ticket", "read", "ticket:demo-42")
    lab.conn = open_ledger(lab.path)
    assert lab.conn.execute("SELECT COUNT(*) FROM lab_effects").fetchone()[0] == 0


def test_decision_log_is_chained_and_verified(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g1"))
    for _ in range(5):
        lab.propose("ticket", "read", "ticket:demo-42")
    lab.propose("shell", "exec", "shell:x")
    assert verify_decisions(lab.conn).ok and verify_decisions(lab.conn).count == 6
    conn = raw_attacker_connection(lab.path)
    conn.execute("UPDATE decisions SET outcome = 'ALLOW' WHERE sequence = 6")
    restore_triggers(conn)
    conn.close()
    report = verify_ledger(lab.path)
    assert not report.ok and report.errors[0].code.value == "DECISION_LOG_INVALID"


def test_unknown_hook_name_rejected(lab: GatewayLab) -> None:
    with pytest.raises(ValueError, match="unknown gateway hooks"):
        Gateway(lab.conn, lab.clock.now, hooks={"mid_effect": lambda: None})


def test_lock_timeout_is_bounded(tmp_path: Path) -> None:
    lab = GatewayLab(tmp_path)
    lab.operator.submit(grant("g1"))
    blocker = open_ledger(lab.path)
    blocker.execute("BEGIN IMMEDIATE")
    start = time.monotonic()
    try:
        r = lab.propose("ticket", "read", "ticket:demo-42")
    except GatewayUnavailableError:
        r = None  # evidence write also blocked: loud failure, no effect
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert time.monotonic() - start < 15
    assert r is None or r.reason_code is R.LEDGER_UNAVAILABLE
    assert lab.effects() == []
    lab.close()
