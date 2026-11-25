"""Regression tests pinning the findings of the session-3 code review (one block per finding)."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ananke.audit import audit_connection
from ananke.cli import app
from ananke.domain import GENESIS_HASH, ActionCore, Outcome, ReasonCode, digest
from ananke.ledger import LedgerUnavailableError, init_ledger, open_ledger, verify_ledger
from ananke.ledger.evidence import read_decisions
from ananke_testkit import (
    AGENT,
    GatewayLab,
    grant,
    raw_attacker_connection,
    restore_triggers,
    seq_ids,
)

runner = CliRunner()


def cli(*args: str) -> tuple[int, dict[str, object]]:
    r = runner.invoke(app, list(args))
    return r.exit_code, json.loads(r.output)


# 1 -------------------------------------------------------------- URI-unsafe path characters


@pytest.mark.parametrize("name", ["a#b.sqlite", "a?b.sqlite", "a%41b.sqlite", "a b.sqlite"])
def test_uri_unsafe_paths_open_exactly_that_file(tmp_path: Path, name: str) -> None:
    db = tmp_path / name
    code, _ = cli("ledger", "init", "--db", str(db), "--operator", "op-a")
    assert code == 0
    assert sorted(p.name for p in tmp_path.iterdir() if p.suffix == ".sqlite") == [name]
    code, out = cli("ledger", "verify", "--db", str(db))
    assert code == 0 and out["ok"] is True


def test_create_is_exclusive(tmp_path: Path) -> None:
    db = tmp_path / "x.sqlite"
    db.write_bytes(b"")
    with pytest.raises(LedgerUnavailableError, match="refusing"):
        init_ledger(db, ["op-a"])
    assert db.read_bytes() == b""  # untouched


# 2 -------------------------------------------------------------- live schema tampering


@pytest.mark.parametrize(
    "attack",
    [
        "DROP TRIGGER decisions_no_update",
        "DROP TRIGGER policy_events_no_update",
        # same-named no-op replacement
        "DROP TRIGGER lab_effects_no_delete; CREATE TRIGGER lab_effects_no_delete BEFORE DELETE"
        " ON lab_effects BEGIN SELECT 1; END",
        "CREATE TABLE shadow(x)",
        "CREATE INDEX extra_idx ON decisions(reason_code)",
    ],
)
def test_live_gateway_fails_closed_after_schema_tampering(tmp_path: Path, attack: str) -> None:
    lab = GatewayLab(tmp_path)
    lab.operator.submit(grant("g1"))
    assert lab.propose("ticket", "read", "ticket:demo-42").outcome is Outcome.ALLOW
    attacker = sqlite3.connect(lab.path, isolation_level=None)
    attacker.executescript(attack)
    attacker.close()
    r = lab.propose("ticket", "read", "ticket:demo-42")
    assert (r.outcome, r.reason_code) == (Outcome.DENY, ReasonCode.POLICY_INVALID)
    assert len(lab.effects()) == 1
    assert not verify_ledger(lab.path).ok
    lab.close()


# 3 -------------------------------------------------------------- forged evidence


def _approval_lab(tmp_path: Path) -> GatewayLab:
    lab = GatewayLab(tmp_path)
    lab.operator.submit(
        grant("g-pub", tool="report", op="publish_mock", res="report:demo-q3", approval=True)
    )
    return lab


def _core() -> ActionCore:
    return ActionCore(
        principal_id=AGENT,
        session_id="s1",
        tool_id="report",
        operation="publish_mock",
        resource="report:demo-q3",
        arguments={"title": "Q3"},
    )


def test_unchained_forged_approval_fails_verification(tmp_path: Path) -> None:
    lab = _approval_lab(tmp_path)
    conn = raw_attacker_connection(lab.path)
    conn.execute(
        "INSERT INTO approvals VALUES (1, '00000000-0000-0000-0000-0000000000aa', 'op-admin',"
        " ?, 's1', ?, 1, 0, 50, ?, ?, CAST('{}' AS BLOB))",
        (AGENT, _core().digest(), GENESIS_HASH, "sha256:" + "a" * 64),
    )
    restore_triggers(conn)
    conn.close()
    report = verify_ledger(lab.path)
    assert not report.ok and report.errors[0].code.value == "APPROVAL_LOG_INVALID"
    lab.close()


def test_forged_allow_decision_and_effect_are_caught_by_audit(tmp_path: Path) -> None:
    """No grant exists for ticket.update; an attacker appends a chain-valid ALLOW + effect."""
    from ananke.ledger.db import write_transaction
    from ananke.ledger.evidence import append_decision

    lab = GatewayLab(tmp_path)
    lab.operator.submit(grant("g1"))
    lab.propose("ticket", "read", "ticket:demo-42")
    conn = raw_attacker_connection(lab.path)
    restore_triggers(conn)  # appends are allowed by triggers; the forgery is append-only
    conn.close()
    with write_transaction(lab.conn) as c:
        forged = append_decision(
            c,
            {
                "decision_id": "00000000-0000-0000-0000-0000000000bb",
                "request_id": None,
                "session_id": "s1",
                "principal_id": AGENT,
                "tool_id": "ticket",
                "operation": "update",
                "resource": "ticket:demo-42",
                "action_digest": "sha256:" + "b" * 64,
                "outcome": Outcome.ALLOW,
                "reason_code": ReasonCode.ALLOWED,
                "matched_rule_ids": ("g1",),
                "epoch": 1,
                "evaluated_at": 0,
                "approval_id": None,
                "effect_id": "00000000-0000-0000-0000-0000000000cc",
                "duplicate_of": None,
            },
        )
        c.execute(
            "INSERT INTO lab_effects VALUES (?, ?, 'ticket', 'update', 'ticket:demo-42', 0)",
            (forged.effect_id, forged.decision_id),
        )
    assert verify_ledger(lab.path).ok  # structurally the chains are intact...
    report = audit_connection(lab.conn)  # ...but the evidence does not replay
    codes = {i.code for i in report.issues}
    assert not report.ok and "REPLAY_MISMATCH" in codes and "IDEMPOTENCY_MISMATCH" in codes
    code, out = cli("ledger", "verify", "--db", str(lab.path))
    assert code == 1 and out["audit"]["ok"] is False  # type: ignore[index]
    lab.close()


def test_orphan_effect_and_consumption_are_caught(tmp_path: Path) -> None:
    lab = _approval_lab(tmp_path)
    appr = lab.operator.issue_approval(_core(), expires_at=50)
    conn = sqlite3.connect(lab.path, isolation_level=None)
    conn.execute(
        "INSERT INTO lab_effects VALUES ('00000000-0000-0000-0000-0000000000dd',"
        " '00000000-0000-0000-0000-0000000000ee', 'report', 'publish_mock',"
        " 'report:demo-q3', 0)"
    )
    conn.execute(
        "INSERT INTO approval_consumptions VALUES (?, ?, 0)",
        (appr.approval_id, "00000000-0000-0000-0000-0000000000ef"),
    )
    conn.close()
    codes = {i.code for i in audit_connection(lab.conn).issues}
    assert {"ORPHAN_EFFECT", "ORPHAN_CONSUMPTION"} <= codes
    lab.close()


def test_consistent_forgery_under_registered_operator_is_NOT_caught(tmp_path: Path) -> None:
    """Documented limitation (ADR-0010 proposed): without operator signatures, an attacker with
    full DB write access who forges a *correctly chained* approval passes verification and audit."""
    from ananke.ledger.db import write_transaction
    from ananke.ledger.evidence import append_approval

    lab = _approval_lab(tmp_path)
    with write_transaction(lab.conn) as c:  # attacker reuses the trusted append routine
        forged = append_approval(
            c,
            {
                "approval_id": "00000000-0000-0000-0000-0000000000f1",
                "issued_by": "op-admin",
                "principal_id": AGENT,
                "session_id": "s1",
                "action_digest": _core().digest(),
                "issued_epoch": 1,
                "issued_at": 0,
                "expires_at": 50,
            },
        )
    r = lab.propose(
        "report",
        "publish_mock",
        "report:demo-q3",
        args={"title": "Q3"},
        approval_id=forged.approval_id,
    )
    assert r.outcome is Outcome.ALLOW
    assert verify_ledger(lab.path).ok and audit_connection(lab.conn).ok
    lab.close()


# 4 -------------------------------------------------------------- CLI error contract


def test_cli_bad_operator_identifier_is_structured(tmp_path: Path) -> None:
    db = tmp_path / "l.sqlite"
    cli("ledger", "init", "--db", str(db), "--operator", "op-a")
    changes = tmp_path / "c.json"
    changes.write_text("[]")
    code, out = cli(
        "ledger",
        "apply",
        "--db",
        str(db),
        "--operator",
        "Bad Op",
        "--changes",
        str(changes),
        "--at",
        "0",
    )
    assert code == 1 and out["code"] == "UNKNOWN_OPERATOR"


def test_cli_rejects_unsafe_tick(tmp_path: Path) -> None:
    r = runner.invoke(
        app,
        [
            "ledger",
            "apply",
            "--db",
            str(tmp_path / "l"),
            "--operator",
            "op-a",
            "--changes",
            "x",
            "--at",
            str(2**53),
        ],
    )
    assert r.exit_code == 2  # usage error, no traceback
    assert "Traceback" not in r.output


def test_cli_lock_timeout_exits_2(tmp_path: Path) -> None:
    db = tmp_path / "l.sqlite"
    cli("ledger", "init", "--db", str(db), "--operator", "op-a")
    changes = tmp_path / "c.json"
    changes.write_text(
        json.dumps(
            [
                {
                    "kind": "GRANT",
                    "rule_id": "g1",
                    "principal_id": AGENT,
                    "tool_id": "ticket",
                    "operation": "read",
                    "resource_scope": "ticket:x",
                    "valid_from": 0,
                }
            ]
        )
    )
    blocker = open_ledger(db)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        code, out = cli(
            "ledger",
            "apply",
            "--db",
            str(db),
            "--operator",
            "op-a",
            "--changes",
            str(changes),
            "--at",
            "0",
        )
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert code == 2 and out["code"] == "LEDGER_UNAVAILABLE"


def test_cli_garbage_file_is_structured(tmp_path: Path) -> None:
    db = tmp_path / "junk.sqlite"
    db.write_bytes(b"this is not a database at all" * 100)
    for args in (("ledger", "verify"), ("ledger", "show")):
        r = runner.invoke(app, [*args, "--db", str(db)])
        assert r.exit_code in (1, 2) and "Traceback" not in r.output
        assert json.loads(r.output)["status"] == "error"


# 5 -------------------------------------------------------------- I/O failure classification


def test_operational_error_mid_transaction_is_ledger_unavailable(tmp_path: Path) -> None:
    def disk_full() -> None:
        raise sqlite3.OperationalError("database or disk is full")

    lab = GatewayLab(tmp_path, hooks={"after_effect": disk_full})
    lab.operator.submit(grant("g1"))
    r = lab.propose("ticket", "read", "ticket:demo-42")
    assert (r.outcome, r.reason_code) == (Outcome.DENY, ReasonCode.LEDGER_UNAVAILABLE)
    assert lab.effects() == []
    lab.close()


# 6 -------------------------------------------------------------- approval_id evidence


def test_unevaluated_approval_is_not_recorded_as_evidence(tmp_path: Path) -> None:
    lab = GatewayLab(tmp_path)
    lab.operator.submit(grant("g1"))  # no approval required
    bogus = "00000000-0000-0000-0000-00000000beef"
    r = lab.propose("ticket", "read", "ticket:demo-42", approval_id=bogus)
    lab.propose("shell", "exec", "shell:x", approval_id=bogus)
    assert r.outcome is Outcome.ALLOW
    assert all(d.approval_id is None for d in read_decisions(lab.conn))
    assert audit_connection(lab.conn).ok
    lab.close()


# 7 -------------------------------------------------------------- init cleanup


def test_failed_init_leaves_no_file_and_retry_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ananke.ledger.store as store

    db = tmp_path / "l.sqlite"

    def broken(_conn: sqlite3.Connection) -> int:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store, "migrate", broken)
    with pytest.raises(sqlite3.OperationalError):
        init_ledger(db, ["op-a"])
    assert not any(tmp_path.iterdir())
    monkeypatch.undo()
    init_ledger(db, ["op-a"])
    assert verify_ledger(db).ok


# --------------------------------------------------------------- audit on legitimate histories


def test_audit_passes_on_full_legitimate_history(tmp_path: Path) -> None:
    from ananke_testkit import revoke

    lab = _approval_lab(tmp_path)
    lab.operator.submit(grant("g1", vu=5))
    lab.propose("ticket", "read", "ticket:demo-42", key="a")
    lab.propose("ticket", "read", "ticket:demo-42", key="a")  # duplicate
    lab.propose("report", "publish_mock", "report:demo-q3", args={"title": "Q3"})  # needs appr.
    appr = lab.operator.issue_approval(_core(), expires_at=50)
    lab.propose(
        "report",
        "publish_mock",
        "report:demo-q3",
        args={"title": "Q3"},
        approval_id=appr.approval_id,
    )
    lab.propose(
        "report",
        "publish_mock",
        "report:demo-q3",
        args={"title": "Q3"},
        approval_id=appr.approval_id,
        key="replay",
    )
    lab.propose(
        "report",
        "publish_mock",
        "report:demo-q3",
        args={"title": "other"},
        approval_id=appr.approval_id,
        key="invalid",
    )
    stale = lab.operator.issue_approval(_core(), expires_at=50)
    lab.clock.advance_to(6)
    lab.operator.submit(revoke("g1"))
    lab.propose(
        "report",
        "publish_mock",
        "report:demo-q3",
        args={"title": "Q3"},
        approval_id=stale.approval_id,
        key="stale",
    )
    lab.propose("ticket", "read", "ticket:demo-42")  # revoked
    lab.propose("shell", "exec", "shell:x")
    lab.port.propose({"principal_id": "root"})
    reasons = {d.reason_code for d in read_decisions(lab.conn)}
    assert {
        ReasonCode.ALLOWED,
        ReasonCode.DUPLICATE_REQUEST,
        ReasonCode.APPROVAL_REQUIRED,
        ReasonCode.APPROVAL_REPLAY,
        ReasonCode.APPROVAL_INVALID,
        ReasonCode.APPROVAL_STALE,
        ReasonCode.GRANT_REVOKED,
        ReasonCode.UNKNOWN_TOOL,
        ReasonCode.INVALID_ARGUMENTS,
    } <= reasons
    report = audit_connection(lab.conn)
    assert report.ok, report.as_dict()
    assert report.replayed == 7 and report.consumptions == 1  # 7 policy-replayable of 10
    lab.close()


def test_audit_is_thread_safe_with_concurrent_writers(tmp_path: Path) -> None:
    lab = GatewayLab(tmp_path)
    lab.operator.submit(grant("g1"))
    stop = threading.Event()

    def writer() -> None:
        conn = open_ledger(lab.path)
        from ananke.runtime import AgentPort, Gateway

        port = AgentPort(
            Gateway(conn, lab.clock.now, id_factory=seq_ids(500)),
            principal_id=AGENT,
            session_id="s9",
            id_factory=seq_ids(501),
        )
        i = 0
        while not stop.is_set() and i < 40:
            port.propose(
                {
                    "tool_id": "ticket",
                    "operation": "read",
                    "resource": "ticket:demo-42",
                    "idempotency_key": f"w{i}",
                }
            )
            i += 1
        conn.close()

    t = threading.Thread(target=writer)
    t.start()
    reader = open_ledger(lab.path)
    try:
        for _ in range(5):
            assert audit_connection(reader).ok  # consistent snapshot every time
    finally:
        stop.set()
        t.join()
        reader.close()
    assert audit_connection(lab.conn).ok
    _ = digest  # keep import used for readability of forgery tests
    lab.close()
