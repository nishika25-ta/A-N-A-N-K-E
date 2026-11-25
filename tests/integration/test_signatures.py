"""ADR-0010: operator signatures and signed external checkpoints."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ananke.audit import audit_connection
from ananke.cli import app
from ananke.domain import ActionCore, Outcome, ReasonCode
from ananke.ledger import (
    Checkpoint,
    LedgerIntegrityError,
    OperatorChannel,
    PolicyReader,
    SigningError,
    build_event,
    create_checkpoint,
    generate_key,
    init_ledger,
    load_private_key,
    open_ledger,
    public_key_hex,
    verify_checkpoint,
    verify_ledger,
    write_private_key,
)
from ananke.ledger.db import read_transaction, write_transaction
from ananke.ledger.evidence import append_approval
from ananke.ledger.signing import KIND_EVENT, insert_signature
from ananke_testkit import (
    AGENT,
    OPERATOR,
    GatewayLab,
    Lab,
    grant,
    raw_attacker_connection,
    restore_triggers,
    revoke,
    seq_ids,
)

PUB = ("report", "publish_mock", "report:demo-q3")


def _core() -> ActionCore:
    return ActionCore(
        principal_id=AGENT,
        session_id="s1",
        tool_id="report",
        operation="publish_mock",
        resource="report:demo-q3",
        arguments={"title": "Q3"},
    )


@pytest.fixture
def lab(tmp_path: Path) -> GatewayLab:
    lab = GatewayLab(tmp_path, signed=True)
    yield lab  # type: ignore[misc]
    lab.close()


def _sig_count(lab: Lab, kind: str) -> int:
    return lab.conn.execute(
        "SELECT COUNT(*) FROM record_signatures WHERE record_kind = ?", (kind,)
    ).fetchone()[0]


# ------------------------------------------------------------------ happy path


def test_signed_ledger_signs_every_event_and_approval(lab: GatewayLab) -> None:
    lab.operator.submit_many(
        [
            grant("g1"),
            grant("g-pub", tool="report", op="publish_mock", res="report:demo-q3", approval=True),
        ]
    )
    lab.operator.submit(revoke("g1"))
    appr = lab.operator.issue_approval(_core(), expires_at=50)
    r = lab.propose(*PUB, args={"title": "Q3"}, approval_id=appr.approval_id)
    assert r.outcome is Outcome.ALLOW
    assert _sig_count(lab, "policy-event") == 3 and _sig_count(lab, "approval") == 1
    report = verify_ledger(lab.path)
    assert report.ok and report.authenticity == "signed"
    assert audit_connection(lab.conn).ok


def test_unsigned_ledger_reports_unsigned(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    lab.operator.submit(grant("g1"))
    assert verify_ledger(lab.path).authenticity == "unsigned"
    lab.close()


# ------------------------------------------------------------------ channel and setup rules


def test_channel_requires_the_registered_key(lab: GatewayLab) -> None:
    with pytest.raises(SigningError, match="private key is required"):
        OperatorChannel(lab.conn, OPERATOR, lab.clock.now)
    with pytest.raises(SigningError, match="does not match"):
        OperatorChannel(lab.conn, OPERATOR, lab.clock.now, signing_key=generate_key())


def test_unsigned_ledger_refuses_a_key(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    with pytest.raises(SigningError, match="unsigned"):
        OperatorChannel(lab.conn, OPERATOR, lab.clock.now, signing_key=generate_key())
    lab.close()


def test_init_requires_a_key_for_every_operator(tmp_path: Path) -> None:
    k = public_key_hex(generate_key())
    with pytest.raises(ValueError, match="exactly the registered operators"):
        init_ledger(tmp_path / "a.sqlite", ["op-a", "op-b"], public_keys={"op-a": k})
    with pytest.raises(SigningError):
        init_ledger(tmp_path / "b.sqlite", ["op-a"], public_keys={"op-a": "zz"})
    assert not (tmp_path / "a.sqlite").exists() and not (tmp_path / "b.sqlite").exists()


# ------------------------------------------------------------------ forgery is now caught


def _forge_event(lab: Lab, rule: str, *, actor: str = OPERATOR) -> object:
    """An attacker with DB write access appends a chain-consistent event (appends are allowed)."""
    state = lab.operator.current_state()
    ev = build_event(
        state,
        grant(rule),
        event_id="00000000-0000-0000-0000-00000000f0f0",
        actor_id=actor,
        recorded_at=lab.clock.now(),
    )
    lab.conn.execute(
        "INSERT INTO policy_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            ev.sequence,
            ev.event_id,
            ev.epoch,
            "GRANT",
            actor,
            rule,
            None,
            ev.recorded_at,
            ev.prev_hash,
            ev.event_hash,
            ev.canonical(),
        ),
    )
    return ev


def test_unsigned_forged_event_fails_verify_and_gateway(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g-other", res="ticket:demo-43"))
    _forge_event(lab, "g-forged")
    report = verify_ledger(lab.path)
    assert not report.ok and report.errors[0].code.value == "SIGNATURE_INVALID"
    r = lab.propose("ticket", "read", "ticket:demo-42")
    assert (r.outcome, r.reason_code) == (Outcome.DENY, ReasonCode.POLICY_INVALID)
    assert lab.effects() == []


def test_forged_event_signed_with_attacker_key_fails(lab: GatewayLab) -> None:
    ev = _forge_event(lab, "g-forged")
    insert_signature(lab.conn, generate_key(), KIND_EVENT, ev.event_hash, OPERATOR)  # type: ignore[attr-defined]
    assert "invalid policy-event signature" in verify_ledger(lab.path).errors[0].detail
    fresh = open_ledger(lab.path)
    try:
        with read_transaction(fresh), pytest.raises(LedgerIntegrityError):
            PolicyReader(fresh).current_state()  # a fresh reader must refuse the ledger
    finally:
        fresh.close()


def test_consistent_approval_forgery_is_now_denied(lab: GatewayLab) -> None:
    """The session-3 limitation, re-run on a signed ledger: the forgery no longer works."""
    lab.operator.submit(
        grant("g-pub", tool="report", op="publish_mock", res="report:demo-q3", approval=True)
    )
    with write_transaction(lab.conn) as c:
        forged = append_approval(
            c,
            {
                "approval_id": "00000000-0000-0000-0000-0000000000f1",
                "issued_by": OPERATOR,
                "principal_id": AGENT,
                "session_id": "s1",
                "action_digest": _core().digest(),
                "issued_epoch": 1,
                "issued_at": 0,
                "expires_at": 50,
            },
        )
    r = lab.propose(*PUB, args={"title": "Q3"}, approval_id=forged.approval_id)
    assert (r.outcome, r.reason_code) == (Outcome.DENY, ReasonCode.APPROVAL_INVALID)
    assert lab.effects() == []
    report = verify_ledger(lab.path)
    assert not report.ok and report.errors[0].code.value == "APPROVAL_LOG_INVALID"


def test_replaced_signature_rows_are_detected(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g1"))
    lab.close()
    conn = raw_attacker_connection(lab.path)
    conn.execute("UPDATE record_signatures SET signature = ?", ("ab" * 64,))
    restore_triggers(conn)
    conn.close()
    assert verify_ledger(lab.path).errors[0].code.value == "SIGNATURE_INVALID"


def test_missing_signing_mode_fails_closed(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g1"))
    lab.close()
    conn = raw_attacker_connection(lab.path)
    conn.execute("DELETE FROM ledger_config WHERE key = 'signing'")
    restore_triggers(conn)
    conn.close()
    assert not verify_ledger(lab.path).ok
    conn = open_ledger(lab.path)
    try:
        with pytest.raises(SigningError):
            OperatorChannel(conn, OPERATOR, lambda: 0, signing_key=generate_key())
    finally:
        conn.close()


# ------------------------------------------------------------------ keys on disk


def test_key_files_are_private_and_never_overwritten(tmp_path: Path) -> None:
    k = generate_key()
    path = tmp_path / "op.key"
    write_private_key(path, k)
    assert (path.stat().st_mode & 0o777) == 0o600
    assert public_key_hex(load_private_key(path)) == public_key_hex(k)
    with pytest.raises(SigningError, match="refusing to overwrite"):
        write_private_key(path, generate_key())
    if os.name == "posix":
        path.chmod(0o644)
        with pytest.raises(SigningError, match="0600"):
            load_private_key(path)
    bad = tmp_path / "bad.key"
    bad.write_text("not a key")
    bad.chmod(0o600)
    with pytest.raises(SigningError):
        load_private_key(bad)


# ------------------------------------------------------------------ checkpoints


def _cp_lab(tmp_path: Path) -> tuple[Lab, Checkpoint]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    lab = Lab(tmp_path, signed=True)
    lab.operator.submit_many([grant("g1"), grant("g2", res="ticket:demo-43")])
    lab.clock.advance_to(5)
    lab.operator.submit(revoke("g1"))
    cp = create_checkpoint(lab.conn, actor_id=OPERATOR, key=lab.keys[OPERATOR], tick=5)
    lab.operator.submit(grant("g3", res="ticket:t1"))  # appended after the checkpoint
    return lab, cp


def test_checkpoint_accepts_an_extended_history(tmp_path: Path) -> None:
    lab, cp = _cp_lab(tmp_path)
    assert cp.event_sequence == 3 and verify_checkpoint(lab.conn, cp) == []
    lab.close()


def test_checkpoint_detects_truncation_and_rewrite(tmp_path: Path) -> None:
    lab, cp = _cp_lab(tmp_path)
    lab.close()
    conn = raw_attacker_connection(lab.path)
    conn.execute("DELETE FROM policy_events WHERE sequence >= 3")  # cut below the checkpoint
    restore_triggers(conn)
    conn.close()
    assert verify_ledger(lab.path).ok  # the shorter chain is internally consistent...
    conn = open_ledger(lab.path)
    try:
        problems = verify_checkpoint(conn, cp)  # ...but the checkpoint exposes the truncation
    finally:
        conn.close()
    assert problems == ["policy_events: truncated below checkpointed sequence 3"]
    conn = sqlite3.connect(lab.path)
    try:
        forged = cp.model_copy(update={"event_sequence": 2})
        assert verify_checkpoint(conn, forged) == ["checkpoint hash does not match its contents"]
    finally:
        conn.close()


def test_checkpoint_from_other_ledger_or_wrong_key_rejected(tmp_path: Path) -> None:
    lab, cp = _cp_lab(tmp_path / "a")
    (tmp_path / "b").mkdir()
    (tmp_path / "c").mkdir()
    other = Lab(tmp_path / "b", signed=True)
    assert verify_checkpoint(other.conn, cp) == ["checkpoint belongs to a different ledger"]
    with pytest.raises(SigningError, match="does not match"):
        create_checkpoint(lab.conn, actor_id=OPERATOR, key=generate_key(), tick=9)
    unsigned = Lab(tmp_path / "c")
    with pytest.raises(SigningError, match="signed ledger"):
        create_checkpoint(unsigned.conn, actor_id=OPERATOR, key=generate_key(), tick=1)
    for x in (lab, other, unsigned):
        x.close()


# ------------------------------------------------------------------ CLI


def test_cli_signed_workflow_with_checkpoint(tmp_path: Path) -> None:
    run = CliRunner()

    def cli(*a: str) -> tuple[int, dict[str, object]]:
        r = run.invoke(app, list(a))
        return r.exit_code, json.loads(r.output)

    examples = Path(__file__).resolve().parents[2] / "examples"
    code, out = cli("ledger", "keygen", "--out", str(tmp_path / "op.key"))
    assert code == 0
    pub = str(out["public_key"])
    db = str(tmp_path / "l.sqlite")
    assert (
        cli("ledger", "init", "--db", db, "--operator", "op-admin", "--pubkey", pub)[1][
            "authenticity"
        ]
        == "signed"
    )
    code, out = cli(
        "ledger",
        "apply",
        "--db",
        db,
        "--operator",
        "op-admin",
        "--changes",
        str(examples / "policy.json"),
        "--at",
        "0",
    )
    assert code == 1 and out["code"] == "SIGNATURE_REQUIRED"
    assert (
        cli(
            "ledger",
            "apply",
            "--db",
            db,
            "--operator",
            "op-admin",
            "--changes",
            str(examples / "policy.json"),
            "--at",
            "0",
            "--key",
            str(tmp_path / "op.key"),
        )[0]
        == 0
    )
    cp = str(tmp_path / "cp.json")
    assert (
        cli(
            "ledger",
            "checkpoint",
            "--db",
            db,
            "--operator",
            "op-admin",
            "--key",
            str(tmp_path / "op.key"),
            "--at",
            "1",
            "--out",
            cp,
        )[0]
        == 0
    )
    code, out = cli("ledger", "verify", "--db", db, "--checkpoint", cp)
    assert code == 0 and out["authenticity"] == "signed"
    conn = raw_attacker_connection(Path(db))
    conn.execute("DELETE FROM policy_events WHERE sequence = 2")
    restore_triggers(conn)
    conn.close()
    code, out = cli("ledger", "verify", "--db", db, "--checkpoint", cp)
    assert code == 1 and out["checkpoints"][0]["problems"]  # type: ignore[index]
    assert (
        cli(
            "ledger",
            "init",
            "--db",
            str(tmp_path / "x.sqlite"),
            "--operator",
            "op-a",
            "--operator",
            "op-b",
            "--pubkey",
            pub,
        )[0]
        == 1
    )


def test_signing_does_not_change_decisions(tmp_path: Path) -> None:
    """Same program on a signed and an unsigned ledger: identical outcomes."""
    outs = []
    for signed in (False, True):
        (tmp_path / str(signed)).mkdir()
        lab = GatewayLab(tmp_path / str(signed), signed=signed)
        lab.operator.submit(grant("g1"))
        a = lab.propose("ticket", "read", "ticket:demo-42")
        lab.operator.submit(revoke("g1"))
        b = lab.propose("ticket", "read", "ticket:demo-42")
        outs.append([(r.outcome, r.reason_code, r.epoch) for r in (a, b)])
        lab.close()
    assert outs[0] == outs[1]
    _ = seq_ids  # imported for parity with other suites
