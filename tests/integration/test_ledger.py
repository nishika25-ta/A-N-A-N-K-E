"""Ledger persistence, append-only enforcement, tamper detection, restart and concurrency."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from ananke.domain import LogicalClock, PolicyEvent, RuleStatus, digest
from ananke.ledger import (
    LedgerIntegrityError,
    LedgerUnavailableError,
    OperatorChannel,
    PolicyReader,
    PolicyTransitionError,
    SchemaError,
    UnknownOperatorError,
    VerifyCode,
    init_ledger,
    load_state,
    open_ledger,
    verify_ledger,
)
from ananke.ledger.db import connect, read_transaction
from ananke_testkit import (
    OPERATOR,
    Lab,
    deny,
    grant,
    raw_attacker_connection,
    restore_triggers,
    revoke,
    seq_ids,
    supersede,
)


@pytest.fixture
def lab(tmp_path: Path) -> Lab:
    lab = Lab(tmp_path)
    yield lab  # type: ignore[misc]
    lab.close()


def _populate(lab: Lab) -> list[PolicyEvent]:
    events = lab.operator.submit_many([grant("grant-001", vu=20), deny("deny-001", res="ticket:x")])
    lab.clock.advance_to(10)
    events += [lab.operator.submit(revoke("grant-001"))]
    lab.clock.advance_to(12)
    events += [lab.operator.submit(grant("grant-002", tool="report", res="report:demo-q3"))]
    return events


def _codes(path: Path) -> set[VerifyCode]:
    return {e.code for e in verify_ledger(path).errors}


# ------------------------------------------------------------------ lifecycle


def test_init_open_verify_roundtrip(lab: Lab) -> None:
    events = _populate(lab)
    report = verify_ledger(lab.path)
    assert report.ok and report.event_count == 4 and report.epoch == 4
    assert report.head_hash == events[-1].event_hash
    state = load_state(lab.path)
    assert state.rules["grant-001"].status is RuleStatus.REVOKED
    assert report.state_digest == state.state_digest()


def test_restart_reproduces_identical_state(lab: Lab) -> None:
    _populate(lab)
    before = lab.operator.current_state().state_digest()
    lab.close()
    conn = open_ledger(lab.path)
    try:
        channel = OperatorChannel(conn, OPERATOR, LogicalClock(12).now, id_factory=seq_ids(1))
        assert channel.current_state().state_digest() == before
        channel.submit(revoke("grant-002"))  # continues the chain after restart
    finally:
        conn.close()
    assert verify_ledger(lab.path).ok


def test_missing_and_existing_files(tmp_path: Path) -> None:
    with pytest.raises(LedgerUnavailableError):
        open_ledger(tmp_path / "nope.sqlite")
    with pytest.raises(LedgerUnavailableError):
        verify_ledger(tmp_path / "nope.sqlite")
    init_ledger(tmp_path / "a.sqlite", [OPERATOR])
    with pytest.raises(LedgerUnavailableError):
        init_ledger(tmp_path / "a.sqlite", [OPERATOR])


def test_init_validates_operators(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least one"):
        init_ledger(tmp_path / "a.sqlite", [])
    with pytest.raises(ValueError, match="duplicate"):
        init_ledger(tmp_path / "b.sqlite", [OPERATOR, OPERATOR])
    with pytest.raises(ValueError, match="not a valid lowercase identifier"):
        init_ledger(tmp_path / "c.sqlite", ["Not An Id"])


def test_wal_mode_and_pragmas(lab: Lab) -> None:
    assert lab.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert lab.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert lab.conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL


# ------------------------------------------------------------------ authority boundary


def test_unknown_operator_cannot_open_channel(lab: Lab) -> None:
    with pytest.raises(UnknownOperatorError):
        OperatorChannel(lab.conn, "agent-lab-01", lab.clock.now)


def test_batch_is_atomic(lab: Lab) -> None:
    lab.operator.submit(grant("grant-001"))
    with pytest.raises(PolicyTransitionError):
        lab.operator.submit_many([grant("grant-002"), revoke("grant-404")])
    state = lab.operator.current_state()
    assert state.epoch == 1 and "grant-002" not in state.rules
    assert lab.conn.execute("SELECT COUNT(*) FROM policy_events").fetchone()[0] == 1


def test_rejected_change_leaves_no_trace(lab: Lab) -> None:
    lab.operator.submit(grant("grant-001"))
    for bad in (
        grant("grant-001"),
        revoke("grant-404"),
        supersede("grant-001", "grant-002", principal="agent-x"),
    ):
        with pytest.raises(PolicyTransitionError):
            lab.operator.submit(bad)
    assert verify_ledger(lab.path).event_count == 1


def test_operator_time_cannot_regress(lab: Lab) -> None:
    lab.clock.advance_to(5)
    lab.operator.submit(grant("grant-001"))
    channel = OperatorChannel(lab.conn, OPERATOR, lambda: 4, id_factory=seq_ids(2))
    with pytest.raises(PolicyTransitionError):
        channel.submit(grant("grant-002"))


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE policy_events SET canonical = x'00'",
        "UPDATE policy_events SET kind = 'GRANT' WHERE sequence = 3",
        "DELETE FROM policy_events WHERE sequence = 3",
        "DELETE FROM operators",
        "UPDATE operators SET actor_id = 'evil'",
    ],
)
def test_append_only_triggers_block_mutation(lab: Lab, sql: str) -> None:
    _populate(lab)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        lab.conn.execute(sql)
    assert verify_ledger(lab.path).ok


def test_forged_insert_with_valid_shape_but_unknown_actor_is_detected(lab: Lab) -> None:
    events = _populate(lab)
    lab.close()
    from ananke.ledger import build_event

    state = load_state(lab.path)
    forged = build_event(
        state,
        grant("grant-666"),
        event_id="00000000-0000-0000-0000-00000000f00d",
        actor_id="mallory",
        recorded_at=20,
    )
    conn = sqlite3.connect(lab.path, isolation_level=None)
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute(
        "INSERT INTO policy_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            forged.sequence,
            forged.event_id,
            forged.epoch,
            "GRANT",
            "mallory",
            "grant-666",
            None,
            20,
            events[-1].event_hash,
            forged.event_hash,
            forged.canonical(),
        ),
    )
    conn.close()
    assert VerifyCode.UNKNOWN_OPERATOR in _codes(lab.path)
    with pytest.raises(LedgerIntegrityError):
        load_state(lab.path)


# ------------------------------------------------------------------ tamper detection


def _tamper(path: Path, sql: str, params: tuple[object, ...] = ()) -> None:
    conn = raw_attacker_connection(path)
    conn.execute(sql, params)
    restore_triggers(conn)
    conn.close()


def test_edit_canonical_blob_detected(lab: Lab) -> None:
    _populate(lab)
    lab.close()
    row = (
        sqlite3.connect(lab.path)
        .execute("SELECT canonical FROM policy_events WHERE sequence = 3")
        .fetchone()
    )
    edited = row[0].replace(b'"kind":"REVOKE"', b'"kind":"REVOKE" ')  # non-canonical whitespace
    _tamper(lab.path, "UPDATE policy_events SET canonical = ? WHERE sequence = 3", (edited,))
    assert VerifyCode.NON_CANONICAL_EVENT in _codes(lab.path)


def test_semantic_edit_with_canonical_bytes_detected_by_hash(lab: Lab) -> None:
    _populate(lab)
    lab.close()
    raw = (
        sqlite3.connect(lab.path)
        .execute("SELECT canonical FROM policy_events WHERE sequence = 1")
        .fetchone()[0]
    )
    edited = raw.replace(b'"valid_until":20', b'"valid_until":99')
    _tamper(lab.path, "UPDATE policy_events SET canonical = ? WHERE sequence = 1", (edited,))
    assert _codes(lab.path) == {VerifyCode.CHAIN_INVALID}
    assert "EVENT_HASH_MISMATCH" in verify_ledger(lab.path).errors[0].detail


def test_column_desync_detected(lab: Lab) -> None:
    _populate(lab)
    lab.close()
    _tamper(lab.path, "UPDATE policy_events SET kind = 'GRANT' WHERE sequence = 3")
    assert VerifyCode.COLUMN_MISMATCH in _codes(lab.path)


def test_deleted_row_detected(lab: Lab) -> None:
    _populate(lab)
    lab.close()
    _tamper(lab.path, "DELETE FROM policy_events WHERE sequence = 3")
    assert VerifyCode.SEQUENCE_GAP in _codes(lab.path)


def test_truncated_tail_is_NOT_detected_without_external_anchor(lab: Lab) -> None:
    """Documented limitation: dropping the newest events leaves a valid shorter chain.

    Rollback detection requires an external checkpoint (future work, threat-model section 5).
    """
    _populate(lab)
    lab.close()
    _tamper(lab.path, "DELETE FROM policy_events WHERE sequence = 4")
    report = verify_ledger(lab.path)
    assert report.ok and report.event_count == 3  # undetected by design limitation


def test_rehashed_single_row_breaks_successor_link(lab: Lab) -> None:
    events = _populate(lab)
    lab.close()
    raw = events[0].model_dump(mode="json")
    raw["valid_until"] = 99
    raw["event_hash"] = digest({k: v for k, v in raw.items() if k != "event_hash"})
    forged = PolicyEvent.model_validate(raw)
    _tamper(
        lab.path,
        "UPDATE policy_events SET canonical = ?, event_hash = ? WHERE sequence = 1",
        (forged.canonical(), forged.event_hash),
    )
    report = verify_ledger(lab.path)
    assert not report.ok and "PREV_HASH_MISMATCH" in report.errors[0].detail


def test_garbage_blob_detected(lab: Lab) -> None:
    _populate(lab)
    lab.close()
    _tamper(lab.path, "UPDATE policy_events SET canonical = ? WHERE sequence = 2", (b"{not json",))
    assert VerifyCode.MALFORMED_EVENT in _codes(lab.path)


# ------------------------------------------------------------------ schema pinning


def test_dropped_trigger_fails_schema_check(lab: Lab) -> None:
    _populate(lab)
    lab.close()
    conn = sqlite3.connect(lab.path, isolation_level=None)
    conn.execute("DROP TRIGGER policy_events_no_update")
    conn.close()
    assert _codes(lab.path) == {VerifyCode.SCHEMA_INVALID}
    with pytest.raises(SchemaError):
        open_ledger(lab.path)


def test_edited_or_future_migration_rejected(lab: Lab) -> None:
    lab.close()
    conn = sqlite3.connect(lab.path, isolation_level=None)
    conn.execute("INSERT INTO schema_migrations VALUES (99, 'future', 'sha256:00')")
    conn.close()
    with pytest.raises(SchemaError, match="newer"):
        open_ledger(lab.path)
    conn = sqlite3.connect(lab.path, isolation_level=None)
    conn.execute("DELETE FROM schema_migrations WHERE version = 99")
    conn.execute("UPDATE schema_migrations SET digest = 'sha256:ff' WHERE version = 1")
    conn.close()
    with pytest.raises(SchemaError, match="does not match"):
        open_ledger(lab.path)


def test_non_ledger_sqlite_file_rejected(tmp_path: Path) -> None:
    p = tmp_path / "other.sqlite"
    sqlite3.connect(p).execute("CREATE TABLE t(x)").connection.close()
    with pytest.raises(SchemaError):
        open_ledger(p)


# ------------------------------------------------------------------ reader cache


def test_reader_sees_new_events_from_other_connection(lab: Lab) -> None:
    lab.operator.submit(grant("grant-001"))
    other = connect(lab.path)
    reader = PolicyReader(other)
    with read_transaction(other):
        assert reader.current_state().epoch == 1
    lab.operator.submit(revoke("grant-001"))
    with read_transaction(other):
        s = reader.current_state()
    assert s.epoch == 2 and s.rules["grant-001"].status is RuleStatus.REVOKED
    other.close()


def test_reader_detects_tampered_tail_after_cache(lab: Lab) -> None:
    lab.operator.submit(grant("grant-001"))
    other = connect(lab.path)
    reader = PolicyReader(other)
    with read_transaction(other):
        reader.current_state()
    lab.operator.submit(revoke("grant-001"))
    _tamper(lab.path, "UPDATE policy_events SET kind = 'GRANT' WHERE sequence = 2")
    with read_transaction(other), pytest.raises(LedgerIntegrityError):
        reader.current_state()
    other.close()


# ------------------------------------------------------------------ concurrency


def test_concurrent_operators_produce_a_valid_contiguous_chain(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite"
    init_ledger(path, ["op-a", "op-b"])
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def worker(actor: str, prefix: int) -> None:
        conn = open_ledger(path)
        try:
            channel = OperatorChannel(conn, actor, lambda: 0, id_factory=seq_ids(prefix))
            barrier.wait()
            for i in range(25):
                channel.submit(grant(f"{actor}-r{i}"))
        except BaseException as exc:  # surfaced via the errors list below
            errors.append(exc)
        finally:
            conn.close()

    actors = ["op-a", "op-b"]
    threads = [threading.Thread(target=worker, args=(a, i + 3)) for i, a in enumerate(actors)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    report = verify_ledger(path)
    assert report.ok and report.event_count == 50 and report.epoch == 50
