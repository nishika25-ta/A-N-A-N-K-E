"""Ledger persistence: initialization, strict reading, verification, and the operator channel.

Separation of capabilities (ADR-0003):

* :class:`OperatorChannel` is the **only** writer of policy events and approvals. It is built from
  a registered operator identity and is never handed to agent or provider code.
* :class:`PolicyReader` gives read-only, verified access to the current policy state. The gateway
  uses it inside its own transaction.
"""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from ananke.domain import (
    GENESIS_HASH,
    ActionCore,
    Approval,
    PolicyChange,
    PolicyEvent,
    validate_identifier,
)
from ananke.ledger.db import (
    LATEST_VERSION,
    LedgerUnavailableError,
    SchemaError,
    check_schema,
    check_schema_objects,
    connect,
    migrate,
    read_transaction,
    write_transaction,
)
from ananke.ledger.evidence import append_approval, verify_approvals, verify_decisions
from ananke.ledger.reducer import (
    EMPTY_STATE,
    PolicyState,
    PolicyTransitionError,
    TransitionError,
    build_event,
    check_chain,
    reduce_events,
)

IdFactory = Callable[[], str]
TickSource = Callable[[], int]


def uuid4_factory() -> str:
    return str(uuid.uuid4())


class LedgerIntegrityError(RuntimeError):
    """The ledger failed verification. All effects must stop (fail closed)."""

    def __init__(self, report: VerificationReport) -> None:
        first = report.errors[0] if report.errors else None
        super().__init__(f"ledger integrity failure: {first.code if first else 'unknown'}")
        self.report = report


class UnknownOperatorError(PermissionError):
    """The actor is not a registered operator."""


class VerifyCode(StrEnum):
    SCHEMA_INVALID = "SCHEMA_INVALID"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    MALFORMED_EVENT = "MALFORMED_EVENT"
    NON_CANONICAL_EVENT = "NON_CANONICAL_EVENT"
    COLUMN_MISMATCH = "COLUMN_MISMATCH"
    CHAIN_INVALID = "CHAIN_INVALID"
    UNKNOWN_OPERATOR = "UNKNOWN_OPERATOR"
    DECISION_LOG_INVALID = "DECISION_LOG_INVALID"
    APPROVAL_LOG_INVALID = "APPROVAL_LOG_INVALID"


@dataclass(frozen=True, slots=True)
class VerifyIssue:
    code: VerifyCode
    sequence: int | None
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {"code": self.code.value, "sequence": self.sequence, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class VerificationReport:
    ok: bool
    schema_version: int | None
    event_count: int
    epoch: int
    head_hash: str
    state_digest: str | None
    errors: tuple[VerifyIssue, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "schema_version": self.schema_version,
            "event_count": self.event_count,
            "epoch": self.epoch,
            "head_hash": self.head_hash,
            "state_digest": self.state_digest,
            "errors": [e.as_dict() for e in self.errors],
        }


# --------------------------------------------------------------------------- initialization


def init_ledger(path: Path | str, operators: Sequence[str], *, registered_at: int = 0) -> None:
    """Create a new ledger database with the given operator identities (trusted setup)."""
    if not operators:
        raise ValueError("at least one operator identity is required")
    ids = [validate_identifier(op, "operator") for op in operators]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate operator identity")
    db_path = Path(path)
    conn = connect(db_path, create=True)
    try:
        migrate(conn)
        with write_transaction(conn):
            conn.executemany(
                "INSERT INTO operators(actor_id, registered_at) VALUES (?, ?)",
                [(op, registered_at) for op in ids],
            )
    except BaseException:
        conn.close()
        # Never leave a half-initialized ledger behind (it would block every retry).
        for suffix in ("", "-wal", "-shm"):
            Path(str(db_path) + suffix).unlink(missing_ok=True)
        raise
    conn.close()


def open_ledger(path: Path | str) -> sqlite3.Connection:
    """Open an existing ledger and require the exact known schema (fail closed)."""
    conn = connect(path, create=False)
    try:
        check_schema(conn)
    except SchemaError:
        conn.close()
        raise
    return conn


# --------------------------------------------------------------------------- reading


_COLS = (
    "sequence, event_id, epoch, kind, actor_id, rule_id, target_rule_id,"
    " recorded_at, prev_hash, event_hash, canonical"
)
# S608: built only from the module constant above; no external input reaches these strings.
_SELECT_ALL = "SELECT " + _COLS + " FROM policy_events ORDER BY sequence"  # noqa: S608
_SELECT_AFTER = "SELECT " + _COLS + " FROM policy_events WHERE sequence > ? ORDER BY sequence"  # noqa: S608
_INSERT = "INSERT INTO policy_events (" + _COLS + ") VALUES (?,?,?,?,?,?,?,?,?,?,?)"  # noqa: S608


def _parse_row(row: tuple[object, ...]) -> tuple[PolicyEvent | None, list[VerifyIssue]]:
    seq = cast(int, row[0])
    blob = row[10]
    if not isinstance(blob, bytes):
        return None, [VerifyIssue(VerifyCode.MALFORMED_EVENT, seq, "canonical column not a BLOB")]
    try:
        event = PolicyEvent.model_validate_json(blob)
    except ValidationError as exc:
        return None, [
            VerifyIssue(VerifyCode.MALFORMED_EVENT, seq, f"{exc.error_count()} validation errors")
        ]
    issues: list[VerifyIssue] = []
    if event.canonical() != blob:
        issues.append(VerifyIssue(VerifyCode.NON_CANONICAL_EVENT, seq, "bytes are not canonical"))
    columns = (
        event.sequence,
        event.event_id,
        event.epoch,
        event.kind.value,
        event.actor_id,
        event.rule_id,
        event.target_rule_id,
        event.recorded_at,
        event.prev_hash,
        event.event_hash,
    )
    if tuple(row[:10]) != columns:
        issues.append(VerifyIssue(VerifyCode.COLUMN_MISMATCH, seq, "index columns disagree"))
    return event, issues


def _verify_rows(
    rows: Sequence[tuple[object, ...]], start: PolicyState, operators: frozenset[str]
) -> tuple[PolicyState, list[VerifyIssue]]:
    state = start
    expected_seq = start.last_sequence + 1
    issues: list[VerifyIssue] = []
    events: list[PolicyEvent] = []
    for row in rows:
        seq = cast(int, row[0])
        if seq != expected_seq:
            issues.append(
                VerifyIssue(VerifyCode.SEQUENCE_GAP, seq, f"expected sequence {expected_seq}")
            )
            break
        expected_seq += 1
        event, row_issues = _parse_row(row)
        issues.extend(row_issues)
        if event is None or row_issues:
            break
        if event.actor_id not in operators:
            issues.append(VerifyIssue(VerifyCode.UNKNOWN_OPERATOR, seq, "actor not registered"))
            break
        events.append(event)
    if issues:
        return state, issues
    try:
        state = reduce_events(events, start)
    except PolicyTransitionError as exc:
        issues.append(VerifyIssue(VerifyCode.CHAIN_INVALID, None, str(exc)))
    return state, issues


def _operators(conn: sqlite3.Connection) -> frozenset[str]:
    return frozenset(str(r[0]) for r in conn.execute("SELECT actor_id FROM operators"))


def _schema_report(detail: str) -> VerificationReport:
    return VerificationReport(
        ok=False,
        schema_version=None,
        event_count=0,
        epoch=0,
        head_hash=GENESIS_HASH,
        state_digest=None,
        errors=(VerifyIssue(VerifyCode.SCHEMA_INVALID, None, detail),),
    )


def verify_connection(conn: sqlite3.Connection) -> VerificationReport:
    """Full verification: schema, triggers, contiguity, canonical bytes, columns, chain, replay."""
    try:
        check_schema(conn)
    except SchemaError as exc:
        return _schema_report(str(exc))
    with read_transaction(conn):
        rows = conn.execute(_SELECT_ALL).fetchall()
        state, issues = _verify_rows(rows, EMPTY_STATE, _operators(conn))
        decisions = verify_decisions(conn)
        approvals = verify_approvals(conn, _operators(conn))
    if not decisions.ok:
        issues.append(
            VerifyIssue(VerifyCode.DECISION_LOG_INVALID, None, decisions.error or "invalid")
        )
    if not approvals.ok:
        issues.append(
            VerifyIssue(VerifyCode.APPROVAL_LOG_INVALID, None, approvals.error or "invalid")
        )
    return VerificationReport(
        ok=not issues,
        schema_version=LATEST_VERSION,
        event_count=len(rows),
        epoch=state.epoch,
        head_hash=state.head_hash,
        state_digest=state.state_digest() if not issues else None,
        errors=tuple(issues),
    )


def verify_ledger(path: Path | str) -> VerificationReport:
    conn = connect(path, create=False)
    try:
        return verify_connection(conn)
    finally:
        conn.close()


class PolicyReader:
    """Verified, incrementally cached read access to the current policy state.

    :meth:`current_state` must be called inside the caller's transaction so that the state it
    returns is the state that transaction will commit against. The cache is valid only if the
    head row (sequence, event_hash) still matches. New rows are verified as a chain continuation.
    Any mismatch triggers a full re-verification, and failure raises LedgerIntegrityError.

    Limitation: rows *older* than the cached head are re-verified only on a full reload or
    by ``ananke ledger verify``. In-place rewrites of old rows by an attacker with file access are
    detected then, not on every decision (docs/threat-model.md).
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._state: PolicyState | None = None
        self._operators: frozenset[str] | None = None

    def invalidate(self) -> None:
        self._state = None
        self._operators = None

    def current_state(self) -> PolicyState:
        conn = self._conn
        try:
            check_schema_objects(conn)  # dropped/replaced trigger or altered table: fail closed
        except SchemaError as exc:
            self.invalidate()
            raise LedgerIntegrityError(_schema_report(str(exc))) from exc
        head = conn.execute(
            "SELECT sequence, event_hash FROM policy_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        head_seq, head_hash = (0, GENESIS_HASH) if head is None else (int(head[0]), str(head[1]))
        cached = self._state
        if cached is not None and (cached.last_sequence, cached.head_hash) == (head_seq, head_hash):
            return cached
        if self._operators is None:
            self._operators = _operators(conn)
        if cached is not None and head_seq > cached.last_sequence:
            rows = conn.execute(_SELECT_AFTER, (cached.last_sequence,)).fetchall()
            # New operators may have been registered; refresh before verifying the tail.
            self._operators = _operators(conn)
            state, issues = _verify_rows(rows, cached, self._operators)
            if not issues and (state.last_sequence, state.head_hash) == (head_seq, head_hash):
                self._state = state
                return state
        return self._full_reload()

    def _full_reload(self) -> PolicyState:
        self._state = None
        conn = self._conn
        self._operators = _operators(conn)
        rows = conn.execute(_SELECT_ALL).fetchall()
        state, issues = _verify_rows(rows, EMPTY_STATE, self._operators)
        if issues:
            raise LedgerIntegrityError(
                VerificationReport(
                    ok=False,
                    schema_version=LATEST_VERSION,
                    event_count=len(rows),
                    epoch=state.epoch,
                    head_hash=state.head_hash,
                    state_digest=None,
                    errors=tuple(issues),
                )
            )
        self._state = state
        return state


def load_state(path: Path | str) -> PolicyState:
    """Open, verify fully and reduce. Raises on any integrity problem."""
    conn = open_ledger(path)
    try:
        with read_transaction(conn):
            return PolicyReader(conn).current_state()
    finally:
        conn.close()


# --------------------------------------------------------------------------- operator channel


class OperatorChannel:
    """The trusted operator interface: the only path that mutates authority.

    Authentication in Phases 1-6 is *capability possession plus registration*: the channel can be
    built only for an identity listed in the ``operators`` table, and the object is never given to
    agent code. OS-level authentication is Phase 7/8 work (ADR-0003).
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        actor_id: str,
        clock: TickSource,
        *,
        id_factory: IdFactory = uuid4_factory,
    ) -> None:
        validate_identifier(actor_id, "operator")
        row = conn.execute("SELECT 1 FROM operators WHERE actor_id = ?", (actor_id,)).fetchone()
        if row is None:
            raise UnknownOperatorError(f"{actor_id!r} is not a registered operator")
        self._conn = conn
        self._actor_id = actor_id
        self._clock = clock
        self._ids = id_factory
        self._reader = PolicyReader(conn)

    @property
    def actor_id(self) -> str:
        return self._actor_id

    def submit(self, change: PolicyChange) -> PolicyEvent:
        return self.submit_many([change])[0]

    def submit_many(self, changes: Sequence[PolicyChange]) -> list[PolicyEvent]:
        """Append ``changes`` atomically: all are committed, or none are."""
        if not changes:
            return []
        committed: list[PolicyEvent] = []
        with write_transaction(self._conn) as conn:
            state = self._reader.current_state()
            now = self._clock()
            for change in changes:
                event = build_event(
                    state, change, event_id=self._ids(), actor_id=self._actor_id, recorded_at=now
                )
                check_chain(state, event)
                conn.execute(
                    _INSERT,
                    (
                        event.sequence,
                        event.event_id,
                        event.epoch,
                        event.kind.value,
                        event.actor_id,
                        event.rule_id,
                        event.target_rule_id,
                        event.recorded_at,
                        event.prev_hash,
                        event.event_hash,
                        event.canonical(),
                    ),
                )
                state = reduce_events([event], state)
                committed.append(event)
        self._reader.invalidate()
        return committed

    def issue_approval(self, action: ActionCore, *, expires_at: int) -> Approval:
        """Approve one exact action for the current epoch, single use, until ``expires_at``.

        The operator approves the *action itself*; a digest supplied by agent code is never
        accepted. Any later accepted policy event makes this approval stale (ADR-0001).
        """
        with write_transaction(self._conn) as conn:
            state = self._reader.current_state()
            if state.epoch < 1:
                raise PolicyTransitionError(
                    TransitionError.TARGET_UNKNOWN, "cannot approve against an empty policy"
                )
            now = self._clock()
            if expires_at <= now:
                raise ValueError("expires_at must be in the future")
            approval = append_approval(
                conn,
                {
                    "approval_id": self._ids(),
                    "issued_by": self._actor_id,
                    "principal_id": action.principal_id,
                    "session_id": action.session_id,
                    "action_digest": action.digest(),
                    "issued_epoch": state.epoch,
                    "issued_at": now,
                    "expires_at": expires_at,
                },
            )
        return approval

    def current_state(self) -> PolicyState:
        with read_transaction(self._conn):
            return self._reader.current_state()


def validate_changes(
    changes: Sequence[PolicyChange], start: PolicyState = EMPTY_STATE
) -> PolicyState:
    """Dry-run: apply changes in memory with a synthetic chain. Raises PolicyTransitionError."""
    state = start
    for change in changes:
        event = build_event(
            state,
            change,
            event_id=str(uuid.UUID(int=state.last_sequence + 1)),
            actor_id="dry-run",
            recorded_at=state.last_recorded_at,
        )
        state = reduce_events([event], state)
    return state


__all__ = [
    "LedgerIntegrityError",
    "LedgerUnavailableError",
    "OperatorChannel",
    "PolicyReader",
    "SchemaError",
    "UnknownOperatorError",
    "VerificationReport",
    "VerifyCode",
    "VerifyIssue",
    "init_ledger",
    "load_state",
    "open_ledger",
    "uuid4_factory",
    "validate_changes",
    "verify_connection",
    "verify_ledger",
]
