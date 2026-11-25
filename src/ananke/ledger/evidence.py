"""Decision log (hash-chained, append-only) and approval persistence.

Functions here run on a connection inside a caller-managed transaction: the gateway's single
``BEGIN IMMEDIATE`` transaction, or the operator channel's. They never commit by themselves.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, cast

from pydantic import ValidationError

from ananke.domain import GENESIS_HASH, Approval, Decision, digest

_DECISION_COLS = (
    "sequence, decision_id, request_id, session_id, principal_id, outcome, reason_code,"
    " epoch, evaluated_at, effect_id, prev_hash, decision_hash, canonical"
)
# S608: built only from the module constant above; no external input reaches these strings.
_DECISION_INSERT = (
    "INSERT INTO decisions (" + _DECISION_COLS + ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"  # noqa: S608
)
_DECISION_SELECT = "SELECT " + _DECISION_COLS + " FROM decisions ORDER BY sequence"  # noqa: S608


def append_decision(conn: sqlite3.Connection, fields: dict[str, Any]) -> Decision:
    """Append a decision as the successor of the current head (caller holds the write lock)."""
    head = conn.execute(
        "SELECT sequence, decision_hash FROM decisions ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    seq, prev = (1, GENESIS_HASH) if head is None else (int(head[0]) + 1, str(head[1]))
    payload = {**fields, "sequence": seq, "prev_hash": prev}
    # Validate every field strictly first (placeholder hash), then hash the validated payload.
    probe = Decision.model_validate({**payload, "decision_hash": GENESIS_HASH})
    decision = Decision.model_validate(
        {**probe.hash_payload(), "decision_hash": digest(probe.hash_payload())}
    )
    conn.execute(
        _DECISION_INSERT,
        (
            decision.sequence,
            decision.decision_id,
            decision.request_id,
            decision.session_id,
            decision.principal_id,
            decision.outcome.value,
            decision.reason_code.value,
            decision.epoch,
            decision.evaluated_at,
            decision.effect_id,
            decision.prev_hash,
            decision.decision_hash,
            decision.canonical(),
        ),
    )
    return decision


@dataclass(frozen=True, slots=True)
class DecisionLogReport:
    ok: bool
    count: int
    head_hash: str
    error: str | None = None


def verify_decisions(conn: sqlite3.Connection) -> DecisionLogReport:
    """Verify contiguity, canonical bytes, column agreement and the decision hash chain."""
    prev = GENESIS_HASH
    rows = conn.execute(_DECISION_SELECT).fetchall()
    for expected_seq, row in enumerate(rows, start=1):
        seq = cast(int, row[0])
        if seq != expected_seq:
            return DecisionLogReport(False, len(rows), prev, f"sequence gap at {expected_seq}")
        blob = row[12]
        try:
            d = Decision.model_validate_json(blob)
        except ValidationError:
            return DecisionLogReport(False, len(rows), prev, f"malformed decision {seq}")
        if d.canonical() != blob:
            return DecisionLogReport(False, len(rows), prev, f"non-canonical decision {seq}")
        columns = (
            d.sequence,
            d.decision_id,
            d.request_id,
            d.session_id,
            d.principal_id,
            d.outcome.value,
            d.reason_code.value,
            d.epoch,
            d.evaluated_at,
            d.effect_id,
            d.prev_hash,
            d.decision_hash,
        )
        if tuple(row[:12]) != columns:
            return DecisionLogReport(False, len(rows), prev, f"column mismatch at {seq}")
        if d.prev_hash != prev:
            return DecisionLogReport(False, len(rows), prev, f"prev_hash mismatch at {seq}")
        if digest(d.hash_payload()) != d.decision_hash:
            return DecisionLogReport(False, len(rows), prev, f"decision_hash mismatch at {seq}")
        prev = d.decision_hash
    return DecisionLogReport(True, len(rows), prev)


def read_decisions(conn: sqlite3.Connection) -> list[Decision]:
    return [Decision.model_validate_json(r[12]) for r in conn.execute(_DECISION_SELECT)]


# ----------------------------------------------------------------------------- approvals

_APPROVAL_COLS = (
    "sequence, approval_id, issued_by, principal_id, session_id, action_digest, issued_epoch,"
    " issued_at, expires_at, prev_hash, approval_hash, canonical"
)
_APPROVAL_INSERT = (
    "INSERT INTO approvals (" + _APPROVAL_COLS + ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"  # noqa: S608
)
_APPROVAL_SELECT = "SELECT " + _APPROVAL_COLS + " FROM approvals"  # noqa: S608


def append_approval(conn: sqlite3.Connection, fields: dict[str, Any]) -> Approval:
    """Append a chained approval issuance record (caller holds the write lock)."""
    head = conn.execute(
        "SELECT sequence, approval_hash FROM approvals ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    seq, prev = (1, GENESIS_HASH) if head is None else (int(head[0]) + 1, str(head[1]))
    probe = Approval.model_validate(
        {**fields, "sequence": seq, "prev_hash": prev, "approval_hash": GENESIS_HASH}
    )
    approval = Approval.model_validate(
        {**probe.hash_payload(), "approval_hash": digest(probe.hash_payload())}
    )
    conn.execute(
        _APPROVAL_INSERT,
        (
            approval.sequence,
            approval.approval_id,
            approval.issued_by,
            approval.principal_id,
            approval.session_id,
            approval.action_digest,
            approval.issued_epoch,
            approval.issued_at,
            approval.expires_at,
            approval.prev_hash,
            approval.approval_hash,
            approval.canonical(),
        ),
    )
    return approval


def load_approval(conn: sqlite3.Connection, approval_id: str) -> tuple[Approval, bool] | None:
    """Return (approval, consumed) or None. The approval is parsed from its canonical blob."""
    row = conn.execute(
        "SELECT a.canonical, c.approval_id IS NOT NULL FROM approvals a"
        " LEFT JOIN approval_consumptions c ON c.approval_id = a.approval_id"
        " WHERE a.approval_id = ?",
        (approval_id,),
    ).fetchone()
    if row is None:
        return None
    return Approval.model_validate_json(row[0]), bool(row[1])


def consume_approval(
    conn: sqlite3.Connection, approval_id: str, *, at: int, decision_id: str
) -> None:
    """Record single use. A second consumption violates the PRIMARY KEY and aborts."""
    conn.execute(
        "INSERT INTO approval_consumptions(approval_id, decision_id, consumed_at) VALUES (?,?,?)",
        (approval_id, decision_id, at),
    )


def read_approvals(conn: sqlite3.Connection) -> list[tuple[tuple[object, ...], Approval | None]]:
    """All approval rows in sequence order with their parsed record (None if unparseable)."""
    out: list[tuple[tuple[object, ...], Approval | None]] = []
    for row in conn.execute(_APPROVAL_SELECT + " ORDER BY sequence"):
        try:
            out.append((tuple(row), Approval.model_validate_json(row[11])))
        except ValidationError:
            out.append((tuple(row), None))
    return out


def verify_approvals(conn: sqlite3.Connection, operators: frozenset[str]) -> DecisionLogReport:
    """Verify the approval issuance chain: contiguity, canonical bytes, columns, hashes, issuer."""
    prev = GENESIS_HASH
    rows = read_approvals(conn)
    for expected_seq, (row, a) in enumerate(rows, start=1):
        seq = cast(int, row[0])
        if seq != expected_seq:
            return DecisionLogReport(False, len(rows), prev, f"approval sequence gap at {seq}")
        if a is None:
            return DecisionLogReport(False, len(rows), prev, f"malformed approval {seq}")
        if a.canonical() != row[11]:
            return DecisionLogReport(False, len(rows), prev, f"non-canonical approval {seq}")
        columns = (
            a.sequence,
            a.approval_id,
            a.issued_by,
            a.principal_id,
            a.session_id,
            a.action_digest,
            a.issued_epoch,
            a.issued_at,
            a.expires_at,
            a.prev_hash,
            a.approval_hash,
        )
        if tuple(row[:11]) != columns:
            return DecisionLogReport(False, len(rows), prev, f"approval column mismatch {seq}")
        if a.prev_hash != prev or digest(a.hash_payload()) != a.approval_hash:
            return DecisionLogReport(False, len(rows), prev, f"approval chain broken at {seq}")
        if a.issued_by not in operators:
            return DecisionLogReport(False, len(rows), prev, f"approval {seq}: unknown issuer")
        prev = a.approval_hash
    return DecisionLogReport(True, len(rows), prev)


def outstanding_approvals(conn: sqlite3.Connection) -> Sequence[Approval]:
    rows = conn.execute(
        "SELECT a.canonical FROM approvals a LEFT JOIN approval_consumptions c"
        " ON c.approval_id = a.approval_id WHERE c.approval_id IS NULL ORDER BY a.sequence"
    ).fetchall()
    return [Approval.model_validate_json(r[0]) for r in rows]
