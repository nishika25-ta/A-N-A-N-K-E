"""Signed external checkpoints of the ledger heads (ADR-0010, accepted).

A checkpoint records the head (sequence, hash) of the policy, approval and decision chains, signed
by a registered operator, and is stored **outside** the database (e.g. another disk, a ticket or an
email to oneself). ``verify_checkpoint`` then detects what the hash chains alone cannot:

* **tail truncation**: the database has fewer records than the checkpoint saw;
* **rewrite below the checkpoint**: the record at the checkpointed sequence has a different hash.

A checkpoint can only vouch for history up to its own head. Records appended after it are covered by
the next checkpoint.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Final, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field, StrictInt, StrictStr

from ananke.domain import GENESIS_HASH, digest
from ananke.domain.models import Digest, Identifier, StrictModel, Tick
from ananke.ledger.db import read_transaction
from ananke.ledger.signing import (
    KIND_CHECKPOINT,
    SigningError,
    public_key_from_hex,
    public_key_hex,
    sign,
    signing_mode,
    verify,
)

CHECKPOINT_SCHEMA: Final = "ananke.checkpoint/0"
# Literal statements per chain (no string-built SQL): (prefix, table, head query, at-sequence query)
_CHAINS = (
    (
        "event",
        "policy_events",
        "SELECT sequence, event_hash FROM policy_events ORDER BY sequence DESC LIMIT 1",
        "SELECT event_hash FROM policy_events WHERE sequence = ?",
    ),
    (
        "approval",
        "approvals",
        "SELECT sequence, approval_hash FROM approvals ORDER BY sequence DESC LIMIT 1",
        "SELECT approval_hash FROM approvals WHERE sequence = ?",
    ),
    (
        "decision",
        "decisions",
        "SELECT sequence, decision_hash FROM decisions ORDER BY sequence DESC LIMIT 1",
        "SELECT decision_hash FROM decisions WHERE sequence = ?",
    ),
)


class Checkpoint(StrictModel):
    schema_version: Literal["ananke.checkpoint/0"] = CHECKPOINT_SCHEMA
    ledger_id: StrictStr
    issued_by: Identifier
    issued_at: Tick
    event_sequence: StrictInt = Field(ge=0)
    event_head: Digest
    approval_sequence: StrictInt = Field(ge=0)
    approval_head: Digest
    decision_sequence: StrictInt = Field(ge=0)
    decision_head: Digest
    checkpoint_hash: Digest
    signature: StrictStr

    def body(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"checkpoint_hash", "signature"})


def _heads(conn: sqlite3.Connection) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for prefix, _table, head_sql, _at_sql in _CHAINS:
        row = conn.execute(head_sql).fetchone()
        out[f"{prefix}_sequence"] = 0 if row is None else int(row[0])
        out[f"{prefix}_head"] = GENESIS_HASH if row is None else str(row[1])
    return out


def _ledger_id(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT value FROM ledger_config WHERE key = 'ledger_id'").fetchone()
    if row is None:
        raise SigningError("ledger has no ledger_id")
    return str(row[0])


def create_checkpoint(
    conn: sqlite3.Connection, *, actor_id: str, key: Ed25519PrivateKey, tick: int
) -> Checkpoint:
    """Sign the current heads. Only for signed ledgers, by a registered operator key."""
    with read_transaction(conn):
        if signing_mode(conn) != "required":
            raise SigningError("checkpoints require a signed ledger")
        reg = conn.execute(
            "SELECT public_key FROM operator_keys WHERE actor_id = ?", (actor_id,)
        ).fetchone()
        if reg is None or str(reg[0]) != public_key_hex(key):
            raise SigningError(f"key does not match the registered key of {actor_id!r}")
        body = {
            "schema_version": CHECKPOINT_SCHEMA,
            "ledger_id": _ledger_id(conn),
            "issued_by": actor_id,
            "issued_at": tick,
            **_heads(conn),
        }
    h = digest(body)
    return Checkpoint.model_validate(
        {**body, "checkpoint_hash": h, "signature": sign(key, KIND_CHECKPOINT, h)}
    )


def verify_checkpoint(conn: sqlite3.Connection, cp: Checkpoint) -> list[str]:
    """Return problems (empty list = the database extends the checkpointed history intact)."""
    problems: list[str] = []
    if digest(cp.body()) != cp.checkpoint_hash:
        return ["checkpoint hash does not match its contents"]
    with read_transaction(conn):
        try:
            if cp.ledger_id != _ledger_id(conn):
                return ["checkpoint belongs to a different ledger"]
        except SigningError as exc:
            return [str(exc)]
        reg = conn.execute(
            "SELECT public_key FROM operator_keys WHERE actor_id = ?", (cp.issued_by,)
        ).fetchone()
        if reg is None:
            return [f"checkpoint issuer {cp.issued_by!r} has no registered key"]
        if not verify(
            public_key_from_hex(str(reg[0])), KIND_CHECKPOINT, cp.checkpoint_hash, cp.signature
        ):
            return ["invalid checkpoint signature"]
        for prefix, table, _head_sql, at_sql in _CHAINS:
            seq = getattr(cp, f"{prefix}_sequence")
            head = getattr(cp, f"{prefix}_head")
            if seq == 0:
                continue
            row = conn.execute(at_sql, (seq,)).fetchone()
            if row is None:
                problems.append(f"{table}: truncated below checkpointed sequence {seq}")
            elif str(row[0]) != head:
                problems.append(f"{table}: record {seq} differs from the checkpoint")
    return problems
