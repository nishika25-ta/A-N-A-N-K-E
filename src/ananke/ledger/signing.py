"""Operator signatures for authority records (ADR-0010, accepted).

* Each operator holds an **Ed25519 private key outside the database**. The ledger stores only the
  public key, which is registered once at trusted setup (``operator_keys``, append-only).
* Every policy event and every approval is signed over its record hash, with domain separation by
  record kind: ``ananke-sig-1\\n<kind>\\n<record_hash>``. Signatures live in ``record_signatures``
  (append-only, one per record).
* A ledger created with keys is **signed** (``ledger_config.signing = required``). Verification, the
  per-decision policy reader, the gateway's approval check and the evidence audit then fail closed
  on a missing or invalid signature. An attacker with database write access but without a private
  key can no longer forge consistent authority.
* A ledger created without keys is **unsigned** (``signing = none``). It still works, and every
  verification report says so (``authenticity: unsigned``).

Out of scope (documented): key compromise, key rotation and revocation of operator keys, and
hardware-backed or passphrase-protected key storage.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEME = "ananke-sig-1"
KEY_HEADER = "ananke-ed25519-private-key-v1"
KIND_EVENT = "policy-event"
KIND_APPROVAL = "approval"
KIND_CHECKPOINT = "checkpoint"
KINDS = frozenset({KIND_EVENT, KIND_APPROVAL, KIND_CHECKPOINT})


class SigningError(ValueError):
    """A key or signature problem. Callers must fail closed."""


# --------------------------------------------------------------------------- keys


def generate_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes_raw().hex()


def public_key_from_hex(value: str) -> Ed25519PublicKey:
    try:
        raw = bytes.fromhex(value.strip())
    except ValueError as exc:
        raise SigningError("public key is not hex") from exc
    if len(raw) != 32:
        raise SigningError("public key must be 32 bytes (64 hex characters)")
    return Ed25519PublicKey.from_public_bytes(raw)


def write_private_key(path: Path, key: Ed25519PrivateKey) -> None:
    """Create ``path`` exclusively with mode 0600. Never overwrites an existing key file."""
    seed = key.private_bytes_raw().hex()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SigningError(f"refusing to overwrite existing key file {path.name}") from exc
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(f"{KEY_HEADER}\n{seed}\n")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load a private key file. On POSIX, refuse files readable by group or others."""
    try:
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise SigningError(f"key file {path.name} must not be group/world accessible (0600)")
        lines = path.read_text(encoding="ascii").split()
    except OSError as exc:
        raise SigningError(f"cannot read key file {path.name}") from exc
    if len(lines) != 2 or lines[0] != KEY_HEADER:
        raise SigningError(f"{path.name} is not an ANANKE private key file")
    try:
        raw = bytes.fromhex(lines[1])
    except ValueError as exc:
        raise SigningError("malformed private key") from exc
    if len(raw) != 32:
        raise SigningError("malformed private key")
    return Ed25519PrivateKey.from_private_bytes(raw)


# --------------------------------------------------------------------------- signatures


def _message(kind: str, record_hash: str) -> bytes:
    if kind not in KINDS:
        raise SigningError(f"unknown record kind {kind!r}")
    return f"{SCHEME}\n{kind}\n{record_hash}".encode("ascii")


def sign(key: Ed25519PrivateKey, kind: str, record_hash: str) -> str:
    return key.sign(_message(kind, record_hash)).hex()


def verify(public_key: Ed25519PublicKey, kind: str, record_hash: str, signature_hex: str) -> bool:
    try:
        sig = bytes.fromhex(signature_hex)
        public_key.verify(sig, _message(kind, record_hash))
    except (ValueError, InvalidSignature, SigningError):
        return False
    return True


# --------------------------------------------------------------------------- ledger binding


def signing_mode(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("SELECT value FROM ledger_config WHERE key = 'signing'").fetchone()
    return None if row is None else str(row[0])


@dataclass
class Authenticator:
    """Checks record signatures against registered operator keys, per the ledger's mode.

    ``check`` returns ``None`` when the record is acceptable, otherwise a short reason. In an
    unsigned ledger every record is acceptable (the report says ``unsigned``). A missing or
    unknown signing mode fails closed.
    """

    conn: sqlite3.Connection
    mode: str | None = None
    keys: dict[str, Ed25519PublicKey] = field(default_factory=dict)

    @classmethod
    def load(cls, conn: sqlite3.Connection) -> Authenticator:
        auth = cls(conn, signing_mode(conn))
        if auth.mode == "required":
            for actor, pub in conn.execute("SELECT actor_id, public_key FROM operator_keys"):
                auth.keys[str(actor)] = public_key_from_hex(str(pub))
        return auth

    @property
    def required(self) -> bool:
        return self.mode == "required"

    @property
    def authenticity(self) -> str:
        return {"required": "signed", "none": "unsigned"}.get(self.mode or "", "invalid")

    def check(self, kind: str, record_hash: str, actor_id: str) -> str | None:
        if self.mode == "none":
            return None
        if self.mode != "required":
            return "ledger signing mode missing or unknown"
        key = self.keys.get(actor_id)
        if key is None:
            return f"no registered key for operator {actor_id!r}"
        row = self.conn.execute(
            "SELECT actor_id, signature FROM record_signatures"
            " WHERE record_kind = ? AND record_hash = ?",
            (kind, record_hash),
        ).fetchone()
        if row is None:
            return f"missing {kind} signature"
        if str(row[0]) != actor_id:
            return f"{kind} signed by a different operator"
        if not verify(key, kind, record_hash, str(row[1])):
            return f"invalid {kind} signature"
        return None


def insert_signature(
    conn: sqlite3.Connection, key: Ed25519PrivateKey, kind: str, record_hash: str, actor_id: str
) -> None:
    conn.execute(
        "INSERT INTO record_signatures(record_kind, record_hash, actor_id, signature)"
        " VALUES (?, ?, ?, ?)",
        (kind, record_hash, actor_id, sign(key, kind, record_hash)),
    )
