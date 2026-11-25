"""SQLite connection handling and versioned, digest-pinned migrations.

* WAL journal, ``synchronous=FULL``, foreign keys on, explicit transactions only
  (``isolation_level=None``; writers use ``BEGIN IMMEDIATE``).
* Every migration is identified by (version, name, sha256 of its SQL). On open, the applied
  migrations must be a prefix of the known list with identical digests. Otherwise the database is
  rejected (fail closed): an unknown future schema or an edited migration is not trusted.
* Append-only tables are protected by triggers. This is application-level defense only: an
  attacker with write access to the file can drop triggers. Hash-chain verification is the
  detection layer (docs/threat-model.md section 5).
"""

from __future__ import annotations

import functools
import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


class LedgerUnavailableError(RuntimeError):
    """The ledger database is missing, unreadable or locked beyond the timeout."""


class SchemaError(RuntimeError):
    """The database schema is unknown, edited or incomplete."""


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


def _append_only(table: str) -> str:
    return f"""
CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table}
BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END;
CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table}
BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END;
"""


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        1,
        "policy_ledger",
        """
CREATE TABLE operators (
  actor_id      TEXT PRIMARY KEY,
  registered_at INTEGER NOT NULL CHECK (registered_at >= 0)
) STRICT;

CREATE TABLE policy_events (
  sequence       INTEGER PRIMARY KEY CHECK (sequence >= 1),
  event_id       TEXT NOT NULL UNIQUE,
  epoch          INTEGER NOT NULL UNIQUE CHECK (epoch >= 1),
  kind           TEXT NOT NULL CHECK (kind IN ('GRANT','DENY','REVOKE','SUPERSEDE')),
  actor_id       TEXT NOT NULL REFERENCES operators(actor_id),
  rule_id        TEXT,
  target_rule_id TEXT,
  recorded_at    INTEGER NOT NULL CHECK (recorded_at >= 0),
  prev_hash      TEXT NOT NULL,
  event_hash     TEXT NOT NULL UNIQUE,
  canonical      BLOB NOT NULL
) STRICT;
"""
        + _append_only("operators")
        + _append_only("policy_events"),
    ),
    Migration(
        2,
        "gateway_runtime",
        """
CREATE TABLE approvals (
  sequence       INTEGER PRIMARY KEY CHECK (sequence >= 1),
  approval_id    TEXT NOT NULL UNIQUE,
  issued_by      TEXT NOT NULL REFERENCES operators(actor_id),
  principal_id   TEXT NOT NULL,
  session_id     TEXT NOT NULL,
  action_digest  TEXT NOT NULL,
  issued_epoch   INTEGER NOT NULL CHECK (issued_epoch >= 1),
  issued_at      INTEGER NOT NULL CHECK (issued_at >= 0),
  expires_at     INTEGER NOT NULL,
  prev_hash      TEXT NOT NULL,
  approval_hash  TEXT NOT NULL UNIQUE,
  canonical      BLOB NOT NULL,
  CHECK (expires_at > issued_at)
) STRICT;

-- Single use is structural: one consumption row per approval (PRIMARY KEY), append-only.
CREATE TABLE approval_consumptions (
  approval_id  TEXT PRIMARY KEY REFERENCES approvals(approval_id),
  decision_id  TEXT NOT NULL UNIQUE,
  consumed_at  INTEGER NOT NULL CHECK (consumed_at >= 0)
) STRICT;

CREATE TABLE decisions (
  sequence        INTEGER PRIMARY KEY CHECK (sequence >= 1),
  decision_id     TEXT NOT NULL UNIQUE,
  request_id      TEXT,
  session_id      TEXT,
  principal_id    TEXT,
  outcome         TEXT NOT NULL CHECK (outcome IN ('ALLOW','DENY','NEEDS_APPROVAL')),
  reason_code     TEXT NOT NULL,
  epoch           INTEGER NOT NULL CHECK (epoch >= 0),
  evaluated_at    INTEGER NOT NULL CHECK (evaluated_at >= 0),
  effect_id       TEXT,
  prev_hash       TEXT NOT NULL,
  decision_hash   TEXT NOT NULL UNIQUE,
  canonical       BLOB NOT NULL
) STRICT;

CREATE TABLE idempotency (
  session_id      TEXT NOT NULL,
  principal_id    TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  action_digest   TEXT NOT NULL,
  decision_id     TEXT NOT NULL REFERENCES decisions(decision_id),
  PRIMARY KEY (session_id, principal_id, idempotency_key)
) STRICT;

-- Synthetic lab state. Only the gateway's effect handlers write here.
CREATE TABLE lab_records (
  resource   TEXT PRIMARY KEY,
  body       BLOB NOT NULL,
  version    INTEGER NOT NULL CHECK (version >= 1)
) STRICT;

CREATE TABLE lab_effects (
  effect_id   TEXT PRIMARY KEY,
  decision_id TEXT NOT NULL UNIQUE,
  tool_id     TEXT NOT NULL,
  operation   TEXT NOT NULL,
  resource    TEXT NOT NULL,
  committed_at INTEGER NOT NULL
) STRICT;
"""
        + _append_only("approvals")
        + _append_only("approval_consumptions")
        + _append_only("decisions")
        + _append_only("idempotency")
        + _append_only("lab_effects"),
    ),
    Migration(
        3,
        "operator_signatures",
        """
-- Ledger-wide settings written once at trusted setup: 'signing' (required|none), 'ledger_id'.
CREATE TABLE ledger_config (
  key    TEXT PRIMARY KEY,
  value  TEXT NOT NULL
) STRICT;

-- Ed25519 public keys of operators (ADR-0010). Private keys never enter the database.
CREATE TABLE operator_keys (
  actor_id      TEXT PRIMARY KEY REFERENCES operators(actor_id),
  public_key    TEXT NOT NULL CHECK (length(public_key) = 64),
  registered_at INTEGER NOT NULL CHECK (registered_at >= 0)
) STRICT;

-- One signature per authority record, over its record hash (domain-separated by kind).
CREATE TABLE record_signatures (
  record_kind  TEXT NOT NULL CHECK (record_kind IN ('policy-event', 'approval')),
  record_hash  TEXT NOT NULL,
  actor_id     TEXT NOT NULL REFERENCES operators(actor_id),
  signature    TEXT NOT NULL CHECK (length(signature) = 128),
  PRIMARY KEY (record_kind, record_hash)
) STRICT;
"""
        + _append_only("ledger_config")
        + _append_only("operator_keys")
        + _append_only("record_signatures"),
    ),
)

LATEST_VERSION = MIGRATIONS[-1].version
EXPECTED_TRIGGERS = frozenset(
    {
        "operators_no_update",
        "operators_no_delete",
        "policy_events_no_update",
        "policy_events_no_delete",
        "approvals_no_update",
        "approvals_no_delete",
        "approval_consumptions_no_update",
        "approval_consumptions_no_delete",
        "decisions_no_update",
        "decisions_no_delete",
        "idempotency_no_update",
        "idempotency_no_delete",
        "lab_effects_no_update",
        "lab_effects_no_delete",
        "ledger_config_no_update",
        "ledger_config_no_delete",
        "operator_keys_no_update",
        "operator_keys_no_delete",
        "record_signatures_no_update",
        "record_signatures_no_delete",
    }
)

BUSY_TIMEOUT_MS = 5000


_URI_SAFE = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/:")


def _sqlite_uri(path: Path, mode: str) -> str:
    """Build a ``file:`` URI with every unsafe byte percent-encoded.

    Without this, '#', '?' and '%' in a path would be read as URI syntax and SQLite would open a
    *different* file than the one the existence checks inspected.
    """
    raw = path.resolve().as_posix()
    if not raw.startswith("/"):
        raw = "/" + raw  # Windows drive paths: file:/C:/...
    encoded = "".join(chr(b) if b in _URI_SAFE else f"%{b:02X}" for b in raw.encode("utf-8"))
    return f"file:{encoded}?mode={mode}"


def connect(path: Path | str, *, create: bool = False) -> sqlite3.Connection:
    """Open a ledger connection.

    ``create=False``: the file must exist (else LedgerUnavailableError).
    ``create=True``: the file is created *exclusively* (``O_EXCL``), so a concurrent or
    pre-existing file is never reused.
    """
    db_path = Path(path)
    if create:
        try:
            with db_path.open("xb"):
                pass
        except FileExistsError as exc:
            raise LedgerUnavailableError(
                f"refusing to create over existing file: {db_path.name}"
            ) from exc
        except OSError as exc:
            raise LedgerUnavailableError(f"cannot create ledger: {exc.strerror}") from exc
    elif not db_path.is_file():
        raise LedgerUnavailableError(f"ledger database not found: {db_path.name}")
    try:
        conn = sqlite3.connect(
            _sqlite_uri(db_path, "rw"),
            uri=True,
            isolation_level=None,
            timeout=BUSY_TIMEOUT_MS / 1000,
            check_same_thread=True,
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA trusted_schema=OFF")
    except sqlite3.Error as exc:
        raise LedgerUnavailableError(f"cannot open ledger: {exc}") from exc
    return conn


@contextmanager
def write_transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """``BEGIN IMMEDIATE`` ... ``COMMIT``. Any exception rolls back and propagates.

    ``sqlite3.OperationalError`` (lock timeout, disk full, I/O error) at BEGIN, inside the body
    or at COMMIT is re-raised as :class:`LedgerUnavailableError`, so callers can tell
    infrastructure unavailability apart from logic errors.
    """
    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as exc:
        raise LedgerUnavailableError(f"cannot acquire write lock: {exc}") from exc
    try:
        yield conn
    except sqlite3.OperationalError as exc:
        _rollback(conn)
        raise LedgerUnavailableError(f"ledger I/O failure: {exc}") from exc
    except BaseException:
        _rollback(conn)
        raise
    try:
        conn.execute("COMMIT")
    except sqlite3.OperationalError as exc:
        # A failed COMMIT must not leave the connection mid-transaction.
        _rollback(conn)
        raise LedgerUnavailableError(f"commit failed: {exc}") from exc
    except BaseException:
        _rollback(conn)
        raise


def _rollback(conn: sqlite3.Connection) -> None:
    if conn.in_transaction:
        conn.execute("ROLLBACK")


@contextmanager
def read_transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """A consistent read snapshot (``BEGIN DEFERRED``; WAL readers never block the writer)."""
    conn.execute("BEGIN")
    try:
        yield conn
    finally:
        conn.execute("ROLLBACK")


def migrate(conn: sqlite3.Connection) -> int:
    """Apply missing migrations in one transaction. Returns the resulting schema version."""
    with write_transaction(conn):
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version INTEGER PRIMARY KEY, name TEXT NOT NULL, digest TEXT NOT NULL) STRICT"
        )
        applied = _applied(conn)
        _check_prefix(applied)
        for m in MIGRATIONS[len(applied) :]:
            # Statements are executed one by one: executescript() would COMMIT implicitly and
            # break the all-or-nothing migration transaction.
            for statement in _split_sql(m.sql):
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_migrations(version, name, digest) VALUES (?, ?, ?)",
                (m.version, m.name, m.digest),
            )
    return LATEST_VERSION


def schema_fingerprint(conn: sqlite3.Connection) -> str:
    """Digest of every user schema object (type, name, table, whitespace-normalized SQL)."""
    rows = conn.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master"
        " WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    canon = "\n".join(f"{t}|{n}|{tbl}|{' '.join((sql or '').split())}" for t, n, tbl, sql in rows)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


@functools.cache
def expected_schema_fingerprint() -> str:
    """Fingerprint of a fresh in-memory database built from MIGRATIONS (computed once)."""
    mem = sqlite3.connect(":memory:", isolation_level=None)
    try:
        migrate(mem)
        return schema_fingerprint(mem)
    finally:
        mem.close()


def check_schema_objects(conn: sqlite3.Connection) -> None:
    """Fast per-transaction check that no table, trigger or index was added, dropped or altered."""
    try:
        actual = schema_fingerprint(conn)
    except sqlite3.Error as exc:
        raise SchemaError(f"cannot read schema: {exc}") from exc
    if actual != expected_schema_fingerprint():
        raise SchemaError("schema objects differ from the pinned migration definitions")


def check_schema(conn: sqlite3.Connection) -> None:
    """Raise SchemaError unless the schema is exactly the latest known one, triggers intact."""
    try:
        applied = _applied(conn)
    except sqlite3.Error as exc:
        raise SchemaError(f"cannot read schema_migrations: {exc}") from exc
    _check_prefix(applied)
    if len(applied) != len(MIGRATIONS):
        raise SchemaError(f"schema at version {len(applied)}, expected {LATEST_VERSION}")
    triggers = {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
    }
    missing = EXPECTED_TRIGGERS - triggers
    if missing:
        raise SchemaError(f"append-only triggers missing: {sorted(missing)}")
    check_schema_objects(conn)


def _applied(conn: sqlite3.Connection) -> list[tuple[int, str, str]]:
    rows = conn.execute(
        "SELECT version, name, digest FROM schema_migrations ORDER BY version"
    ).fetchall()
    return [(int(v), str(n), str(d)) for v, n, d in rows]


def _check_prefix(applied: list[tuple[int, str, str]]) -> None:
    if len(applied) > len(MIGRATIONS):
        raise SchemaError("database schema is newer than this code (unknown migrations)")
    for (version, name, dig), known in zip(applied, MIGRATIONS, strict=False):
        if (version, name, dig) != (known.version, known.name, known.digest):
            raise SchemaError(f"migration {version} does not match the known definition")


def _split_sql(sql: str) -> list[str]:
    """Split a migration into statements, keeping trigger bodies (BEGIN ... END;) intact."""
    statements: list[str] = []
    buf: list[str] = []
    for line in sql.splitlines():
        if line.strip().startswith("--") or not line.strip():
            continue
        buf.append(line)
        candidate = "\n".join(buf)
        if sqlite3.complete_statement(candidate):
            statements.append(candidate.strip())
            buf = []
    if buf:
        raise SchemaError("incomplete SQL statement in migration")
    return statements
