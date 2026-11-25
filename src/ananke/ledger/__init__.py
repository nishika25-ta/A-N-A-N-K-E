"""Versioned, append-only, hash-chained policy ledger (Phase 1).

Public surface:

* trusted setup: :func:`init_ledger`
* authority mutation (operator only): :class:`OperatorChannel`
* verified reads: :class:`PolicyReader`, :func:`load_state`, :func:`verify_ledger`
* pure semantics: :func:`reduce_events`, :func:`apply_event`, :class:`PolicyState`
"""

from ananke.ledger.checkpoint import Checkpoint, create_checkpoint, verify_checkpoint
from ananke.ledger.db import LedgerUnavailableError, SchemaError
from ananke.ledger.reducer import (
    EMPTY_STATE,
    PolicyState,
    PolicyTransitionError,
    TransitionError,
    apply_event,
    build_event,
    check_change,
    reduce_events,
)
from ananke.ledger.signing import (
    SigningError,
    generate_key,
    load_private_key,
    public_key_hex,
    write_private_key,
)
from ananke.ledger.store import (
    LedgerIntegrityError,
    OperatorChannel,
    PolicyReader,
    UnknownOperatorError,
    VerificationReport,
    VerifyCode,
    init_ledger,
    load_state,
    open_ledger,
    validate_changes,
    verify_connection,
    verify_ledger,
)

__all__ = [
    "EMPTY_STATE",
    "Checkpoint",
    "LedgerIntegrityError",
    "LedgerUnavailableError",
    "OperatorChannel",
    "PolicyReader",
    "PolicyState",
    "PolicyTransitionError",
    "SchemaError",
    "SigningError",
    "TransitionError",
    "UnknownOperatorError",
    "VerificationReport",
    "VerifyCode",
    "apply_event",
    "build_event",
    "check_change",
    "create_checkpoint",
    "generate_key",
    "init_ledger",
    "load_private_key",
    "load_state",
    "open_ledger",
    "public_key_hex",
    "reduce_events",
    "validate_changes",
    "verify_checkpoint",
    "verify_connection",
    "verify_ledger",
    "write_private_key",
]
