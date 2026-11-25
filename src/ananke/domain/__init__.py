"""Domain primitives: enums, canonical serialization, logical clock, identifiers, records.

This package must not import any other ``ananke`` subpackage (dependencies flow inward).
"""

from ananke.domain.actions import (
    ACTION_SCHEMA_VERSION,
    ActionCore,
    ActionRequest,
    Approval,
    Decision,
    DecisionReceipt,
    Proposal,
)
from ananke.domain.canonical import (
    CANONICALIZATION_VERSION,
    CanonicalizationError,
    canonical_bytes,
    digest,
)
from ananke.domain.clock import ClockError, LogicalClock
from ananke.domain.enums import (
    MemoryEntryType,
    Outcome,
    PolicyEventKind,
    ReasonCode,
    Sensitivity,
    Trust,
)
from ananke.domain.identifiers import (
    InvalidIdentifierError,
    validate_identifier,
    validate_resource,
    validate_text,
)
from ananke.domain.models import (
    GENESIS_HASH,
    POLICY_SCHEMA_VERSION,
    Effect,
    PolicyChange,
    PolicyEvent,
    PolicySnapshot,
    Rule,
    RuleStatus,
)

__all__ = [
    "ACTION_SCHEMA_VERSION",
    "CANONICALIZATION_VERSION",
    "GENESIS_HASH",
    "POLICY_SCHEMA_VERSION",
    "ActionCore",
    "ActionRequest",
    "Approval",
    "CanonicalizationError",
    "ClockError",
    "Decision",
    "DecisionReceipt",
    "Effect",
    "InvalidIdentifierError",
    "LogicalClock",
    "MemoryEntryType",
    "Outcome",
    "PolicyChange",
    "PolicyEvent",
    "PolicyEventKind",
    "PolicySnapshot",
    "Proposal",
    "ReasonCode",
    "Rule",
    "RuleStatus",
    "Sensitivity",
    "Trust",
    "canonical_bytes",
    "digest",
    "validate_identifier",
    "validate_resource",
    "validate_text",
]
