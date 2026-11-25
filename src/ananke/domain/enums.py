"""Closed enumerations from MASTERPLAN.md section 8 and docs/policy-spec.md."""

from __future__ import annotations

from enum import StrEnum


class PolicyEventKind(StrEnum):
    GRANT = "GRANT"
    DENY = "DENY"
    REVOKE = "REVOKE"
    SUPERSEDE = "SUPERSEDE"


class Outcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"


class ReasonCode(StrEnum):
    ALLOWED = "ALLOWED"
    NO_MATCHING_GRANT = "NO_MATCHING_GRANT"
    EXPLICIT_DENY = "EXPLICIT_DENY"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    GRANT_REVOKED = "GRANT_REVOKED"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    INVALID_ARGUMENTS = "INVALID_ARGUMENTS"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_STALE = "APPROVAL_STALE"
    APPROVAL_REPLAY = "APPROVAL_REPLAY"
    APPROVAL_INVALID = "APPROVAL_INVALID"  # extension: unknown id or wrong action/principal/session
    LEDGER_UNAVAILABLE = "LEDGER_UNAVAILABLE"
    POLICY_INVALID = "POLICY_INVALID"
    DUPLICATE_REQUEST = "DUPLICATE_REQUEST"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    INTERNAL_ERROR = "INTERNAL_ERROR"  # extension: fail-closed catch-all after full rollback


class MemoryEntryType(StrEnum):
    FACT = "FACT"
    TASK = "TASK"
    OBSERVATION = "OBSERVATION"
    SUMMARY = "SUMMARY"


class Trust(StrEnum):
    """Ordered least-trusted first. Derived entries take the minimum (least trust) of sources."""

    UNTRUSTED = "UNTRUSTED"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    OPERATOR = "OPERATOR"

    @property
    def rank(self) -> int:
        return _TRUST_ORDER.index(self)


class Sensitivity(StrEnum):
    """Ordered least-sensitive first. Derived entries take the maximum of sources."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"

    @property
    def rank(self) -> int:
        return _SENSITIVITY_ORDER.index(self)


_TRUST_ORDER = (Trust.UNTRUSTED, Trust.TOOL_OUTPUT, Trust.OPERATOR)
_SENSITIVITY_ORDER = (Sensitivity.PUBLIC, Sensitivity.INTERNAL, Sensitivity.RESTRICTED)
