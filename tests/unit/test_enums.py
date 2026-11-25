from ananke.domain import PolicyEventKind, ReasonCode, Sensitivity, Trust

# Reason codes listed in MASTERPLAN.md section 8, plus ALLOWED for the allow path.
SPEC_REASON_CODES = {
    "NO_MATCHING_GRANT",
    "EXPLICIT_DENY",
    "GRANT_EXPIRED",
    "GRANT_REVOKED",
    "UNKNOWN_TOOL",
    "INVALID_ARGUMENTS",
    "APPROVAL_REQUIRED",
    "APPROVAL_STALE",
    "APPROVAL_REPLAY",
    "LEDGER_UNAVAILABLE",
    "POLICY_INVALID",
    "DUPLICATE_REQUEST",
    "IDEMPOTENCY_CONFLICT",
    "BUDGET_EXCEEDED",
}


# Documented extensions (docs/policy-spec.md section 4/5): ALLOWED for the allow path,
# APPROVAL_INVALID (unknown/mismatched approval), INTERNAL_ERROR (fail-closed after rollback).
EXTENSIONS = {"ALLOWED", "APPROVAL_INVALID", "INTERNAL_ERROR"}


def test_reason_codes_match_spec() -> None:
    assert {r.value for r in ReasonCode} == SPEC_REASON_CODES | EXTENSIONS


def test_policy_event_kinds() -> None:
    assert {k.value for k in PolicyEventKind} == {"GRANT", "DENY", "REVOKE", "SUPERSEDE"}


def test_label_orderings_are_conservative() -> None:
    assert Trust.UNTRUSTED.rank < Trust.TOOL_OUTPUT.rank < Trust.OPERATOR.rank
    assert Sensitivity.PUBLIC.rank < Sensitivity.INTERNAL.rank < Sensitivity.RESTRICTED.rank
