"""Pure policy evaluator (docs/policy-spec.md section 4, steps 4-7).

``evaluate`` has no I/O. It answers: *under this reduced ledger state, at logical time ``now``, may
``principal`` perform ``operation`` with ``tool`` on ``resource``, and is an approval required?*
Approval validity, idempotency and effects are the gateway's job.

Diagnostics are derived only from rules present in the ledger. A matching rule is never fabricated.
"""

from __future__ import annotations

from dataclasses import dataclass

from ananke.domain import Effect, ReasonCode, Rule, RuleStatus
from ananke.ledger import PolicyState


@dataclass(frozen=True, slots=True)
class Verdict:
    permitted: bool
    reason: ReasonCode
    matched_rule_ids: tuple[str, ...]
    approval_required: bool = False


def _ids(rules: list[Rule]) -> tuple[str, ...]:
    return tuple(sorted(r.rule_id for r in rules))


def evaluate(
    state: PolicyState,
    *,
    principal_id: str,
    tool_id: str,
    operation: str,
    resource: str,
    now: int,
) -> Verdict:
    matching = [
        r for r in state.rules.values() if r.matches(principal_id, tool_id, operation, resource)
    ]
    applicable = [
        r for r in matching if r.status is RuleStatus.ACTIVE and r.in_validity_window(now)
    ]

    denies = [r for r in applicable if r.effect is Effect.DENY]
    if denies:  # explicit deny wins over any grant
        return Verdict(False, ReasonCode.EXPLICIT_DENY, _ids(denies))

    grants = [r for r in applicable if r.effect is Effect.GRANT]
    if grants:  # conservative union: approval required if ANY applicable grant requires it
        return Verdict(
            True,
            ReasonCode.ALLOWED,
            _ids(grants),
            approval_required=any(g.requires_approval for g in grants),
        )

    matching_grants = [r for r in matching if r.effect is Effect.GRANT]
    retired = [r for r in matching_grants if r.status is not RuleStatus.ACTIVE]
    if retired:
        return Verdict(False, ReasonCode.GRANT_REVOKED, _ids(retired))
    expired = [
        r
        for r in matching_grants
        if r.status is RuleStatus.ACTIVE and r.valid_until is not None and now >= r.valid_until
    ]
    if expired:
        return Verdict(False, ReasonCode.GRANT_EXPIRED, _ids(expired))
    return Verdict(False, ReasonCode.NO_MATCHING_GRANT, ())
