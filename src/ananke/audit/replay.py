"""Evidence audit: replay every recorded decision and cross-check all evidence tables.

Structural verification (``ledger.store.verify_connection``) checks the hash chains. This module
checks that the evidence is *semantically* consistent:

* **Decision replay.** Every policy-derived decision is re-evaluated with the production
  evaluator against the reduced ledger state at the decision's own epoch and logical time.
  Outcome, reason and matched rules must be reproduced exactly.
* **Effect justification.** Every ``lab_effects`` row maps to exactly one ALLOW/ALLOWED
  decision with the same coordinates and time, and every such decision has exactly one effect
  and one idempotency row.
* **Approval justification.** An allowed decision whose policy required approval consumed
  exactly one approval issued by a registered operator for that exact action digest, principal,
  session and epoch, unexpired at the decision time. A consumption no allowed decision justifies
  is an error.
  Approval denials are re-derived (INVALID / REPLAY / STALE).
* **Order.** Policy-evaluated decisions have non-decreasing epoch and evaluated_at (linearization).

Limitation: an attacker with full database write access who also forges *consistent* policy events
under a registered operator identity can still pass this audit. Preventing that needs operator
signatures (proposed ADR-0010), which are not implemented.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from ananke.domain import Approval, Decision, Outcome, PolicyEvent, ReasonCode
from ananke.lab import REGISTRY
from ananke.ledger import EMPTY_STATE, PolicyState, reduce_events
from ananke.ledger.db import read_transaction
from ananke.ledger.evidence import read_approvals, read_decisions
from ananke.policy import evaluate

R = ReasonCode
POLICY_REASONS = frozenset(
    {
        R.ALLOWED,
        R.APPROVAL_REQUIRED,
        R.EXPLICIT_DENY,
        R.GRANT_REVOKED,
        R.GRANT_EXPIRED,
        R.NO_MATCHING_GRANT,
        R.APPROVAL_INVALID,
        R.APPROVAL_REPLAY,
        R.APPROVAL_STALE,
    }
)
EXPECTED_OUTCOME = {
    R.ALLOWED: Outcome.ALLOW,
    R.DUPLICATE_REQUEST: Outcome.ALLOW,
    R.APPROVAL_REQUIRED: Outcome.NEEDS_APPROVAL,
}


@dataclass(frozen=True, slots=True)
class AuditIssue:
    code: str
    decision_sequence: int | None
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "decision_sequence": self.decision_sequence,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class AuditReport:
    ok: bool
    decisions: int
    replayed: int
    effects: int
    approvals: int
    consumptions: int
    issues: tuple[AuditIssue, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "decisions": self.decisions,
            "replayed": self.replayed,
            "effects": self.effects,
            "approvals": self.approvals,
            "consumptions": self.consumptions,
            "issues": [i.as_dict() for i in self.issues[:50]],
            "issue_count": len(self.issues),
        }


class _States:
    """Policy state after the first k events, computed incrementally and memoized."""

    def __init__(self, events: list[PolicyEvent]) -> None:
        self._events = events
        self._memo: dict[int, PolicyState] = {0: EMPTY_STATE}

    @property
    def final_epoch(self) -> int:
        return len(self._events)

    def at(self, epoch: int) -> PolicyState:
        if epoch in self._memo:
            return self._memo[epoch]
        base = max(k for k in self._memo if k <= epoch)
        state = reduce_events(self._events[base:epoch], self._memo[base])
        self._memo[epoch] = state
        return state


def audit_connection(conn: sqlite3.Connection) -> AuditReport:
    with read_transaction(conn):
        events = [
            PolicyEvent.model_validate_json(r[0])
            for r in conn.execute("SELECT canonical FROM policy_events ORDER BY sequence")
        ]
        decisions = read_decisions(conn)
        approvals = {a.approval_id: a for _, a in read_approvals(conn) if a is not None}
        consumptions = {
            str(a): (str(d), int(t))
            for a, d, t in conn.execute(
                "SELECT approval_id, decision_id, consumed_at FROM approval_consumptions"
            )
        }
        effects = {
            str(r[1]): r
            for r in conn.execute(
                "SELECT effect_id, decision_id, tool_id, operation, resource, committed_at"
                " FROM lab_effects"
            )
        }
        idem = [
            tuple(r)
            for r in conn.execute(
                "SELECT session_id, principal_id, idempotency_key, action_digest, decision_id"
                " FROM idempotency"
            )
        ]
        operators = {str(r[0]) for r in conn.execute("SELECT actor_id FROM operators")}
    return _audit(events, decisions, approvals, consumptions, effects, idem, operators)


def _audit(
    events: list[PolicyEvent],
    decisions: list[Decision],
    approvals: dict[str, Approval],
    consumptions: dict[str, tuple[str, int]],
    effects: dict[str, Any],
    idem: list[tuple[Any, ...]],
    operators: set[str],
) -> AuditReport:
    issues: list[AuditIssue] = []
    states = _States(events)
    by_id = {d.decision_id: d for d in decisions}
    consumed_by = {dec: appr for appr, (dec, _) in consumptions.items()}
    idem_by_decision: dict[str, list[tuple[Any, ...]]] = {}
    for row in idem:
        idem_by_decision.setdefault(str(row[4]), []).append(row)
    replayed = 0
    last_epoch, last_tick = -1, -1

    def flag(code: str, d: Decision | None, detail: str) -> None:
        issues.append(AuditIssue(code, d.sequence if d else None, detail))

    for d in decisions:
        want_outcome = EXPECTED_OUTCOME.get(d.reason_code, Outcome.DENY)
        if d.outcome is not want_outcome:
            flag("OUTCOME_REASON_MISMATCH", d, f"{d.outcome} with {d.reason_code}")
        allowed = d.reason_code is R.ALLOWED
        # Only ALLOWED decisions may carry an effect, an idempotency binding or a consumption.
        if not allowed:
            if d.effect_id is not None or d.decision_id in effects:
                flag("UNJUSTIFIED_EFFECT", d, "effect attached to a non-ALLOWED decision")
            if d.decision_id in consumed_by:
                flag("UNJUSTIFIED_CONSUMPTION", d, "approval consumed by a non-ALLOWED decision")
            if d.decision_id in idem_by_decision:
                flag("UNJUSTIFIED_IDEMPOTENCY", d, "idempotency bound to a non-ALLOWED decision")

        if d.reason_code is R.DUPLICATE_REQUEST:
            orig = by_id.get(d.duplicate_of or "")
            if (
                orig is None
                or orig.reason_code is not R.ALLOWED
                or orig.sequence >= d.sequence
                or orig.action_digest != d.action_digest
                or (orig.session_id, orig.principal_id) != (d.session_id, d.principal_id)
            ):
                flag(
                    "DUPLICATE_UNJUSTIFIED",
                    d,
                    "duplicate_of does not name a prior identical ALLOWED decision",
                )
            continue
        if d.reason_code is R.UNKNOWN_TOOL:
            if d.tool_id in REGISTRY:
                flag("REPLAY_MISMATCH", d, "UNKNOWN_TOOL for a registered tool")
            continue
        if d.reason_code not in POLICY_REASONS:
            continue  # validation / infrastructure denials: not policy-replayable

        # ---- policy replay
        principal, tool, op, res = d.principal_id, d.tool_id, d.operation, d.resource
        if principal is None or tool is None or op is None or res is None:
            flag("REPLAY_MISMATCH", d, "policy decision without action coordinates")
            continue
        if d.epoch > states.final_epoch:
            flag("EPOCH_FROM_FUTURE", d, f"epoch {d.epoch} > ledger epoch {states.final_epoch}")
            continue
        if d.epoch < last_epoch or d.evaluated_at < last_tick:
            flag("ORDER_VIOLATION", d, "epoch/time decreased along the decision chain")
        last_epoch, last_tick = d.epoch, d.evaluated_at
        v = evaluate(
            states.at(d.epoch),
            principal_id=principal,
            tool_id=tool,
            operation=op,
            resource=res,
            now=d.evaluated_at,
        )
        replayed += 1
        if tuple(v.matched_rule_ids) != tuple(d.matched_rule_ids):
            flag(
                "REPLAY_MISMATCH", d, f"matched {d.matched_rule_ids} != replay {v.matched_rule_ids}"
            )
        approval_path = d.reason_code in (
            R.ALLOWED,
            R.APPROVAL_REQUIRED,
            R.APPROVAL_INVALID,
            R.APPROVAL_REPLAY,
            R.APPROVAL_STALE,
        )
        if approval_path:
            if not v.permitted:
                flag("REPLAY_MISMATCH", d, f"recorded {d.reason_code}, replay denies {v.reason}")
                if allowed:  # keep auditing linkage so every inconsistency is reported
                    _check_allowed(
                        d,
                        False,
                        approvals,
                        consumptions,
                        consumed_by,
                        effects,
                        idem_by_decision,
                        operators,
                        flag,
                    )
                continue
            needs = v.approval_required
            if d.reason_code is not R.ALLOWED and not needs:
                flag("REPLAY_MISMATCH", d, f"{d.reason_code} but no approval was required")
        elif v.permitted or v.reason is not d.reason_code:
            flag("REPLAY_MISMATCH", d, f"recorded {d.reason_code}, replay {v.reason}")
            continue

        if d.reason_code is R.APPROVAL_REQUIRED and d.approval_id is not None:
            flag("REPLAY_MISMATCH", d, "APPROVAL_REQUIRED but an approval id is recorded")
        if d.reason_code in (R.APPROVAL_INVALID, R.APPROVAL_REPLAY, R.APPROVAL_STALE):
            _check_approval_denial(d, approvals, consumptions, by_id, flag)
        if allowed:
            _check_allowed(
                d,
                v.approval_required,
                approvals,
                consumptions,
                consumed_by,
                effects,
                idem_by_decision,
                operators,
                flag,
            )

    # Orphans: rows that no ALLOWED decision justifies.
    for dec_id in effects:
        owner = by_id.get(dec_id)
        if owner is None or owner.reason_code is not R.ALLOWED:
            flag("ORPHAN_EFFECT", owner, f"effect for decision {dec_id} is not justified")
    for appr_id, (dec_id, _) in consumptions.items():
        owner = by_id.get(dec_id)
        if owner is None or owner.reason_code is not R.ALLOWED or owner.approval_id != appr_id:
            flag("ORPHAN_CONSUMPTION", owner, f"consumption of {appr_id} is not justified")
    for dec_id in idem_by_decision:
        if dec_id not in by_id:
            flag("ORPHAN_IDEMPOTENCY", None, f"idempotency row for unknown decision {dec_id}")
    for a in approvals.values():
        if a.issued_by not in operators:
            flag("APPROVAL_ISSUER_UNKNOWN", None, f"approval {a.approval_id}")
        if not 1 <= a.issued_epoch <= states.final_epoch:
            flag("APPROVAL_EPOCH_INVALID", None, f"approval {a.approval_id} epoch {a.issued_epoch}")
        else:
            lo = events[a.issued_epoch - 1].recorded_at
            hi = events[a.issued_epoch].recorded_at if a.issued_epoch < len(events) else None
            if a.issued_at < lo or (hi is not None and a.issued_at > hi):
                flag(
                    "APPROVAL_TIME_INCONSISTENT",
                    None,
                    f"approval {a.approval_id} issued outside its epoch's time window",
                )

    return AuditReport(
        ok=not issues,
        decisions=len(decisions),
        replayed=replayed,
        effects=len(effects),
        approvals=len(approvals),
        consumptions=len(consumptions),
        issues=tuple(issues),
    )


def _check_allowed(
    d: Decision,
    needs_approval: bool,
    approvals: dict[str, Approval],
    consumptions: dict[str, tuple[str, int]],
    consumed_by: dict[str, str],
    effects: dict[str, Any],
    idem_by_decision: dict[str, list[tuple[Any, ...]]],
    operators: set[str],
    flag: Any,
) -> None:
    eff = effects.get(d.decision_id)
    if eff is None or d.effect_id is None or str(eff[0]) != d.effect_id:
        flag("MISSING_EFFECT", d, "ALLOWED decision without its matching effect row")
    elif (eff[2], eff[3], eff[4], eff[5]) != (d.tool_id, d.operation, d.resource, d.evaluated_at):
        flag("EFFECT_MISMATCH", d, "effect coordinates or time differ from the decision")
    rows = idem_by_decision.get(d.decision_id, [])
    if len(rows) != 1 or (rows[0][0], rows[0][1], rows[0][3]) != (
        d.session_id,
        d.principal_id,
        d.action_digest,
    ):
        flag("IDEMPOTENCY_MISMATCH", d, "ALLOWED decision without exactly one matching binding")
    if not needs_approval:
        if d.approval_id is not None or d.decision_id in consumed_by:
            flag("UNJUSTIFIED_CONSUMPTION", d, "approval recorded although none was required")
        return
    a = approvals.get(d.approval_id or "")
    cons = consumptions.get(d.approval_id or "")
    if a is None or cons is None or cons[0] != d.decision_id:
        flag("APPROVAL_NOT_CONSUMED", d, "approval-gated effect without its consumption")
        return
    if (a.action_digest, a.principal_id, a.session_id) != (
        d.action_digest,
        d.principal_id,
        d.session_id,
    ):
        flag("APPROVAL_MISMATCH", d, "consumed approval is for a different action")
    if a.issued_epoch != d.epoch or d.evaluated_at >= a.expires_at or cons[1] != d.evaluated_at:
        flag("APPROVAL_STALE_USED", d, "consumed approval was stale, expired or mistimed")
    if a.issued_by not in operators:
        flag("APPROVAL_ISSUER_UNKNOWN", d, "approval issued by an unregistered identity")


def _check_approval_denial(
    d: Decision,
    approvals: dict[str, Approval],
    consumptions: dict[str, tuple[str, int]],
    by_id: dict[str, Decision],
    flag: Any,
) -> None:
    a = approvals.get(d.approval_id or "")
    mismatch = a is None or (a.action_digest, a.principal_id, a.session_id) != (
        d.action_digest,
        d.principal_id,
        d.session_id,
    )
    if d.reason_code is R.APPROVAL_INVALID:
        if not mismatch:
            flag("REPLAY_MISMATCH", d, "APPROVAL_INVALID for a matching approval")
        return
    if mismatch or a is None:
        flag("REPLAY_MISMATCH", d, f"{d.reason_code} for a non-matching approval")
        return
    cons = consumptions.get(a.approval_id)
    earlier = cons is not None and cons[0] in by_id and by_id[cons[0]].sequence < d.sequence
    if d.reason_code is R.APPROVAL_REPLAY and not earlier:
        flag("REPLAY_MISMATCH", d, "APPROVAL_REPLAY without an earlier consumption")
    if d.reason_code is R.APPROVAL_STALE:
        if earlier:
            flag("REPLAY_MISMATCH", d, "STALE recorded for an already consumed approval")
        if a.issued_epoch == d.epoch and d.evaluated_at < a.expires_at:
            flag("REPLAY_MISMATCH", d, "APPROVAL_STALE for a fresh approval")
