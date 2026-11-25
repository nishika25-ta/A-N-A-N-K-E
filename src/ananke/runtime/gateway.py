"""Reference monitor / execution gateway (docs/policy-spec.md section 4, ADR-0002).

Linearization: every request is decided inside one ``BEGIN IMMEDIATE`` transaction on the ledger
database. The transaction covers the verified policy load, validation, idempotency lookup,
evaluation, approval check and consumption, the mock effect, the decision record and the
idempotency record. Operator policy writes take the same lock, so effects and authority changes are
totally ordered, and ``COMMIT`` is the linearization point.

Failure semantics (fail closed):

* any exception inside the transaction leads to a full ROLLBACK. Then a DENY decision is recorded in
  a fresh transaction with POLICY_INVALID, LEDGER_UNAVAILABLE, INVALID_ARGUMENTS (a tool error) or
  INTERNAL_ERROR;
* if that evidence cannot be recorded either, :class:`GatewayUnavailableError` is raised. The
  harness must stop the run. Nothing is silently swallowed.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping
from typing import Any

from pydantic import ValidationError

from ananke.domain import (
    ActionRequest,
    Approval,
    Decision,
    DecisionReceipt,
    Outcome,
    ReasonCode,
)
from ananke.lab import REGISTRY, ToolError, ToolSpec
from ananke.ledger import LedgerIntegrityError, LedgerUnavailableError, PolicyReader, PolicyState
from ananke.ledger.db import write_transaction
from ananke.ledger.evidence import append_decision, consume_approval, load_approval
from ananke.ledger.signing import KIND_APPROVAL
from ananke.ledger.store import IdFactory, TickSource, uuid4_factory
from ananke.policy import evaluate

HookName = str  # "policy_loaded" | "before_effect" | "after_effect" | "before_commit"
HOOK_NAMES = frozenset({"policy_loaded", "before_effect", "after_effect", "before_commit"})


class GatewayUnavailableError(RuntimeError):
    """Decision evidence could not be recorded. No effect was committed; the run must stop."""


def check_approval(
    lookup: tuple[Approval, bool] | None,
    *,
    request: ActionRequest,
    action_digest: str,
    state: PolicyState,
    now: int,
) -> ReasonCode | None:
    """Return a denial reason, or None if the approval is valid for this exact request now."""
    action = request.action
    if lookup is None:
        return ReasonCode.APPROVAL_INVALID
    approval, consumed = lookup
    if (
        approval.principal_id != action.principal_id
        or approval.session_id != action.session_id
        or approval.action_digest != action_digest
    ):
        return ReasonCode.APPROVAL_INVALID
    if consumed:
        return ReasonCode.APPROVAL_REPLAY
    if approval.issued_epoch != state.epoch or now >= approval.expires_at:
        return ReasonCode.APPROVAL_STALE
    return None


class Gateway:
    """The only component that can commit lab effects. Construct it in trusted code only."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        clock: TickSource,
        *,
        registry: Mapping[str, ToolSpec] = REGISTRY,
        id_factory: IdFactory = uuid4_factory,
        hooks: Mapping[HookName, Callable[[], None]] | None = None,
    ) -> None:
        unknown = set(hooks or {}) - HOOK_NAMES
        if unknown:
            raise ValueError(f"unknown gateway hooks: {sorted(unknown)}")
        self._conn = conn
        self._clock = clock
        self._registry = registry
        self._ids = id_factory
        self._hooks = dict(hooks or {})
        self._reader = PolicyReader(conn)

    # ------------------------------------------------------------------ public API

    def submit(self, request: ActionRequest) -> DecisionReceipt:
        action = request.action
        base: dict[str, Any] = {
            "decision_id": self._ids(),
            "request_id": request.request_id,
            "session_id": action.session_id,
            "principal_id": action.principal_id,
            "tool_id": action.tool_id,
            "operation": action.operation,
            "resource": action.resource,
            "action_digest": action.digest(),
            "approval_id": None,  # set only if the approval is actually evaluated
            "matched_rule_ids": (),
            "effect_id": None,
            "duplicate_of": None,
        }
        try:
            with write_transaction(self._conn) as conn:
                return self._decide(conn, request, base)
        except LedgerIntegrityError:
            self._reader.invalidate()
            return self._record_failure(base, ReasonCode.POLICY_INVALID)
        except LedgerUnavailableError:
            return self._record_failure(base, ReasonCode.LEDGER_UNAVAILABLE)
        except ToolError:
            return self._record_failure(base, ReasonCode.INVALID_ARGUMENTS)
        except Exception:
            self._reader.invalidate()
            return self._record_failure(base, ReasonCode.INTERNAL_ERROR)

    def reject(
        self,
        *,
        session_id: str,
        principal_id: str,
        reason: ReasonCode,
        request_id: str | None = None,
    ) -> DecisionReceipt:
        """Record a denial for a proposal that could not even be parsed into a request."""
        base: dict[str, Any] = {
            "decision_id": self._ids(),
            "request_id": request_id,
            "session_id": session_id,
            "principal_id": principal_id,
            "tool_id": None,
            "operation": None,
            "resource": None,
            "action_digest": None,
            "approval_id": None,
            "matched_rule_ids": (),
            "effect_id": None,
            "duplicate_of": None,
        }
        return self._record_failure(base, reason)

    # ------------------------------------------------------------------ internals

    def _hook(self, name: HookName) -> None:
        hook = self._hooks.get(name)
        if hook is not None:
            hook()

    def _finish(
        self,
        conn: sqlite3.Connection,
        fields: dict[str, Any],
        outcome: Outcome,
        reason: ReasonCode,
        result: dict[str, Any] | None = None,
        **extra: Any,
    ) -> DecisionReceipt:
        decision = append_decision(
            conn, {**fields, **extra, "outcome": outcome, "reason_code": reason}
        )
        return _receipt(decision, result)

    def _decide(
        self, conn: sqlite3.Connection, request: ActionRequest, base: dict[str, Any]
    ) -> DecisionReceipt:
        action = request.action
        state = self._reader.current_state()  # verified; raises LedgerIntegrityError
        self._hook("policy_loaded")
        now = self._clock()
        fields = {**base, "epoch": state.epoch, "evaluated_at": now}

        # 1. typed validation against the tool registry (fail closed)
        spec = self._registry.get(action.tool_id)
        if spec is None:
            return self._finish(conn, fields, Outcome.DENY, ReasonCode.UNKNOWN_TOOL)
        op = spec.operations.get(action.operation)
        if op is None or not action.resource.startswith(spec.namespace + ":"):
            return self._finish(conn, fields, Outcome.DENY, ReasonCode.INVALID_ARGUMENTS)
        try:
            args = op.args_model.model_validate(action.arguments)
        except ValidationError:
            return self._finish(conn, fields, Outcome.DENY, ReasonCode.INVALID_ARGUMENTS)

        # 2. idempotency: a key bound to a committed effect is never re-executed
        row = conn.execute(
            "SELECT action_digest, decision_id FROM idempotency"
            " WHERE session_id = ? AND principal_id = ? AND idempotency_key = ?",
            (action.session_id, action.principal_id, request.idempotency_key),
        ).fetchone()
        if row is not None:
            if row[0] == base["action_digest"]:
                return self._finish(
                    conn,
                    fields,
                    Outcome.ALLOW,
                    ReasonCode.DUPLICATE_REQUEST,
                    duplicate_of=str(row[1]),
                )
            return self._finish(conn, fields, Outcome.DENY, ReasonCode.IDEMPOTENCY_CONFLICT)

        # 3. policy evaluation against the latest committed ledger state
        verdict = evaluate(
            state,
            principal_id=action.principal_id,
            tool_id=action.tool_id,
            operation=action.operation,
            resource=action.resource,
            now=now,
        )
        fields["matched_rule_ids"] = verdict.matched_rule_ids
        if not verdict.permitted:
            return self._finish(conn, fields, Outcome.DENY, verdict.reason)

        # 4. approval obligation
        if verdict.approval_required:
            if request.approval_id is None:
                return self._finish(
                    conn, fields, Outcome.NEEDS_APPROVAL, ReasonCode.APPROVAL_REQUIRED
                )
            fields["approval_id"] = request.approval_id
            lookup = load_approval(conn, request.approval_id)
            auth = self._reader.authenticator()
            if lookup is not None and auth.required:
                # Signed ledger: an approval without a valid issuer signature authorizes nothing.
                appr = lookup[0]
                if auth.check(KIND_APPROVAL, appr.approval_hash, appr.issued_by) is not None:
                    lookup = None
            denial = check_approval(
                lookup,
                request=request,
                action_digest=base["action_digest"],
                state=state,
                now=now,
            )
            if denial is not None:
                return self._finish(conn, fields, Outcome.DENY, denial)

        # 5. effect, approval consumption, evidence: all in this transaction
        self._hook("before_effect")
        effect_id = self._ids()
        result = op.handler(conn, action.resource, args, now)
        conn.execute(
            "INSERT INTO lab_effects(effect_id, decision_id, tool_id, operation, resource,"
            " committed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                effect_id,
                base["decision_id"],
                action.tool_id,
                action.operation,
                action.resource,
                now,
            ),
        )
        self._hook("after_effect")
        if verdict.approval_required and request.approval_id is not None:
            consume_approval(conn, request.approval_id, at=now, decision_id=base["decision_id"])
        receipt = self._finish(
            conn,
            fields,
            Outcome.ALLOW,
            ReasonCode.ALLOWED,
            result=result if op.discloses else None,
            effect_id=effect_id,
        )
        conn.execute(
            "INSERT INTO idempotency(session_id, principal_id, idempotency_key, action_digest,"
            " decision_id) VALUES (?, ?, ?, ?, ?)",
            (
                action.session_id,
                action.principal_id,
                request.idempotency_key,
                base["action_digest"],
                base["decision_id"],
            ),
        )
        self._hook("before_commit")
        return receipt

    def _record_failure(self, base: dict[str, Any], reason: ReasonCode) -> DecisionReceipt:
        """Record a fail-closed denial in a fresh transaction (after any rollback)."""
        try:
            now = self._clock()
            with write_transaction(self._conn) as conn:
                epoch = self._last_known_epoch()
                decision = append_decision(
                    conn,
                    {
                        **base,
                        "outcome": Outcome.DENY,
                        "reason_code": reason,
                        "epoch": epoch,
                        "evaluated_at": now,
                        "effect_id": None,
                        "duplicate_of": None,
                    },
                )
        except Exception as exc:
            raise GatewayUnavailableError(f"cannot record decision evidence ({reason})") from exc
        return _receipt(decision, None)

    def _last_known_epoch(self) -> int:
        try:
            return self._reader.current_state().epoch
        except (LedgerIntegrityError, sqlite3.Error):
            return 0


def _receipt(decision: Decision, result: dict[str, Any] | None) -> DecisionReceipt:
    return DecisionReceipt(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        outcome=decision.outcome,
        reason_code=decision.reason_code,
        epoch=decision.epoch,
        evaluated_at=decision.evaluated_at,
        matched_rule_ids=decision.matched_rule_ids,
        action_digest=decision.action_digest,
        effect_id=decision.effect_id,
        duplicate_of=decision.duplicate_of,
        result=result,
    )
