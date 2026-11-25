"""Action, approval and decision records (MASTERPLAN section 8).

Trust split:

* :class:`Proposal` is what agent/model code may say. It is untrusted, strict, and it cannot carry
  identity. Any ``principal_id`` or ``session_id`` key is rejected as an unknown field.
* :class:`ActionRequest` is built by trusted runtime code (``AgentPort``), which binds the
  principal and session of the channel the proposal arrived on.
* :class:`Decision` is the persisted, hash-chained, redacted evidence record.
* :class:`DecisionReceipt` is what the agent gets back. It holds no internal hashes.
"""

from __future__ import annotations

from typing import Annotated, Any, Final, Literal

from pydantic import AfterValidator, Field, StrictInt, StrictStr

from ananke.domain.canonical import canonical_bytes, digest
from ananke.domain.enums import Outcome, ReasonCode
from ananke.domain.models import (
    Digest,
    Identifier,
    PositiveInt,
    Resource,
    StrictModel,
    Tick,
    UUIDStr,
)

ACTION_SCHEMA_VERSION: Final = "ananke.action/0"
MAX_ARGUMENT_BYTES = 4096


def _canonical_arguments(value: dict[str, Any]) -> dict[str, Any]:
    if len(canonical_bytes(value)) > MAX_ARGUMENT_BYTES:
        raise ValueError(f"arguments exceed {MAX_ARGUMENT_BYTES} canonical bytes")
    return value


Arguments = Annotated[dict[StrictStr, Any], AfterValidator(_canonical_arguments)]
IdempotencyKey = Annotated[StrictStr, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")]


class Proposal(StrictModel):
    """Untrusted typed proposal from agent code. Identity fields are deliberately absent."""

    tool_id: Identifier
    operation: Identifier
    resource: Resource
    arguments: Arguments = Field(default_factory=dict)
    idempotency_key: IdempotencyKey
    approval_id: UUIDStr | None = None
    observed_epoch: StrictInt | None = Field(default=None, ge=0)  # informational only


class ActionCore(StrictModel):
    """The exact action an approval or decision is bound to (digest input)."""

    schema_version: Literal["ananke.action/0"] = ACTION_SCHEMA_VERSION
    principal_id: Identifier
    session_id: Identifier
    tool_id: Identifier
    operation: Identifier
    resource: Resource
    arguments: Arguments = Field(default_factory=dict)

    def digest(self) -> str:
        return digest(self.model_dump(mode="json"))


class ActionRequest(StrictModel):
    request_id: UUIDStr
    action: ActionCore
    idempotency_key: IdempotencyKey
    approval_id: UUIDStr | None = None
    observed_epoch: StrictInt | None = Field(default=None, ge=0)


class Approval(StrictModel):
    """Operator-issued, hash-chained approval of one exact action (insert-only record).

    Consumption is recorded separately (``approval_consumptions``), at most once per approval.
    """

    approval_id: UUIDStr
    sequence: PositiveInt
    issued_by: Identifier
    principal_id: Identifier
    session_id: Identifier
    action_digest: Digest
    issued_epoch: PositiveInt
    issued_at: Tick
    expires_at: Tick
    prev_hash: Digest
    approval_hash: Digest

    def hash_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"approval_hash"})


class Decision(StrictModel):
    """Persisted decision evidence. Redacted: no arguments, no tool results."""

    decision_id: UUIDStr
    sequence: PositiveInt
    request_id: UUIDStr | None
    session_id: Identifier | None
    principal_id: Identifier | None
    tool_id: Identifier | None
    operation: Identifier | None
    resource: Resource | None
    action_digest: Digest | None
    outcome: Outcome
    reason_code: ReasonCode
    matched_rule_ids: tuple[Identifier, ...]
    epoch: StrictInt = Field(ge=0)
    evaluated_at: Tick
    approval_id: UUIDStr | None
    effect_id: UUIDStr | None
    duplicate_of: UUIDStr | None
    prev_hash: Digest
    decision_hash: Digest

    def hash_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"decision_hash"})


class DecisionReceipt(StrictModel):
    """Returned to the agent. ``result`` is present only for an ALLOWed read (synthetic data)."""

    decision_id: UUIDStr
    request_id: UUIDStr | None
    outcome: Outcome
    reason_code: ReasonCode
    epoch: StrictInt = Field(ge=0)
    evaluated_at: Tick
    matched_rule_ids: tuple[Identifier, ...]
    action_digest: Digest | None
    effect_id: UUIDStr | None
    duplicate_of: UUIDStr | None
    result: dict[str, Any] | None = None
