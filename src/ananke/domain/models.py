"""Strict wire/storage records (MASTERPLAN section 8, docs/policy-spec.md section 3).

All records forbid unknown fields, are immutable, and use strict scalar types (no implicit
str->int or float->int coercion). Enumerations accept their string values.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Final, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from ananke.domain.canonical import MAX_SAFE_INT, canonical_bytes, digest
from ananke.domain.enums import PolicyEventKind
from ananke.domain.identifiers import validate_identifier, validate_resource, validate_text

POLICY_SCHEMA_VERSION: Final = "ananke.policy/0"
GENESIS_HASH = "sha256:" + "0" * 64


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
        use_enum_values=False,
    )

    def canonical(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json"))


Identifier = Annotated[StrictStr, AfterValidator(validate_identifier)]
Resource = Annotated[StrictStr, AfterValidator(validate_resource)]
ShortText = Annotated[StrictStr, AfterValidator(validate_text)]
Tick = Annotated[StrictInt, Field(ge=0, le=MAX_SAFE_INT)]
PositiveInt = Annotated[StrictInt, Field(ge=1, le=MAX_SAFE_INT)]
Digest = Annotated[StrictStr, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
UUIDStr = Annotated[
    StrictStr,
    Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
]


class Effect(StrEnum):
    GRANT = "GRANT"
    DENY = "DENY"


class RuleStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    SUPERSEDED = "SUPERSEDED"


_RULE_FIELDS = ("rule_id", "principal_id", "tool_id", "operation", "resource_scope", "valid_from")


class PolicyChange(StrictModel):
    """An authority change as submitted through the operator channel (no ledger fields)."""

    schema_version: Literal["ananke.policy/0"] = POLICY_SCHEMA_VERSION
    kind: PolicyEventKind
    rule_id: Identifier | None = None
    target_rule_id: Identifier | None = None
    principal_id: Identifier | None = None
    tool_id: Identifier | None = None
    operation: Identifier | None = None
    resource_scope: Resource | None = None
    valid_from: Tick | None = None
    valid_until: Tick | None = None
    requires_approval: StrictBool = False
    reason: ShortText = ""

    @model_validator(mode="after")
    def _shape_by_kind(self) -> Self:
        kind = self.kind
        has_rule = [getattr(self, f) is not None for f in _RULE_FIELDS]
        if kind in (PolicyEventKind.GRANT, PolicyEventKind.DENY, PolicyEventKind.SUPERSEDE):
            if not all(has_rule):
                missing = [f for f, h in zip(_RULE_FIELDS, has_rule, strict=True) if not h]
                raise ValueError(f"{kind}: missing required fields {missing}")
        else:  # REVOKE
            if any(has_rule) or self.valid_until is not None or self.requires_approval:
                raise ValueError("REVOKE: must carry only target_rule_id and reason")
        if kind in (PolicyEventKind.REVOKE, PolicyEventKind.SUPERSEDE):
            if self.target_rule_id is None:
                raise ValueError(f"{kind}: target_rule_id is required")
            if self.rule_id is not None and self.rule_id == self.target_rule_id:
                raise ValueError(f"{kind}: rule_id must differ from target_rule_id")
        elif self.target_rule_id is not None:
            raise ValueError(f"{kind}: target_rule_id is not allowed")
        if kind == PolicyEventKind.DENY and self.requires_approval:
            raise ValueError("DENY: requires_approval must be false")
        if (
            self.valid_until is not None
            and self.valid_from is not None
            and self.valid_until <= self.valid_from
        ):
            raise ValueError("valid_until must be greater than valid_from")
        return self


class PolicyEvent(PolicyChange):
    """A committed, hash-chained ledger event."""

    event_id: UUIDStr
    sequence: PositiveInt
    epoch: PositiveInt
    actor_id: Identifier
    recorded_at: Tick
    prev_hash: Digest
    event_hash: Digest

    def hash_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"event_hash"})

    def computed_hash(self) -> str:
        return digest(self.hash_payload())

    def change(self) -> PolicyChange:
        fields = PolicyChange.model_fields.keys()
        return PolicyChange.model_validate({k: getattr(self, k) for k in fields})


class Rule(StrictModel):
    """Reduced state of one rule. Retired rules are kept for diagnostics, never for authority."""

    rule_id: Identifier
    effect: Effect
    principal_id: Identifier
    tool_id: Identifier
    operation: Identifier
    resource_scope: Resource
    valid_from: Tick
    valid_until: Tick | None
    requires_approval: StrictBool
    status: RuleStatus
    created_sequence: PositiveInt
    created_epoch: PositiveInt
    retired_sequence: PositiveInt | None = None
    retired_epoch: PositiveInt | None = None
    replaced_by: Identifier | None = None

    def in_validity_window(self, now: int) -> bool:
        """``valid_from <= now < valid_until`` (``valid_until`` None means unbounded)."""
        return self.valid_from <= now and (self.valid_until is None or now < self.valid_until)

    def matches(self, principal_id: str, tool_id: str, operation: str, resource: str) -> bool:
        """Exact match on all four coordinates. No prefix or wildcard semantics in v0."""
        return (
            self.principal_id == principal_id
            and self.tool_id == tool_id
            and self.operation == operation
            and self.resource_scope == resource
        )


class PolicySnapshot(StrictModel):
    """A cache/evidence view of active rules. A snapshot never authorizes an effect."""

    schema_version: Literal["ananke.policy/0"] = POLICY_SCHEMA_VERSION
    epoch: StrictInt = Field(ge=0)
    last_sequence: StrictInt = Field(ge=0)
    last_event_hash: Digest
    as_of_tick: Tick
    active_rules: tuple[Rule, ...]
    snapshot_digest: Digest
