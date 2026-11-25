"""Pure, deterministic policy reducer: committed events -> rule state.

The reducer is the single source of truth for transition validity. The operator channel uses
:func:`check_change` before writing. Verification and replay use :func:`apply_event`, which also
checks chain fields (sequence, epoch, prev_hash, event_hash, time order). Invalid input raises
:class:`PolicyTransitionError`. Nothing is silently reinterpreted.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from ananke.domain import (
    GENESIS_HASH,
    Effect,
    PolicyChange,
    PolicyEvent,
    PolicyEventKind,
    PolicySnapshot,
    Rule,
    RuleStatus,
    digest,
)


class TransitionError(StrEnum):
    SEQUENCE_GAP = "SEQUENCE_GAP"
    EPOCH_MISMATCH = "EPOCH_MISMATCH"
    PREV_HASH_MISMATCH = "PREV_HASH_MISMATCH"
    EVENT_HASH_MISMATCH = "EVENT_HASH_MISMATCH"
    TIME_REGRESSION = "TIME_REGRESSION"
    RULE_ID_REUSED = "RULE_ID_REUSED"
    TARGET_UNKNOWN = "TARGET_UNKNOWN"
    TARGET_NOT_ACTIVE = "TARGET_NOT_ACTIVE"
    SUPERSEDE_SCOPE_MISMATCH = "SUPERSEDE_SCOPE_MISMATCH"
    DENY_REQUIRES_APPROVAL = "DENY_REQUIRES_APPROVAL"


class PolicyTransitionError(ValueError):
    def __init__(self, code: TransitionError, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class PolicyState:
    """Immutable reduced state. ``rules`` includes retired rules (kept for diagnostics)."""

    epoch: int = 0
    last_sequence: int = 0
    head_hash: str = GENESIS_HASH
    last_recorded_at: int = 0
    rules: Mapping[str, Rule] = field(default_factory=lambda: MappingProxyType({}))

    def active_rules(self) -> tuple[Rule, ...]:
        return tuple(r for _, r in sorted(self.rules.items()) if r.status is RuleStatus.ACTIVE)

    def state_digest(self) -> str:
        return digest(
            {
                "epoch": self.epoch,
                "last_sequence": self.last_sequence,
                "head_hash": self.head_hash,
                "rules": [r.model_dump(mode="json") for _, r in sorted(self.rules.items())],
            }
        )

    def snapshot(self, as_of_tick: int) -> PolicySnapshot:
        active = self.active_rules()
        body = {
            "epoch": self.epoch,
            "last_sequence": self.last_sequence,
            "last_event_hash": self.head_hash,
            "as_of_tick": as_of_tick,
            "active_rules": [r.model_dump(mode="json") for r in active],
        }
        return PolicySnapshot(
            epoch=self.epoch,
            last_sequence=self.last_sequence,
            last_event_hash=self.head_hash,
            as_of_tick=as_of_tick,
            active_rules=active,
            snapshot_digest=digest(body),
        )


EMPTY_STATE = PolicyState()


def check_change(state: PolicyState, change: PolicyChange) -> None:
    """Validate the semantic transition of ``change`` against ``state`` (no chain checks)."""
    rules = state.rules
    if change.rule_id is not None and change.rule_id in rules:
        raise PolicyTransitionError(
            TransitionError.RULE_ID_REUSED, f"rule_id {change.rule_id!r} was already used"
        )
    if change.target_rule_id is None:
        return
    target = rules.get(change.target_rule_id)
    if target is None:
        raise PolicyTransitionError(
            TransitionError.TARGET_UNKNOWN, f"target {change.target_rule_id!r} does not exist"
        )
    if target.status is not RuleStatus.ACTIVE:
        raise PolicyTransitionError(
            TransitionError.TARGET_NOT_ACTIVE,
            f"target {change.target_rule_id!r} is {target.status.value}",
        )
    if change.kind is PolicyEventKind.SUPERSEDE:
        if change.principal_id != target.principal_id or change.tool_id != target.tool_id:
            raise PolicyTransitionError(
                TransitionError.SUPERSEDE_SCOPE_MISMATCH,
                "SUPERSEDE must keep the target's principal_id and tool_id",
            )
        if target.effect is Effect.DENY and change.requires_approval:
            raise PolicyTransitionError(
                TransitionError.DENY_REQUIRES_APPROVAL,
                "a DENY rule cannot be superseded by one requiring approval",
            )


def _require(value: str | None, name: str) -> str:
    """Explicit invariant check (``assert`` is stripped under ``python -O``)."""
    if value is None:
        raise PolicyTransitionError(TransitionError.TARGET_UNKNOWN, f"{name} is missing")
    return value


def _new_rule(change: PolicyChange, effect: Effect, sequence: int, epoch: int) -> Rule:
    _require(change.rule_id, "rule_id")
    return Rule(
        rule_id=change.rule_id,
        effect=effect,
        principal_id=change.principal_id,
        tool_id=change.tool_id,
        operation=change.operation,
        resource_scope=change.resource_scope,
        valid_from=change.valid_from,
        valid_until=change.valid_until,
        requires_approval=change.requires_approval,
        status=RuleStatus.ACTIVE,
        created_sequence=sequence,
        created_epoch=epoch,
    )


def _retire(rule: Rule, status: RuleStatus, sequence: int, epoch: int, by: str | None) -> Rule:
    return rule.model_copy(
        update={
            "status": status,
            "retired_sequence": sequence,
            "retired_epoch": epoch,
            "replaced_by": by,
        }
    )


def _apply_change(rules: dict[str, Rule], change: PolicyChange, sequence: int, epoch: int) -> None:
    kind = change.kind
    if kind is PolicyEventKind.GRANT or kind is PolicyEventKind.DENY:
        effect = Effect.GRANT if kind is PolicyEventKind.GRANT else Effect.DENY
        rules[_require(change.rule_id, "rule_id")] = _new_rule(change, effect, sequence, epoch)
    elif kind is PolicyEventKind.REVOKE:
        tid = _require(change.target_rule_id, "target_rule_id")
        rules[tid] = _retire(rules[tid], RuleStatus.REVOKED, sequence, epoch, None)
    else:  # SUPERSEDE: retire the target and create its replacement in one event
        tid = _require(change.target_rule_id, "target_rule_id")
        new_id = _require(change.rule_id, "rule_id")
        effect = rules[tid].effect
        rules[tid] = _retire(rules[tid], RuleStatus.SUPERSEDED, sequence, epoch, new_id)
        rules[new_id] = _new_rule(change, effect, sequence, epoch)


def check_chain(state: PolicyState, event: PolicyEvent) -> None:
    """Validate ledger-assigned fields of ``event`` as the successor of ``state``."""
    if event.sequence != state.last_sequence + 1:
        raise PolicyTransitionError(
            TransitionError.SEQUENCE_GAP,
            f"expected sequence {state.last_sequence + 1}, got {event.sequence}",
        )
    if event.epoch != state.epoch + 1:
        raise PolicyTransitionError(
            TransitionError.EPOCH_MISMATCH, f"expected epoch {state.epoch + 1}, got {event.epoch}"
        )
    if event.prev_hash != state.head_hash:
        raise PolicyTransitionError(
            TransitionError.PREV_HASH_MISMATCH, f"sequence {event.sequence}: prev_hash mismatch"
        )
    if event.computed_hash() != event.event_hash:
        raise PolicyTransitionError(
            TransitionError.EVENT_HASH_MISMATCH, f"sequence {event.sequence}: event_hash mismatch"
        )
    if event.recorded_at < state.last_recorded_at:
        raise PolicyTransitionError(
            TransitionError.TIME_REGRESSION,
            f"sequence {event.sequence}: recorded_at moves backwards",
        )


def apply_event(state: PolicyState, event: PolicyEvent) -> PolicyState:
    """Return the successor state, or raise PolicyTransitionError. ``state`` is unchanged."""
    check_chain(state, event)
    check_change(state, event)
    rules = dict(state.rules)
    _apply_change(rules, event, event.sequence, event.epoch)
    return PolicyState(
        epoch=event.epoch,
        last_sequence=event.sequence,
        head_hash=event.event_hash,
        last_recorded_at=event.recorded_at,
        rules=MappingProxyType(rules),
    )


def reduce_events(events: Iterable[PolicyEvent], start: PolicyState = EMPTY_STATE) -> PolicyState:
    """Fold events onto ``start``. Uses one mutable dict internally for O(n) replay."""
    rules = dict(start.rules)
    current = start
    for event in events:
        frozen_view = PolicyState(
            current.epoch,
            current.last_sequence,
            current.head_hash,
            current.last_recorded_at,
            MappingProxyType(rules),
        )
        check_chain(frozen_view, event)
        check_change(frozen_view, event)
        _apply_change(rules, event, event.sequence, event.epoch)
        current = PolicyState(
            event.epoch, event.sequence, event.event_hash, event.recorded_at, frozen_view.rules
        )
    return PolicyState(
        current.epoch,
        current.last_sequence,
        current.head_hash,
        current.last_recorded_at,
        MappingProxyType(dict(rules)),
    )


def build_event(
    state: PolicyState,
    change: PolicyChange,
    *,
    event_id: str,
    actor_id: str,
    recorded_at: int,
) -> PolicyEvent:
    """Construct the next committed event for ``change`` (validates the transition first)."""
    check_change(state, change)
    if recorded_at < state.last_recorded_at:
        raise PolicyTransitionError(
            TransitionError.TIME_REGRESSION, "recorded_at precedes the ledger head"
        )
    fields = change.model_dump(mode="json")
    provisional = {
        **fields,
        "event_id": event_id,
        "sequence": state.last_sequence + 1,
        "epoch": state.epoch + 1,
        "actor_id": actor_id,
        "recorded_at": recorded_at,
        "prev_hash": state.head_hash,
    }
    return PolicyEvent.model_validate({**provisional, "event_hash": digest(provisional)})
