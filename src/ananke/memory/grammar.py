"""Rendering of policy facts into the model-visible statement grammar (ADR-0011).

One fact per line, a fixed field order, and no free text. The belief agent's parser
(``providers/belief.py``) is an independent implementation of the same grammar.
"""

from __future__ import annotations

from ananke.domain import Effect, PolicyEvent, PolicyEventKind, Rule
from ananke.ledger import PolicyState


def _window(valid_from: int, valid_until: int | None) -> str:
    return f"from={valid_from} until={'none' if valid_until is None else valid_until}"


def rule_line(rule: Rule, epoch: int) -> str:
    kind = "GRANT" if rule.effect is Effect.GRANT else "DENY"
    approval = "yes" if rule.requires_approval else "no"
    return (
        f"POLICY {kind} {rule.rule_id} {rule.tool_id}.{rule.operation} {rule.resource_scope} "
        f"principal={rule.principal_id} {_window(rule.valid_from, rule.valid_until)} "
        f"approval={approval} epoch={epoch}"
    )


def retired_line(rule: Rule) -> str:
    verb = "REVOKE" if rule.replaced_by is None else "SUPERSEDE"
    return f"POLICY {verb} {rule.rule_id} epoch={rule.retired_epoch}"


def snapshot_header(epoch: int, principal: str, now: int, *, complete: bool = True) -> str:
    return (
        f"POLICY SNAPSHOT epoch={epoch} principal={principal} now={now} "
        f"complete={'yes' if complete else 'no'}"
    )


def notice_lines(event: PolicyEvent, state_after: PolicyState) -> list[str]:
    """In-band operator notification of one committed event (what an agent is told).

    ``state_after`` is the reduced state including ``event``. It supplies the inherited effect of a
    SUPERSEDE replacement, which the event itself does not carry.
    """
    e = event
    if e.kind is PolicyEventKind.REVOKE:
        return [f"POLICY REVOKE {e.target_rule_id} epoch={e.epoch}"]
    new_rule = state_after.rules[e.rule_id or ""]
    lines = [rule_line(new_rule, e.epoch)]
    if e.kind is PolicyEventKind.SUPERSEDE:
        lines.insert(0, f"POLICY SUPERSEDE {e.target_rule_id} epoch={e.epoch}")
    return lines
