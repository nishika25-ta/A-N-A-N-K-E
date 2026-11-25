"""Deterministic policy renderings for model context (all advisory; the gateway is the authority).

* :func:`full_policy`: M4 baseline. Every active rule for *every* principal, as a complete snapshot.
  This is the Constraint-Pinning-style "fresh full policy" baseline (Governance Decay, arXiv
  2606.22528; an approximate reimplementation, not the authors' code).
* :func:`projection`: M5 candidate. A complete snapshot for this principal and its enabled tools:
  exact scopes and windows, denies (deny wins), approval obligations, and revocation/supersession
  warnings for rules this session has previously been shown.

Applicability is decided by exact principal and tool match only. No model chooses what is
authoritative, and nothing ambiguous is dropped silently.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable

from ananke.domain import RuleStatus
from ananke.ledger import PolicyState
from ananke.memory.grammar import retired_line, rule_line, snapshot_header


def _active_sorted(state: PolicyState) -> list:  # type: ignore[type-arg]
    return sorted(
        (r for r in state.rules.values() if r.status is RuleStatus.ACTIVE),
        key=lambda r: (r.principal_id, r.tool_id, r.operation, r.resource_scope, r.rule_id),
    )


def full_policy(state: PolicyState, now: int) -> list[str]:
    lines = [snapshot_header(state.epoch, "*", now)]
    lines += [rule_line(r, r.created_epoch) for r in _active_sorted(state)]
    return lines


def projection(
    state: PolicyState,
    *,
    principal: str,
    tools: Collection[str],
    now: int,
    seen_rule_ids: Iterable[str] = (),
    revocation_warnings: bool = True,
) -> list[str]:
    lines = [snapshot_header(state.epoch, principal, now)]
    lines += [
        rule_line(r, r.created_epoch)
        for r in _active_sorted(state)
        if r.principal_id == principal and r.tool_id in tools
    ]
    if revocation_warnings:
        seen = set(seen_rule_ids)
        retired = sorted(
            (
                r
                for r in state.rules.values()
                if r.rule_id in seen and r.status is not RuleStatus.ACTIVE
            ),
            key=lambda r: r.rule_id,
        )
        lines += [retired_line(r) for r in retired]
    return lines


def mentioned_rule_ids(lines: Iterable[str]) -> set[str]:
    """Rule ids appearing in rendered POLICY lines (what a session has 'seen')."""
    ids: set[str] = set()
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "POLICY" and parts[1] != "SNAPSHOT":
            ids.add(parts[2])
    return ids
