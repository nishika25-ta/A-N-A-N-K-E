"""Deterministic belief agent (ADR-0011). It reads *only* its model-visible context.

This is an independent implementation of the policy-statement grammar. It deliberately does
not import ``ananke.memory`` (enforced by tests/security/test_architecture.py), so a rendering
bug cannot be hidden by a shared parser. Its behaviour:

1. Parse ``POLICY ...`` lines from every section except ``UNTRUSTED DATA`` (unless
   ``respects_quarantine=False``, the sensitivity-analysis variant).
2. Resolve per rule with the latest epoch winning. A complete ``SNAPSHOT`` at epoch S retires
   every rule of the same principal (or every principal for ``*``) whose latest statement has
   epoch <= S and that is absent from the snapshot block.
3. Believe an action is permitted iff some believed-active GRANT matches exactly, its window
   contains ``now``, and no believed-active DENY matches.
4. At a checkpoint, propose the first task option believed permitted. Otherwise abstain.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

_RULE = re.compile(
    r"^POLICY (?P<kind>GRANT|DENY) (?P<id>\S+) (?P<tool>[a-z0-9_-]+)\.(?P<op>[a-z0-9_-]+) "
    r"(?P<res>\S+) principal=(?P<principal>\S+) from=(?P<from>\d+) until=(?P<until>\d+|none) "
    r"approval=(?P<approval>yes|no) epoch=(?P<epoch>\d+)$"
)
_RETIRE = re.compile(r"^POLICY (?P<kind>REVOKE|SUPERSEDE) (?P<id>\S+) epoch=(?P<epoch>\d+)$")
_SNAP = re.compile(
    r"^POLICY SNAPSHOT epoch=(?P<epoch>\d+) principal=(?P<principal>\S+) now=\d+ "
    r"complete=(?P<complete>yes|no)$"
)
_NOW = re.compile(r"^now=(?P<now>\d+)$")
QUARANTINE = "UNTRUSTED DATA"


@dataclass(frozen=True, slots=True)
class BelievedRule:
    rule_id: str
    effect: str
    tool: str
    op: str
    resource: str
    principal: str
    valid_from: int
    valid_until: int | None
    approval: bool
    epoch: int

    def live(self, now: int) -> bool:
        return self.valid_from <= now and (self.valid_until is None or now < self.valid_until)


@dataclass
class Beliefs:
    active: dict[str, BelievedRule] = field(default_factory=dict)
    retired: dict[str, int] = field(default_factory=dict)
    now: int | None = None
    adopted_from_quoted: set[str] = field(default_factory=set)  # rule ids parsed from '>' lines

    def permitted(
        self, principal: str, tool: str, op: str, res: str, now: int
    ) -> tuple[bool, bool]:
        """Return (believed permitted, believed approval required)."""
        hits = [
            r
            for r in self.active.values()
            if (r.principal, r.tool, r.op, r.resource) == (principal, tool, op, res) and r.live(now)
        ]
        if any(r.effect == "DENY" for r in hits):
            return False, False
        grants = [r for r in hits if r.effect == "GRANT"]
        return bool(grants), any(r.approval for r in grants)


def parse_context(text: str, *, respects_quarantine: bool = True) -> Beliefs:
    latest: dict[str, tuple[int, int, BelievedRule | None]] = {}  # id -> (epoch, order, rule|None)
    snapshots: list[tuple[int, str, set[str]]] = []
    beliefs = Beliefs()
    section = ""
    current_snap: tuple[int, str, set[str]] | None = None
    order = 0
    for raw in text.splitlines():
        if raw.startswith("## "):
            section = raw[3:].split(" [", 1)[0]
            current_snap = None
            continue
        quoted = raw.startswith("> ")
        if section == QUARANTINE and respects_quarantine:
            continue
        line = raw[2:] if quoted else raw
        line = line.strip()
        order += 1
        if (m := _NOW.match(line)) is not None:
            beliefs.now = int(m["now"])
            continue
        if (m := _SNAP.match(line)) is not None:
            current_snap = (int(m["epoch"]), m["principal"], set())
            if m["complete"] == "yes":
                snapshots.append(current_snap)
            continue
        if (m := _RULE.match(line)) is not None:
            rule = BelievedRule(
                rule_id=m["id"],
                effect=m["kind"],
                tool=m["tool"],
                op=m["op"],
                resource=m["res"],
                principal=m["principal"],
                valid_from=int(m["from"]),
                valid_until=None if m["until"] == "none" else int(m["until"]),
                approval=m["approval"] == "yes",
                epoch=int(m["epoch"]),
            )
            _record(latest, rule.rule_id, rule.epoch, order, rule)
            if current_snap is not None:
                current_snap[2].add(rule.rule_id)
            if quoted:
                beliefs.adopted_from_quoted.add(rule.rule_id)
            continue
        if (m := _RETIRE.match(line)) is not None:
            _record(latest, m["id"], int(m["epoch"]), order, None)
            current_snap = None
            continue
        current_snap = None  # any other line ends a snapshot block
    for rule_id, (epoch, _, stmt) in latest.items():
        if stmt is None:
            beliefs.retired[rule_id] = epoch
            continue
        covered = [
            snap for snap in snapshots if snap[0] >= epoch and snap[1] in ("*", stmt.principal)
        ]
        if any(rule_id not in snap[2] for snap in covered):
            beliefs.retired[rule_id] = max(snap[0] for snap in covered)
        else:
            beliefs.active[rule_id] = stmt
    return beliefs


def _record(
    latest: dict[str, tuple[int, int, BelievedRule | None]],
    rule_id: str,
    epoch: int,
    order: int,
    rule: BelievedRule | None,
) -> None:
    prev = latest.get(rule_id)
    if prev is None or (epoch, order) >= (prev[0], prev[1]):
        latest[rule_id] = (epoch, order, rule)


@dataclass(frozen=True, slots=True)
class TaskOption:
    tool: str
    op: str
    resource: str
    arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Choice:
    option: TaskOption | None  # None = abstain
    believed_approval: bool
    beliefs_active: int


@dataclass(frozen=True, slots=True)
class BeliefAgent:
    principal: str
    respects_quarantine: bool = True

    def choose(self, context_text: str, options: Sequence[TaskOption]) -> Choice:
        beliefs = parse_context(context_text, respects_quarantine=self.respects_quarantine)
        now = beliefs.now if beliefs.now is not None else 0
        for opt in options:
            ok, approval = beliefs.permitted(self.principal, opt.tool, opt.op, opt.resource, now)
            if ok:
                return Choice(opt, approval, len(beliefs.active))
        return Choice(None, False, len(beliefs.active))

    def recall(self, context_text: str, queries: Sequence[TaskOption]) -> list[bool]:
        """Structured policy recall: is each query believed permitted at the context's ``now``?"""
        beliefs = parse_context(context_text, respects_quarantine=self.respects_quarantine)
        now = beliefs.now if beliefs.now is not None else 0
        return [
            beliefs.permitted(self.principal, q.tool, q.op, q.resource, now)[0] for q in queries
        ]
