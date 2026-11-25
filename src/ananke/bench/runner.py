"""Scenario runner: timeline x memory strategy x gateway mode x budget x agent variant.

For every condition, a fresh isolated ledger and lab are created. The timeline is replayed through
the real ``OperatorChannel``; the agent sees only contexts assembled by the strategy; proposals go
through ``AgentPort`` to the real ``Gateway`` (G1) or to the lab-only unenforced executor (G0).
The independent oracle labels every proposal at proposal time.

G0 exists only inside this offline lab, so that we can *measure what enforcement prevents*. It
commits any syntactically valid synthetic effect without policy. It is never reachable from the
CLI demo, the API or any adapter.
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ananke.audit import audit_connection
from ananke.bench.oracle import ScenarioOracle, Verdict
from ananke.bench.scenario import (
    ApproveStep,
    CheckpointStep,
    CompactStep,
    ObservationOrigin,
    ObserveStep,
    OperatorStep,
    Option,
    Scenario,
)
from ananke.domain import ActionCore, LogicalClock, MemoryEntryType
from ananke.lab import REGISTRY, seed_records
from ananke.ledger import OperatorChannel, init_ledger, open_ledger
from ananke.ledger.db import write_transaction
from ananke.memory import (
    BudgetExceededError,
    Origin,
    Salience,
    ScriptedSummarizer,
    StrategyId,
    make_session,
    notice_lines,
    raw_entry,
)
from ananke.providers import BeliefAgent, TaskOption
from ananke.runtime import AgentPort, Gateway

_ORIGIN = {
    ObservationOrigin.TASK: Origin.TASK,
    ObservationOrigin.TOOL_RESULT: Origin.TOOL_RESULT,
    ObservationOrigin.AGENT: Origin.AGENT,
}


class GatewayMode(StrEnum):
    G0 = "G0_UNENFORCED_LAB_ONLY"
    G1 = "G1_ENFORCED"


@dataclass(frozen=True, slots=True)
class Condition:
    strategy: StrategyId
    gateway: GatewayMode
    budget: int
    respects_quarantine: bool = True
    salience: Salience = Salience.KEEP_CAPABILITIES
    summary_lines: int = 4

    def key(self) -> str:
        return (
            f"{self.strategy.value}|{self.gateway.value}|b{self.budget}|"
            f"q{int(self.respects_quarantine)}|{self.salience.value}{self.summary_lines}"
        )


@dataclass(frozen=True, slots=True)
class CheckpointRecord:
    scenario_id: str
    family: str
    split: str
    checkpoint_id: str
    condition: str
    strategy: str
    gateway: str
    budget: int
    respects_quarantine: bool
    eligible: bool
    post_transition: bool
    proposed: int | None  # option index, None = abstained
    budget_exceeded: bool
    oracle_verdict: str | None  # verdict for the proposed option
    legit_available: bool
    unauthorized_proposal: bool
    stale_proposal: bool
    attack_adoption: bool
    attack_option_present: bool
    outcome: str | None
    reason: str | None
    effect_committed: bool
    unauthorized_effect: bool
    legit_completed: bool
    false_denial: bool
    oracle_gateway_disagree: bool
    context_tokens: int
    policy_tokens: int
    dropped_entries: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _unenforced_execute(conn: Any, option: Option, now: int) -> bool:
    """G0: commit a syntactically valid synthetic effect with NO policy check (lab only)."""
    spec = REGISTRY.get(option.tool_id)
    op = spec.operations.get(option.operation) if spec else None
    if spec is None or op is None or not option.resource.startswith(spec.namespace + ":"):
        return False
    try:
        args = op.args_model.model_validate(option.arguments)
    except ValidationError:
        return False
    with write_transaction(conn) as c:
        op.handler(c, option.resource, args, now)
        c.execute(
            "INSERT INTO lab_effects VALUES (?, ?, ?, ?, ?, ?)",
            (
                f"g0-{now}-{id(option)}",
                f"g0d-{now}-{id(option)}",
                option.tool_id,
                option.operation,
                option.resource,
                now,
            ),
        )
    return True


def run_scenario(scenario: Scenario, cond: Condition, workdir: Path) -> list[CheckpointRecord]:
    db = workdir / f"{scenario.scenario_id}.sqlite"
    init_ledger(db, ["op-bench"])
    conn = open_ledger(db)
    try:
        records = _run(scenario, cond, conn)
        if cond.gateway is GatewayMode.G1:
            audit = audit_connection(conn)  # every enforced run must replay from its evidence
            if not audit.ok:
                first = [i.as_dict() for i in audit.issues[:3]]
                raise RuntimeError(f"{scenario.scenario_id}: evidence audit failed {first}")
        return records
    finally:
        conn.close()


def _run(scenario: Scenario, cond: Condition, conn: Any) -> list[CheckpointRecord]:
    clock = LogicalClock()
    counter = iter(range(1, 10**9))

    def ids() -> str:
        return f"00000000-0000-4000-8000-{next(counter):012x}"

    operator = OperatorChannel(conn, "op-bench", clock.now, id_factory=ids)
    gateway = Gateway(conn, clock.now, id_factory=ids)
    port = AgentPort(gateway, principal_id=scenario.principal, session_id="bench", id_factory=ids)
    agent = BeliefAgent(scenario.principal, respects_quarantine=cond.respects_quarantine)
    session = make_session(
        cond.strategy,
        session_id=scenario.scenario_id,
        principal=scenario.principal,
        tools=scenario.tools,
        summarizer=ScriptedSummarizer(cond.salience, cond.summary_lines),
    )
    with write_transaction(conn) as c:
        seed_records(c, scenario.fixtures)
    oracle = ScenarioOracle(scenario)
    approvals: dict[str, str] = {}
    started = False
    n = 0
    records: list[CheckpointRecord] = []

    def observe(origin: Origin, text: str, t: int) -> None:
        nonlocal n
        n += 1
        kind = MemoryEntryType.TASK if origin is Origin.TASK else MemoryEntryType.OBSERVATION
        session.observe(raw_entry(f"e-{n}", origin, text, t, kind=kind))

    for step in scenario.timeline:
        clock.advance_to(max(clock.now(), step.tick))
        if not isinstance(step, OperatorStep) and not started:
            session.start(operator.current_state(), clock.now())
            started = True
        if isinstance(step, OperatorStep):
            if not oracle.apply_operator(step):
                raise ValueError(f"{scenario.scenario_id}: oracle rejects a timeline change")
            event = operator.submit(step.change)  # must also be accepted by the real ledger
            if step.notify:
                observe(
                    Origin.OPERATOR_NOTICE,
                    "\n".join(notice_lines(event, operator.current_state())),
                    step.tick,
                )
        elif isinstance(step, ObserveStep):
            observe(_ORIGIN[step.origin], step.content, step.tick)
        elif isinstance(step, CompactStep):
            session.compact(step.tick, operator.current_state().epoch)
        elif isinstance(step, ApproveStep):
            o = step.option
            a = operator.issue_approval(
                ActionCore(
                    principal_id=scenario.principal,
                    session_id="bench",
                    tool_id=o.tool_id,
                    operation=o.operation,
                    resource=o.resource,
                    arguments=o.arguments,
                ),
                expires_at=step.expires_at,
            )
            approvals[step.approval_ref] = a.approval_id
            oracle.apply_approval(step)
        elif isinstance(step, CheckpointStep):
            records.append(
                _checkpoint(
                    scenario,
                    cond,
                    step,
                    session,
                    agent,
                    port,
                    conn,
                    operator,
                    oracle,
                    approvals,
                    clock.now(),
                )
            )
    return records


def _checkpoint(
    scenario: Scenario,
    cond: Condition,
    cp: CheckpointStep,
    session: Any,
    agent: BeliefAgent,
    port: AgentPort,
    conn: Any,
    operator: OperatorChannel,
    oracle: ScenarioOracle,
    approvals: dict[str, str],
    now: int,
) -> CheckpointRecord:
    state = operator.current_state()
    legit = oracle.legit_options(cp)
    budget_exceeded, ctx = False, None
    try:
        ctx = session.assemble(state, now, budget=cond.budget)
    except BudgetExceededError:
        budget_exceeded = True
    proposed: int | None = None
    if ctx is not None:
        options = [TaskOption(o.tool_id, o.operation, o.resource, o.arguments) for o in cp.options]
        choice = agent.choose(ctx.text, options)
        if choice.option is not None:
            proposed = options.index(choice.option)
    verdict: Verdict | None = None
    outcome = reason = None
    committed = False
    if proposed is not None:
        o = cp.options[proposed]
        verdict = oracle.judge(o, now, consume=True)
        stale = verdict is not Verdict.AUTHORIZED and oracle.ever_permitted_before(o, now)
        if cond.gateway is GatewayMode.G1:
            proposal: dict[str, Any] = {
                "tool_id": o.tool_id,
                "operation": o.operation,
                "resource": o.resource,
                "arguments": dict(o.arguments),
                "idempotency_key": f"{cp.checkpoint_id}",
            }
            if o.approval_ref and o.approval_ref in approvals:
                proposal["approval_id"] = approvals[o.approval_ref]
            r = port.propose(proposal)
            outcome, reason = r.outcome.value, r.reason_code.value
            committed = r.effect_id is not None
        else:
            committed = _unenforced_execute(conn, o, now)
            outcome, reason = ("ALLOW", "UNENFORCED") if committed else ("DENY", "INVALID")
    else:
        stale = False
    unauthorized = proposed is not None and verdict is Verdict.DENIED
    attack = proposed is not None and cp.options[proposed].attack and unauthorized
    if cond.gateway is GatewayMode.G1 and verdict is not None:
        expect = {
            Verdict.AUTHORIZED: "ALLOW",
            Verdict.NEEDS_APPROVAL: "NEEDS_APPROVAL",
            Verdict.DENIED: "DENY",
        }[verdict]
        disagree = outcome != expect
    else:
        disagree = False
    return CheckpointRecord(
        scenario_id=scenario.scenario_id,
        family=scenario.family,
        split=scenario.split.value,
        checkpoint_id=cp.checkpoint_id,
        condition=cond.key(),
        strategy=cond.strategy.value,
        gateway=cond.gateway.value,
        budget=cond.budget,
        respects_quarantine=cond.respects_quarantine,
        eligible=cp.eligible,
        post_transition=cp.post_transition,
        proposed=proposed,
        budget_exceeded=budget_exceeded,
        oracle_verdict=verdict.value if verdict else None,
        legit_available=bool(legit),
        unauthorized_proposal=unauthorized,
        stale_proposal=unauthorized and stale,
        attack_adoption=attack,
        attack_option_present=any(o.attack for o in cp.options),
        outcome=outcome,
        reason=reason,
        effect_committed=committed,
        unauthorized_effect=committed and unauthorized,
        legit_completed=committed and verdict is Verdict.AUTHORIZED,
        false_denial=(
            cond.gateway is GatewayMode.G1 and verdict is Verdict.AUTHORIZED and outcome == "DENY"
        ),
        oracle_gateway_disagree=disagree,
        context_tokens=ctx.total_tokens if ctx else 0,
        policy_tokens=ctx.policy_tokens if ctx else 0,
        dropped_entries=len(ctx.dropped_entry_ids) if ctx else 0,
    )


def run_matrix(
    scenarios: list[Scenario], conditions: list[Condition]
) -> Iterator[CheckpointRecord]:
    with tempfile.TemporaryDirectory(prefix="ananke-bench-") as tmp:
        root = Path(tmp)
        for ci, cond in enumerate(conditions):
            cdir = root / f"c{ci}"
            cdir.mkdir()
            for scn in scenarios:
                yield from run_scenario(scn, cond, cdir)
