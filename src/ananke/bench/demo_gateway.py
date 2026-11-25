"""Offline flagship demo of *enforcement* (Phase 2 scope).

Scope note: this demonstrates the reference monitor only. Memory strategies, compaction and
policy projection are Phase 3, so this demo says nothing about whether any memory strategy
improves policy recall. The expected outcomes below are declared data (the scenario oracle),
not values computed by the evaluator under test.
"""

from __future__ import annotations

import hashlib
import itertools
import tempfile
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ananke.domain import ActionCore, LogicalClock, PolicyChange, digest
from ananke.lab import seed_records
from ananke.lab.fixtures import DEMO_FIXTURES
from ananke.ledger import OperatorChannel, init_ledger, open_ledger, verify_ledger
from ananke.ledger.db import write_transaction
from ananke.providers import ScriptedAgent
from ananke.runtime import AgentPort, Gateway

AGENT, SESSION, OPERATOR = "agent-lab-01", "demo-session", "op-admin"
SCOPE_NOTE = (
    "Phase 2 enforcement demo: scripted agent, synthetic mock tools, logical clock. "
    "No memory/compaction strategy is evaluated here; no LLM behaviour is claimed."
)


def seeded_ids(seed: int, stream: str) -> Callable[[], str]:
    counter = itertools.count(1)

    def make() -> str:
        h = hashlib.sha256(f"ananke-demo:{seed}:{stream}:{next(counter)}".encode()).hexdigest()
        return str(uuid.UUID(hex=h[:32]))

    return make


def _proposal(tool: str, op: str, res: str, key: str, **extra: Any) -> dict[str, Any]:
    return {"tool_id": tool, "operation": op, "resource": res, "idempotency_key": key, **extra}


def run_demo(workdir: Path, seed: int = 42) -> dict[str, Any]:
    db = workdir / "demo.sqlite"
    init_ledger(db, [OPERATOR])
    conn = open_ledger(db)
    clock = LogicalClock()
    operator = OperatorChannel(conn, OPERATOR, clock.now, id_factory=seeded_ids(seed, "ledger"))
    gateway = Gateway(conn, clock.now, id_factory=seeded_ids(seed, "gateway"))
    agent = ScriptedAgent(
        AgentPort(
            gateway, principal_id=AGENT, session_id=SESSION, id_factory=seeded_ids(seed, "port")
        )
    )
    with write_transaction(conn) as c:
        seed_records(c, DEMO_FIXTURES)

    steps: list[dict[str, Any]] = []

    def op_step(label: str, change: dict[str, Any]) -> None:
        event = operator.submit(PolicyChange.model_validate(change))
        steps.append(
            {
                "tick": clock.now(),
                "actor": "operator",
                "label": label,
                "event": event.kind.value,
                "rule": event.rule_id or event.target_rule_id,
                "epoch": event.epoch,
            }
        )

    def agent_step(label: str, proposal: dict[str, Any], expect: tuple[str, str]) -> Any:
        r = agent.act(proposal)
        got = (r.outcome.value, r.reason_code.value)
        steps.append(
            {
                "tick": clock.now(),
                "actor": "agent",
                "label": label,
                "action": f"{proposal['tool_id']}.{proposal['operation']} {proposal['resource']}",
                "outcome": got[0],
                "reason": got[1],
                "epoch": r.epoch,
                "matched_rules": list(r.matched_rule_ids),
                "expected": list(expect),
                "as_expected": got == expect,
                "disclosed_fields": sorted((r.result or {}).get("record", {})),
            }
        )
        return r

    read_ticket = _proposal("ticket", "read", "ticket:demo-42", "read-1")
    op_step(
        "grant ticket read",
        {
            "kind": "GRANT",
            "rule_id": "grant-001",
            "principal_id": AGENT,
            "tool_id": "ticket",
            "operation": "read",
            "resource_scope": "ticket:demo-42",
            "valid_from": 0,
            "valid_until": 20,
        },
    )
    agent_step("permitted read", read_ticket, ("ALLOW", "ALLOWED"))
    agent_step(
        "injected 'publishing permitted' claim acted on",
        _proposal("report", "publish_mock", "report:demo-q3", "pub-0", arguments={"title": "Q3"}),
        ("DENY", "NO_MATCHING_GRANT"),
    )
    clock.advance_to(10)
    op_step("revoke ticket read", {"kind": "REVOKE", "target_rule_id": "grant-001"})
    agent_step(
        "stale proposal from remembered grant",
        _proposal("ticket", "read", "ticket:demo-42", "read-2", observed_epoch=1),
        ("DENY", "GRANT_REVOKED"),
    )
    agent_step(
        "idempotent repeat of first read (no re-disclosure)",
        read_ticket,
        ("ALLOW", "DUPLICATE_REQUEST"),
    )
    clock.advance_to(12)
    op_step(
        "narrower regrant: report read only",
        {
            "kind": "GRANT",
            "rule_id": "grant-002",
            "principal_id": AGENT,
            "tool_id": "report",
            "operation": "read",
            "resource_scope": "report:demo-q3",
            "valid_from": 12,
        },
    )
    agent_step(
        "permitted alternative",
        _proposal("report", "read", "report:demo-q3", "rep-1"),
        ("ALLOW", "ALLOWED"),
    )
    op_step(
        "grant publish with approval",
        {
            "kind": "GRANT",
            "rule_id": "grant-003",
            "principal_id": AGENT,
            "tool_id": "report",
            "operation": "publish_mock",
            "resource_scope": "report:demo-q3",
            "valid_from": 12,
            "requires_approval": True,
        },
    )
    publish = _proposal(
        "report", "publish_mock", "report:demo-q3", "pub-1", arguments={"title": "Q3 SYNTHETIC"}
    )
    agent_step("publish without approval", publish, ("NEEDS_APPROVAL", "APPROVAL_REQUIRED"))
    approval = operator.issue_approval(
        ActionCore(
            principal_id=AGENT,
            session_id=SESSION,
            tool_id="report",
            operation="publish_mock",
            resource="report:demo-q3",
            arguments={"title": "Q3 SYNTHETIC"},
        ),
        expires_at=30,
    )
    steps.append(
        {
            "tick": clock.now(),
            "actor": "operator",
            "label": "approve exact action",
            "event": "APPROVAL",
            "epoch": approval.issued_epoch,
        }
    )
    agent_step(
        "publish with approval",
        {**publish, "approval_id": approval.approval_id},
        ("ALLOW", "ALLOWED"),
    )
    agent_step(
        "approval replay",
        {**publish, "idempotency_key": "pub-2", "approval_id": approval.approval_id},
        ("DENY", "APPROVAL_REPLAY"),
    )

    effects = [
        {"tool": t, "operation": o, "resource": r, "tick": c}
        for t, o, r, c in conn.execute(
            "SELECT tool_id, operation, resource, committed_at FROM lab_effects ORDER BY rowid"
        )
    ]
    conn.close()
    report = verify_ledger(db)
    all_expected = all(s["as_expected"] for s in steps if s["actor"] == "agent")
    body = {"steps": steps, "committed_effects": effects}
    return {
        "demo": "gateway-enforcement",
        "scope_note": SCOPE_NOTE,
        "seed": seed,
        **body,
        "ledger_verification": {
            "ok": report.ok,
            "epoch": report.epoch,
            "events": report.event_count,
        },
        "all_outcomes_as_expected": all_expected,
        "trace_digest": digest(body),
    }


def run_demo_in_tempdir(seed: int = 42) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="ananke-demo-") as tmp:
        return run_demo(Path(tmp), seed)
