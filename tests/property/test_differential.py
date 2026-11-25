"""Differential property test: real ledger + gateway vs the independent reference model.

Random programs interleave operator changes, clock advances and agent requests from two
principals. For every step, the production system and the reference model must agree on:
transition acceptance, (outcome, reason) of each request, and the number of committed effects.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, event, given, settings
from hypothesis import strategies as st

from ananke.audit import audit_connection
from ananke.domain import PolicyChange
from ananke.ledger import PolicyTransitionError
from ananke.runtime import AgentPort
from ananke_testkit import GatewayLab, seq_ids
from reference_model import ReferencePolicy

PRINCIPALS = ["agent-a", "agent-b"]
OPS = {"ticket": ["read", "update"], "report": ["read", "publish_mock"]}
RES = {"ticket": ["ticket:t1", "ticket:t2"], "report": ["report:r1"]}
ARGS = {("ticket", "update"): {"status": "pending"}, ("report", "publish_mock"): {"title": "T"}}
RULE_IDS = [f"r{i}" for i in range(8)]


@st.composite
def rule_fields(draw: st.DrawFn) -> dict[str, Any]:
    tool = draw(st.sampled_from(sorted(OPS)))
    vf = draw(st.integers(0, 6))
    return {
        "principal_id": draw(st.sampled_from(PRINCIPALS)),
        "tool_id": tool,
        "operation": draw(st.sampled_from(OPS[tool])),
        "resource_scope": draw(st.sampled_from(RES[tool])),
        "valid_from": vf,
        "valid_until": draw(st.none() | st.integers(vf + 1, vf + 8)),
    }


@st.composite
def steps(draw: st.DrawFn) -> tuple[str, Any]:
    kind = draw(
        st.sampled_from(
            ["grant", "grant", "deny", "revoke", "supersede", "tick", "req", "req", "req"]
        )
    )
    if kind == "tick":
        return ("tick", draw(st.integers(1, 4)))
    if kind == "req":
        tool = draw(st.sampled_from(sorted(OPS)))
        return (
            "req",
            (
                draw(st.sampled_from(PRINCIPALS)),
                tool,
                draw(st.sampled_from(OPS[tool])),
                draw(st.sampled_from(RES[tool])),
            ),
        )
    if kind == "revoke":
        return ("change", {"kind": "REVOKE", "target_rule_id": draw(st.sampled_from(RULE_IDS))})
    f = draw(rule_fields())
    rid = draw(st.sampled_from(RULE_IDS))
    approval = draw(st.booleans()) and kind != "deny"
    ch = {"kind": kind.upper(), "rule_id": rid, "requires_approval": approval, **f}
    if kind == "supersede":
        target = draw(st.sampled_from(RULE_IDS))
        if target == rid:
            return ("change", {"kind": "REVOKE", "target_rule_id": target})
        ch["target_rule_id"] = target
    return ("change", ch)


def _normalize(ch: dict[str, Any]) -> dict[str, Any]:
    full = {
        "rule_id": None,
        "target_rule_id": None,
        "principal_id": None,
        "tool_id": None,
        "operation": None,
        "resource_scope": None,
        "valid_from": None,
        "valid_until": None,
        "requires_approval": False,
    }
    return {**full, **ch}


def _steer(ref: ReferencePolicy, ch: dict[str, Any], i: int) -> dict[str, Any]:
    """Retarget 3/4 of revoke/supersede onto an active, scope-compatible rule (coverage)."""
    if ch["kind"] not in ("REVOKE", "SUPERSEDE") or i % 4 == 0:
        return ch
    active = sorted((rid, r) for rid, r in ref._status().items() if r["status"] == "ACTIVE")
    if not active:
        return ch
    rid, target = active[i % len(active)]
    ch = {**ch, "target_rule_id": rid}
    if ch["kind"] == "SUPERSEDE":
        if ch["rule_id"] == rid:
            return {"kind": "REVOKE", "target_rule_id": rid}
        tool = target["tool_id"]
        ch.update(
            principal_id=target["principal_id"],
            tool_id=tool,
            operation=OPS[tool][i % len(OPS[tool])],
            resource_scope=RES[tool][0],
        )
        if target["effect"] == "DENY":
            ch["requires_approval"] = False
    return ch


def _steer_request(
    ref: ReferencePolicy, req: tuple[str, str, str, str], i: int, now: int
) -> tuple[str, str, str, str]:
    """Aim 4/5 of requests at the exact coordinates of some rule in the history (any status).

    Half of those prefer rules whose window has opened. Only *which coordinates* are asked about
    is steered; the expected outcome is still computed independently by the reference model.
    """
    rules = [h for h in ref.history if h.get("rule_id") is not None]
    if not rules or i % 5 == 0:
        return req
    opened = [r for r in rules if r["valid_from"] <= now]
    pool = opened if (opened and i % 2 == 0) else rules
    r = pool[(i * 7) % len(pool)]
    return (r["principal_id"], r["tool_id"], r["operation"], r["resource_scope"])


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(steps(), min_size=1, max_size=40))
def test_gateway_agrees_with_reference_model(program: list[tuple[str, Any]]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        lab = GatewayLab(Path(tmp), signed=True)  # exercise the ADR-0010 path
        ports = {
            p: AgentPort(lab.gateway, principal_id=p, session_id="s1", id_factory=seq_ids(20 + i))
            for i, p in enumerate(PRINCIPALS)
        }
        ref = ReferencePolicy()
        expected_effects = 0
        try:
            for i, (kind, payload) in enumerate(program):
                if kind == "tick":
                    lab.clock.advance(payload)
                elif kind == "change":
                    ch = _normalize(_steer(ref, payload, i))
                    ref_ok = ref.accept(ch)
                    try:
                        lab.operator.submit(PolicyChange.model_validate(ch))
                        real_ok = True
                    except PolicyTransitionError:
                        real_ok = False
                    assert real_ok == ref_ok, f"step {i}: acceptance differs for {ch}"
                else:
                    principal, tool, op, res = _steer_request(ref, payload, i, lab.clock.now())
                    want = ref.decide(principal, tool, op, res, lab.clock.now())
                    event(f"reason={want[1]}")
                    got = ports[principal].propose(
                        {
                            "tool_id": tool,
                            "operation": op,
                            "resource": res,
                            "arguments": ARGS.get((tool, op), {}),
                            "idempotency_key": f"k{i}",
                        }
                    )
                    assert (got.outcome.value, got.reason_code.value) == want, (
                        f"step {i}: {payload} at t={lab.clock.now()}"
                    )
                    expected_effects += want[0] == "ALLOW"
            assert len(lab.effects()) == expected_effects
            audit = audit_connection(lab.conn)  # every decision must replay from the evidence
            assert audit.ok, audit.as_dict()
        finally:
            lab.close()
