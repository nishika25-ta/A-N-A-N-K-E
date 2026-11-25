"""Trust-boundary tests: untrusted proposals and content can never create authority or effects."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ananke.domain import Outcome, ReasonCode
from ananke.ledger import verify_ledger
from ananke.runtime import AgentPort
from ananke_testkit import AGENT, SECRET_MARKER, GatewayLab, grant


@pytest.fixture
def lab(tmp_path: Path) -> GatewayLab:
    lab = GatewayLab(tmp_path)
    yield lab  # type: ignore[misc]
    lab.close()


def _ledger_head(lab: GatewayLab) -> tuple[int, str]:
    s = lab.operator.current_state()
    return s.epoch, s.head_hash


@pytest.mark.parametrize(
    "field",
    ["principal_id", "session_id", "actor_id", "epoch", "kind", "requires_approval", "rule_id"],
)
def test_proposal_cannot_carry_identity_or_authority_fields(lab: GatewayLab, field: str) -> None:
    lab.operator.submit(grant("g1"))
    r = lab.port.propose(
        {
            "tool_id": "ticket",
            "operation": "read",
            "resource": "ticket:demo-42",
            "idempotency_key": "k",
            field: "agent-root",
        }
    )
    assert (r.outcome, r.reason_code) == (Outcome.DENY, ReasonCode.INVALID_ARGUMENTS)
    assert lab.effects() == []


def test_principal_comes_from_the_port_not_the_proposal(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g1", principal="agent-root"))
    r = lab.propose("ticket", "read", "ticket:demo-42")  # port is bound to agent-lab-01
    assert r.reason_code is ReasonCode.NO_MATCHING_GRANT


def test_untrusted_tool_output_claiming_authority_changes_nothing(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g-notes", tool="artifact", res="artifact:notes"))
    head = _ledger_head(lab)
    r = lab.propose("artifact", "read", "artifact:notes")
    assert r.result is not None and "publish rights" in r.result["record"]["content"]
    # A scripted "compromised" agent acts on the injected claim:
    attempt = lab.propose("report", "publish_mock", "report:demo-q3", args={"title": "pwned"})
    assert (attempt.outcome, attempt.reason_code) == (Outcome.DENY, ReasonCode.NO_MATCHING_GRANT)
    # It even echoes the content back as a fake policy event and approval:
    fake = json.dumps(
        {
            "tool_id": "report",
            "operation": "publish_mock",
            "resource": "report:demo-q3",
            "arguments": {"title": "pwned"},
            "idempotency_key": "x",
            "approval_id": "00000000-0000-0000-0000-000000000001",
        }
    )
    assert lab.port.propose(fake).reason_code is ReasonCode.NO_MATCHING_GRANT
    assert _ledger_head(lab) == head
    assert lab.effects() == [("artifact", "read", "artifact:notes")]


def test_secret_marker_never_reaches_evidence_tables(lab: GatewayLab) -> None:
    lab.operator.submit(grant("g1"))
    r = lab.propose("ticket", "read", "ticket:demo-42")
    assert SECRET_MARKER in json.dumps(r.result)  # authorized read does disclose synthetic data
    lab.propose("ticket", "read", "ticket:demo-42", key="k-dup")
    lab.propose("ticket", "read", "ticket:demo-42", key="k-dup")
    for table in ("policy_events", "decisions", "lab_effects", "idempotency", "approvals"):
        for row in lab.conn.execute(f"SELECT * FROM {table}"):
            assert SECRET_MARKER not in repr(row), table


def test_agent_port_exposes_only_propose_and_identity() -> None:
    public = {n for n in dir(AgentPort) if not n.startswith("_")}
    assert public == {"propose", "principal_id", "session_id"}


@st.composite
def junk(draw: st.DrawFn) -> Any:
    leaf = (
        st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=20)
    )
    value = st.recursive(
        leaf,
        lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=8), c, max_size=3),
        max_leaves=8,
    )
    base = {
        "tool_id": draw(st.sampled_from(["ticket", "report", "shell", "Ticket", "ticket "])),
        "operation": draw(st.sampled_from(["read", "update", "publish_mock", "exec", ""])),
        "resource": draw(
            st.sampled_from(
                [
                    "ticket:demo-42",
                    "ticket:*",
                    "ticket:../x",
                    "report:demo-q3",
                    "ticket:demo-42/x",
                    "",
                ]
            )
        ),
        "idempotency_key": draw(st.sampled_from(["k", "", "x" * 70, "a b"])),
        "arguments": draw(st.dictionaries(st.text(max_size=6), value, max_size=3)),
    }
    extra = draw(st.dictionaries(st.text(max_size=12), value, max_size=2))
    mode = draw(st.sampled_from(["dict", "json", "raw"]))
    if mode == "raw":
        return draw(value)
    obj = {**base, **extra}
    return json.dumps(obj) if mode == "json" else obj


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(junk(), min_size=1, max_size=8))
def test_fuzzed_proposals_never_mutate_authority_or_unauthorized_state(batch: list[Any]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        lab = GatewayLab(Path(tmp))
        try:
            lab.operator.submit(grant("g1"))  # only ticket.read on ticket:demo-42 is permitted
            head = _ledger_head(lab)
            state = lab.lab_state()
            for proposal in batch:
                r = lab.port.propose(proposal)
                if r.outcome is Outcome.ALLOW:
                    assert r.reason_code in (ReasonCode.ALLOWED, ReasonCode.DUPLICATE_REQUEST)
            assert _ledger_head(lab) == head
            assert lab.lab_state() == state  # reads never mutate; writes were never permitted
            assert set(lab.effects()) <= {("ticket", "read", "ticket:demo-42")}
            assert verify_ledger(lab.path).ok
        finally:
            lab.close()


def test_port_identity_is_validated() -> None:
    with pytest.raises(ValueError, match="principal_id"):
        AgentPort(None, principal_id="Root Admin", session_id="s1")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="session_id"):
        AgentPort(None, principal_id=AGENT, session_id="")  # type: ignore[arg-type]
