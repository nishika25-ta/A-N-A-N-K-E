"""Deterministic scripted agent: tests runtime logic, NOT language-model behaviour.

A script is a list of steps. Each step yields one proposal (a plain dict, exactly what a model
adapter would emit) to the :class:`~ananke.runtime.port.AgentPort`. The agent never sees anything
but the receipts it gets back.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from ananke.domain import DecisionReceipt
from ananke.runtime.port import AgentPort


@dataclass
class ScriptedAgent:
    port: AgentPort
    memory: list[dict[str, Any]] = field(default_factory=list)  # what the agent "remembers"

    def act(self, proposal: Mapping[str, Any]) -> DecisionReceipt:
        receipt = self.port.propose(proposal)
        self.memory.append(
            {
                "proposal": dict(proposal),
                "outcome": receipt.outcome.value,
                "reason": receipt.reason_code.value,
                "epoch": receipt.epoch,
            }
        )
        return receipt

    def run(self, proposals: Iterable[Mapping[str, Any]]) -> list[DecisionReceipt]:
        return [self.act(p) for p in proposals]
