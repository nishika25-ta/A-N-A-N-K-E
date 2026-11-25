"""Scenario DSL (MASTERPLAN section 11): a declarative, strictly validated timeline.

A scenario is data: fixtures, a principal, enabled tools, and a tick-ordered timeline of operator
changes, observations, compactions, approvals and checkpoints. Expected outcomes are *not* stored.
The independent oracle (``bench/oracle.py``) derives them from the timeline alone.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Final, Literal, Self

from pydantic import Field, StrictBool, StrictStr, model_validator

from ananke.domain import PolicyChange, Sensitivity, canonical_bytes, digest
from ananke.domain.models import Identifier, Resource, StrictModel, Tick

SCENARIO_SCHEMA: Final = "ananke.scenario/0"


class Split(StrEnum):
    DEV = "dev"
    HOLDOUT = "holdout"


class ObservationOrigin(StrEnum):
    TASK = "TASK"
    TOOL_RESULT = "TOOL_RESULT"
    AGENT = "AGENT"


class Option(StrictModel):
    tool_id: Identifier
    operation: Identifier
    resource: Resource
    arguments: dict[StrictStr, Any] = Field(default_factory=dict)
    approval_ref: Identifier | None = None  # refers to an ApproveStep.approval_ref
    attack: StrictBool = False  # option corresponds to an injected (forged) authority claim


class OperatorStep(StrictModel):
    kind: Literal["operator"] = "operator"
    tick: Tick
    change: PolicyChange
    notify: StrictBool = True  # deliver an in-band notice to the agent


class ObserveStep(StrictModel):
    kind: Literal["observe"] = "observe"
    tick: Tick
    origin: ObservationOrigin
    content: StrictStr
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    resource_refs: tuple[Resource, ...] = ()


class CompactStep(StrictModel):
    kind: Literal["compact"] = "compact"
    tick: Tick


class ApproveStep(StrictModel):
    kind: Literal["approve"] = "approve"
    tick: Tick
    approval_ref: Identifier
    option: Option
    expires_at: Tick


class CheckpointStep(StrictModel):
    kind: Literal["checkpoint"] = "checkpoint"
    tick: Tick
    checkpoint_id: Identifier
    options: tuple[Option, ...] = Field(min_length=1)
    eligible: StrictBool = True  # predeclared: counts toward the primary endpoint
    post_transition: StrictBool = False  # follows an authority change for these options


Step = Annotated[
    OperatorStep | ObserveStep | CompactStep | ApproveStep | CheckpointStep,
    Field(discriminator="kind"),
]


class Scenario(StrictModel):
    schema_version: Literal["ananke.scenario/0"] = SCENARIO_SCHEMA
    scenario_id: Identifier
    family: Identifier
    split: Split
    template: Identifier
    variant: int = Field(ge=0)
    principal: Identifier
    tools: tuple[Identifier, ...]
    fixtures: dict[Resource, dict[StrictStr, Any]]
    timeline: tuple[Step, ...] = Field(min_length=1)
    description: StrictStr = ""

    @model_validator(mode="after")
    def _ordered_and_unique(self) -> Self:
        ticks = [step.tick for step in self.timeline]
        if ticks != sorted(ticks):
            raise ValueError("timeline must be in non-decreasing tick order")
        ids = [s.checkpoint_id for s in self.timeline if isinstance(s, CheckpointStep)]
        if len(ids) != len(set(ids)):
            raise ValueError("checkpoint ids must be unique")
        refs = [s.approval_ref for s in self.timeline if isinstance(s, ApproveStep)]
        if len(refs) != len(set(refs)):
            raise ValueError("approval refs must be unique")
        for res in self.fixtures:
            if res.split(":", 1)[0] not in self.tools:
                raise ValueError(f"fixture {res} is outside the enabled tools")
        return self

    def checksum(self) -> str:
        return digest(self.model_dump(mode="json"))

    def canonical_json(self) -> bytes:
        return canonical_bytes(self.model_dump(mode="json"))
