"""Benchmark configuration (frozen, hashed into every run manifest)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool, StrictInt, StrictStr

from ananke.bench.runner import Condition, GatewayMode
from ananke.bench.scenario import Split
from ananke.domain import digest
from ananke.domain.models import StrictModel
from ananke.memory import Salience, StrategyId


class BenchConfig(StrictModel):
    schema_version: Literal["ananke.bench-config/0"] = "ananke.bench-config/0"
    name: StrictStr
    split: Split
    strategies: tuple[StrategyId, ...] = Field(min_length=1)
    gateways: tuple[GatewayMode, ...] = (GatewayMode.G1,)
    budgets: tuple[StrictInt, ...] = Field(min_length=1)
    respects_quarantine: tuple[StrictBool, ...] = (True,)
    salience: Salience = Salience.KEEP_CAPABILITIES
    summary_lines: StrictInt = Field(default=4, ge=1, le=64)
    families: tuple[StrictStr, ...] | None = None
    comparisons: tuple[tuple[StrategyId, StrategyId], ...] = ()
    bootstrap_resamples: StrictInt = Field(default=2000, ge=100, le=100_000)
    bootstrap_seed: StrictInt = 7

    def conditions(self) -> list[Condition]:
        return [
            Condition(s, g, b, q, self.salience, self.summary_lines)
            for s in self.strategies
            for g in self.gateways
            for b in self.budgets
            for q in self.respects_quarantine
        ]

    def config_hash(self) -> str:
        return digest(self.model_dump(mode="json"))
