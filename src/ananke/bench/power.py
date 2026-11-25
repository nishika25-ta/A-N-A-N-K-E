"""Cluster-resampling power estimate for the primary paired comparison (exact McNemar).

From a pilot's checkpoint records: for strategy A vs B at one matched factor level, take each
scenario's paired outcomes on eligible checkpoints. For a candidate number of scenarios S, draw S
scenarios with replacement, count the discordant pairs (A-only, B-only), and test with the exact
McNemar test at ``alpha``. The estimated power is the fraction of simulations that reject.

Caveat that must accompany every number: the estimate assumes the pilot's distribution of
per-scenario discordance carries over to the confirmatory population. For a deterministic
scripted agent, discordance is structural (it comes from specific families), so the estimate is
about the benchmark's *design*, not about LLM behaviour. A real-model arm needs its own pilot.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Any

from ananke.bench.runner import CheckpointRecord
from ananke.bench.stats import mcnemar_exact


def paired_clusters(
    records: Iterable[CheckpointRecord],
    a: str,
    b: str,
    *,
    gateway: str,
    budget: int,
    respects_quarantine: bool,
) -> list[tuple[int, int]]:
    """Per scenario: (A-only unauthorized count, B-only unauthorized count) on eligible pairs."""
    cell: dict[str, dict[tuple[str, str], CheckpointRecord]] = defaultdict(dict)
    for r in records:
        if (
            r.eligible
            and r.strategy in (a, b)
            and r.gateway == gateway
            and r.budget == budget
            and r.respects_quarantine == respects_quarantine
        ):
            cell[r.strategy][(r.scenario_id, r.checkpoint_id)] = r
    keys = sorted(set(cell[a]) & set(cell[b]))
    per: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for k in keys:
        ua, ub = cell[a][k].unauthorized_proposal, cell[b][k].unauthorized_proposal
        per[k[0]][0] += int(ua and not ub)
        per[k[0]][1] += int(ub and not ua)
    return [(v[0], v[1]) for _, v in sorted(per.items())]


def simulate_power(
    clusters: Sequence[tuple[int, int]],
    scenario_counts: Sequence[int],
    *,
    sims: int = 2000,
    seed: int = 11,
    alpha: float = 0.05,
) -> list[dict[str, Any]]:
    if not clusters:
        return [{"scenarios": s, "power": None, "sims": 0} for s in scenario_counts]
    rng = random.Random(seed)  # noqa: S311 - seeded, reproducible simulation (not security)
    out = []
    for s in scenario_counts:
        rejections = 0
        for _ in range(sims):
            b = c = 0
            for _ in range(s):
                x, y = clusters[rng.randrange(len(clusters))]
                b += x
                c += y
            rejections += mcnemar_exact(b, c) < alpha
        out.append({"scenarios": s, "power": round(rejections / sims, 4), "sims": sims})
    return out
