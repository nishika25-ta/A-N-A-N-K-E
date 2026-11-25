"""Small, dependency-free statistics with deterministic resampling (MASTERPLAN section 11).

* :func:`cluster_bootstrap_ratio`: percentile CI for sum(num)/sum(den), resampling *scenarios*
  (clusters) with replacement. Repeated checkpoints within a scenario are not independent.
* :func:`paired_cluster_bootstrap_diff`: CI for rate(A) - rate(B) on the same clusters.
* :func:`mcnemar_exact`: two-sided exact McNemar test on discordant pair counts.
* :func:`wilson`: Wilson score interval (unclustered; secondary).

These are standard methods implemented from their definitions and unit-tested on known values.
Small samples give wide intervals; never read significance into an underpowered pilot.
"""

from __future__ import annotations

import math
import random
from collections.abc import Sequence


def _percentile(sorted_xs: Sequence[float], q: float) -> float:
    if not sorted_xs:
        return float("nan")
    pos = q * (len(sorted_xs) - 1)
    lo, hi = math.floor(pos), math.ceil(pos)
    return sorted_xs[lo] + (sorted_xs[hi] - sorted_xs[lo]) * (pos - lo)


def cluster_bootstrap_ratio(
    clusters: Sequence[tuple[int, int]],
    *,
    resamples: int = 2000,
    seed: int = 7,
    alpha: float = 0.05,
) -> tuple[float, float, float]:
    """Return (point, lo, hi) for sum(num)/sum(den) over clusters of (num, den)."""
    num = sum(c[0] for c in clusters)
    den = sum(c[1] for c in clusters)
    point = num / den if den else float("nan")
    if not clusters or den == 0:
        return point, float("nan"), float("nan")
    rng = random.Random(seed)  # noqa: S311 - seeded, reproducible resampling (not security)
    k = len(clusters)
    stats = []
    for _ in range(resamples):
        sample = [clusters[rng.randrange(k)] for _ in range(k)]
        d = sum(s[1] for s in sample)
        if d:
            stats.append(sum(s[0] for s in sample) / d)
    stats.sort()
    return point, _percentile(stats, alpha / 2), _percentile(stats, 1 - alpha / 2)


def paired_cluster_bootstrap_diff(
    clusters: Sequence[tuple[int, int, int]],
    *,
    resamples: int = 2000,
    seed: int = 7,
    alpha: float = 0.05,
) -> tuple[float, float, float]:
    """Clusters of (num_a, num_b, den) -> (point, lo, hi) for (sum a - sum b) / sum den."""
    den = sum(c[2] for c in clusters)
    if not clusters or den == 0:
        return float("nan"), float("nan"), float("nan")
    point = (sum(c[0] for c in clusters) - sum(c[1] for c in clusters)) / den
    rng = random.Random(seed)  # noqa: S311 - seeded, reproducible resampling (not security)
    k = len(clusters)
    stats = []
    for _ in range(resamples):
        sample = [clusters[rng.randrange(k)] for _ in range(k)]
        d = sum(s[2] for s in sample)
        if d:
            stats.append((sum(s[0] for s in sample) - sum(s[1] for s in sample)) / d)
    stats.sort()
    return point, _percentile(stats, alpha / 2), _percentile(stats, 1 - alpha / 2)


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact p-value: b = A-only events, c = B-only events (binomial, p=0.5)."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (1 << n)
    return min(1.0, 2 * tail)


def wilson(successes: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n == 0:
        return float("nan"), float("nan")
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)
