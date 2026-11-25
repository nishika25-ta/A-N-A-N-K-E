import math

import pytest

from ananke.bench.stats import (
    cluster_bootstrap_ratio,
    mcnemar_exact,
    paired_cluster_bootstrap_diff,
    wilson,
)


@pytest.mark.parametrize(
    ("b", "c", "p"),
    [(0, 0, 1.0), (0, 4, 0.125), (4, 0, 0.125), (5, 5, 1.0), (0, 10, 2 / 1024), (1, 9, 22 / 1024)],
)
def test_mcnemar_exact_known_values(b: int, c: int, p: float) -> None:
    assert mcnemar_exact(b, c) == pytest.approx(p)


def test_wilson_known_values() -> None:
    lo, hi = wilson(0, 52)
    assert lo == 0.0 and hi == pytest.approx(0.0688, abs=1e-3)
    lo, hi = wilson(26, 52)
    assert lo == pytest.approx(0.3688, abs=1e-3) and hi == pytest.approx(0.6312, abs=1e-3)
    assert all(math.isnan(x) for x in wilson(0, 0))


def test_bootstrap_is_deterministic_and_brackets_point() -> None:
    clusters = [(1, 2), (0, 1), (2, 3), (0, 2), (1, 1)]
    a = cluster_bootstrap_ratio(clusters, resamples=500, seed=3)
    b = cluster_bootstrap_ratio(clusters, resamples=500, seed=3)
    assert a == b and a[1] <= a[0] <= a[2]
    assert a[0] == pytest.approx(4 / 9)


def test_bootstrap_degenerate_cases() -> None:
    assert cluster_bootstrap_ratio([(0, 5), (0, 3)]) == (0.0, 0.0, 0.0)
    point, lo, _hi = cluster_bootstrap_ratio([])
    assert math.isnan(point) and math.isnan(lo)


def test_paired_diff() -> None:
    point, lo, hi = paired_cluster_bootstrap_diff([(1, 0, 2), (0, 0, 1), (2, 1, 3)], seed=1)
    assert point == pytest.approx((3 - 1) / 6)
    assert lo <= point <= hi
