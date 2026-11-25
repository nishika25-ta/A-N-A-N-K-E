from ananke.bench.power import simulate_power


def test_no_discordance_has_no_power() -> None:
    (r,) = simulate_power([(0, 0)] * 20, [50], sims=200)
    assert r["power"] == 0.0


def test_one_sided_discordance_has_high_power_with_enough_clusters() -> None:
    clusters = [(0, 1)] * 10 + [(0, 0)] * 10  # half the scenarios contribute a B-only pair
    small, large = simulate_power(clusters, [6, 60], sims=400, seed=3)
    assert small["power"] < large["power"]
    assert large["power"] > 0.95


def test_balanced_discordance_stays_near_alpha() -> None:
    (r,) = simulate_power([(1, 0), (0, 1)] * 10, [60], sims=400, seed=5)
    assert r["power"] < 0.1


def test_deterministic_and_empty() -> None:
    assert simulate_power([(0, 1), (0, 0)], [20], seed=1) == simulate_power(
        [(0, 1), (0, 0)], [20], seed=1
    )
    assert simulate_power([], [10])[0]["power"] is None
