"""Phase 4: generator, frozen manifests, holdout lock, runner invariants, CLI contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ananke.bench.config import BenchConfig
from ananke.bench.generator import FAMILIES, generate
from ananke.bench.run import HoldoutLockedError, execute
from ananke.bench.runner import Condition, GatewayMode, run_matrix
from ananke.bench.scenario import CheckpointStep, Split
from ananke.bench.store import ScenarioStoreError, load_split, write_scenarios
from ananke.cli import app
from ananke.memory import StrategyId

ROOT = Path(__file__).resolve().parents[2]


def test_generator_is_deterministic_and_balanced() -> None:
    a, b = generate(Split.DEV), generate(Split.DEV)
    assert [s.checksum() for s in a] == [s.checksum() for s in b]
    assert len(a) == 36 and {s.family for s in a} == {f.replace("_", "-") for f in FAMILIES}
    for fam in {s.family for s in a}:
        assert sum(s.family == fam for s in a) == 4


def test_dev_and_holdout_share_no_entities_or_templates() -> None:
    dev, hold = generate(Split.DEV), generate(Split.HOLDOUT)

    def entities(ss: list) -> set[str]:  # type: ignore[type-arg]
        return {r for s in ss for r in s.fixtures} | {s.principal for s in ss}

    assert not entities(dev) & entities(hold)
    assert {s.template for s in dev}.isdisjoint({s.template for s in hold})


def test_every_family_has_eligible_checkpoints() -> None:
    for s in generate(Split.DEV):
        cps = [x for x in s.timeline if isinstance(x, CheckpointStep)]
        assert cps and any(c.eligible for c in cps), s.scenario_id


def test_committed_scenarios_match_generator_and_verify() -> None:
    for split in Split:
        files = {s.scenario_id: s.checksum() for s in load_split(ROOT / "scenarios", split)}
        assert files == {s.scenario_id: s.checksum() for s in generate(split)}


def test_tampered_holdout_file_is_rejected(tmp_path: Path) -> None:
    write_scenarios(tmp_path)
    victim = next((tmp_path / "holdout").glob("*.json"))
    data = json.loads(victim.read_text())
    data["description"] = "tuned"
    victim.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(ScenarioStoreError):
        load_split(tmp_path, Split.HOLDOUT)


def test_frozen_holdout_cannot_be_regenerated_differently(tmp_path: Path) -> None:
    write_scenarios(tmp_path)
    frozen = tmp_path / "holdout.manifest.json"
    frozen.write_text(
        frozen.read_text().replace('"manifest_digest":"sha256:', '"manifest_digest":"sha256:0')
    )
    with pytest.raises(ScenarioStoreError, match="frozen"):
        write_scenarios(tmp_path)


def test_holdout_is_locked_without_frozen_preregistration(tmp_path: Path) -> None:
    cfg = BenchConfig(name="x", split=Split.HOLDOUT, strategies=(StrategyId.M5,), budgets=(900,))
    (tmp_path / "research").mkdir()
    (tmp_path / "research" / "preregistration.md").write_text("Status: DRAFT")
    with pytest.raises(HoldoutLockedError):
        execute(cfg, scenarios_root=ROOT / "scenarios", out_root=tmp_path, repo_root=tmp_path)


@pytest.mark.parametrize(
    ("text", "frozen"),
    [
        ("Status: DRAFT", False),
        ("Status: DRAFT\nRuns are refused until the line reads `Status: FROZEN`.", False),
        ("Intro mentions Status: FROZEN in prose\nStatus: DRAFT", False),
        ("No status line at all", False),
        ("Status: FROZEN  ", True),
        ("Status: FROZEN\nStatus: DRAFT", True),
    ],
)
def test_holdout_unlock_requires_exact_first_status_line(
    tmp_path: Path, text: str, frozen: bool
) -> None:
    from ananke.bench.run import preregistration_frozen

    (tmp_path / "research").mkdir()
    (tmp_path / "research" / "preregistration.md").write_text(text)
    assert preregistration_frozen(tmp_path) is frozen


def test_repository_preregistration_is_not_frozen() -> None:
    from ananke.bench.run import preregistration_frozen

    assert preregistration_frozen(ROOT) is False  # the holdout must stay locked in this phase


def test_enforced_runs_hold_every_invariant_across_all_strategies() -> None:
    """G1 over all dev scenarios x all strategies x two budgets x both agent variants:
    oracle and gateway agree on every proposal, no unauthorized effect, no false denial, and every
    run's evidence replays (the runner audits each ledger)."""
    conds = [
        Condition(s, GatewayMode.G1, b, q)
        for s in StrategyId
        for b in (500, 1800)
        for q in (True, False)
    ]
    recs = list(run_matrix(generate(Split.DEV), conds))
    assert len(recs) == len(conds) * 72  # 72 checkpoints per dev v2 split (64 eligible)
    assert not any(r.oracle_gateway_disagree for r in recs)
    assert not any(r.unauthorized_effect for r in recs)
    assert not any(r.false_denial for r in recs)
    assert any(r.unauthorized_proposal for r in recs)  # non-vacuous: proposals were attempted
    assert any(r.budget_exceeded for r in recs)


def test_unenforced_lab_mode_shows_what_enforcement_prevents() -> None:
    dev = generate(Split.DEV)
    g0 = list(run_matrix(dev, [Condition(StrategyId.M2, GatewayMode.G0, 900)]))
    g1 = list(run_matrix(dev, [Condition(StrategyId.M2, GatewayMode.G1, 900)]))
    assert [r.proposed for r in g0] == [r.proposed for r in g1]  # memory fixed: same proposals
    assert sum(r.unauthorized_effect for r in g0) == sum(r.unauthorized_proposal for r in g0) > 0
    assert sum(r.unauthorized_effect for r in g1) == 0


def test_cli_bench_contract(tmp_path: Path) -> None:
    runner = CliRunner()
    cfg = tmp_path / "c.json"
    cfg.write_text(
        json.dumps(
            {
                "name": "t",
                "split": "dev",
                "strategies": ["M5_PROJECTION"],
                "budgets": [900],
                "families": ["revocation"],
                "bootstrap_resamples": 100,
            }
        )
    )
    r1 = runner.invoke(
        app,
        [
            "bench",
            "run",
            "--config",
            str(cfg),
            "--offline",
            "--scenarios",
            str(ROOT / "scenarios"),
            "--out",
            str(tmp_path),
        ],
    )
    assert r1.exit_code == 0, r1.output
    out = json.loads(r1.output)
    r2 = runner.invoke(
        app,
        [
            "bench",
            "run",
            "--config",
            str(cfg),
            "--offline",
            "--scenarios",
            str(ROOT / "scenarios"),
            "--out",
            str(tmp_path),
        ],
    )
    assert json.loads(r2.output)["metrics_digest"] == out["metrics_digest"]  # reproducible
    rep = runner.invoke(app, ["bench", "report", "--run-dir", out["run_dir"]])
    assert rep.exit_code == 0 and "unauthorized_proposal_rate" in rep.output
    bad = tmp_path / "bad.json"
    bad.write_text('{"name": "x"}')
    assert runner.invoke(app, ["bench", "run", "--config", str(bad)]).exit_code == 1
    locked = runner.invoke(
        app,
        [
            "bench",
            "run",
            "--config",
            str(ROOT / "research/experiments/holdout-locked.json"),
            "--scenarios",
            str(ROOT / "scenarios"),
            "--out",
            str(tmp_path),
        ],
    )
    assert locked.exit_code == 2 and "HOLDOUT_LOCKED" in locked.output
    assert (
        runner.invoke(
            app, ["bench", "verify-scenarios", "--root", str(ROOT / "scenarios")]
        ).exit_code
        == 0
    )


# ----------------------------------------------------------------------------- generator v2


def test_holdout_is_v2_matches_frozen_manifest_and_is_balanced() -> None:
    from ananke.bench.generator import GENERATOR_VERSION, SPLIT_VARIANTS

    assert GENERATOR_VERSION == {Split.DEV: 2, Split.HOLDOUT: 2}
    assert SPLIT_VARIANTS == {Split.DEV: 4, Split.HOLDOUT: 8}
    frozen = json.loads((ROOT / "scenarios" / "holdout.manifest.json").read_text())
    regenerated = {s.scenario_id: s.checksum() for s in generate(Split.HOLDOUT)}
    assert {e["scenario_id"]: e["sha256"] for e in frozen["entries"]} == regenerated
    hold = generate(Split.HOLDOUT)
    assert len(hold) == 72 and all(
        sum(s.family == f for s in hold) == 8 for f in {x.family for x in hold}
    )


def test_freeze_log_and_v1_archive_are_consistent() -> None:
    from ananke.domain import digest

    log = json.loads((ROOT / "scenarios" / "holdout.freeze-log.json").read_text())
    assert [e["freeze"] for e in log] == [1, 2]
    assert log[1]["superseded_digest"] == log[0]["manifest_digest"]
    assert log[1]["generator"] == "v2" and log[1]["seed_space"] == "offset 30000"
    archived = json.loads((ROOT / "scenarios" / "holdout.manifest.freeze-1.json").read_text())
    assert archived["manifest_digest"] == log[0]["manifest_digest"]
    v1 = [
        {
            "scenario_id": s.scenario_id,
            "family": s.family,
            "split": s.split.value,
            "template": s.template,
            "variant": s.variant,
            "sha256": s.checksum(),
        }
        for s in sorted(generate(Split.HOLDOUT, variants=4, version=1), key=lambda s: s.scenario_id)
    ]
    assert digest(v1) == archived["manifest_digest"]  # the retired holdout stays reproducible
    current = json.loads((ROOT / "scenarios" / "holdout.manifest.json").read_text())
    assert current["manifest_digest"] == log[-1]["manifest_digest"]


def _seeds(scenarios: list) -> set[str]:  # type: ignore[type-arg]
    return {s.description.split()[0] for s in scenarios}


def _injected_text(scenarios: list) -> str:  # type: ignore[type-arg]
    return " ".join(
        st.content
        for s in scenarios
        if s.family == "untrusted-claim"
        for st in s.timeline
        if st.kind == "observe"
    )


def test_new_holdout_seeds_and_phrasing_are_disjoint_from_v1_and_dev() -> None:
    new = generate(Split.HOLDOUT)
    old = generate(Split.HOLDOUT, variants=4, version=1)
    assert not _seeds(new) & _seeds(old) and not _seeds(new) & _seeds(generate(Split.DEV))
    assert "Operator says:" in _injected_text(generate(Split.DEV))
    assert "Operator says:" not in _injected_text(new)
    assert "attachment preview" in _injected_text(new)


def test_refreeze_requires_reason_archives_and_logs(tmp_path: Path) -> None:
    import ananke.bench.store as store

    write_scenarios(tmp_path)  # fresh root: first freeze, nothing to log yet
    assert not (tmp_path / "holdout.freeze-log.json").exists()
    original = generate
    try:
        store.generate = lambda split, variants=None: original(  # type: ignore[assignment]
            split, 2 if split is Split.HOLDOUT else variants
        )
        with pytest.raises(ScenarioStoreError, match="frozen"):
            write_scenarios(tmp_path)
        with pytest.raises(ScenarioStoreError, match="frozen"):
            write_scenarios(tmp_path, refreeze_holdout_reason="   ")
        out = write_scenarios(tmp_path, refreeze_holdout_reason="test reason")
        assert out["holdout_refrozen"] is True and out["holdout"] == 18
        assert len(list((tmp_path / "holdout").glob("*.json"))) == 18  # stale files removed
        log = json.loads((tmp_path / "holdout.freeze-log.json").read_text())
        assert [e["reason"] for e in log] == ["initial freeze", "test reason"]
        assert (tmp_path / "holdout.manifest.freeze-1.json").exists()
        assert write_scenarios(tmp_path)["holdout_refrozen"] is False  # now stable again
        assert load_split(tmp_path, Split.HOLDOUT)
    finally:
        store.generate = original  # type: ignore[assignment]


def test_refreeze_without_existing_freeze_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ScenarioStoreError, match="nothing to re-freeze"):
        write_scenarios(tmp_path, refreeze_holdout_reason="x")


def test_unknown_generator_version_rejected() -> None:
    with pytest.raises(ValueError, match="unknown generator version"):
        generate(Split.DEV, version=3)


def test_v2_injection_family_has_twelve_attack_checkpoints_and_four_formats() -> None:
    scns = [s for s in generate(Split.DEV) if s.family == "untrusted-claim"]
    cps = [st for s in scns for st in s.timeline if isinstance(st, CheckpointStep)]
    assert sum(any(o.attack for o in c.options) for c in cps) == 12
    ids = {c.checkpoint_id for c in cps}
    assert ids == {
        "cp-forged-grant",
        "cp-wrong-principal",
        "cp-forged-snapshot",
        "cp-forged-revoke",
    }
    assert all("generator=v2" in s.description for s in scns)


def test_v2_budgets_bind_for_truncation() -> None:
    """Exit criterion (Phase 5 prep): M1 legit completion differs across budget levels."""
    dev = generate(Split.DEV)
    done = {}
    for budget in (450, 1100, 2600):
        recs = list(run_matrix(dev, [Condition(StrategyId.M1, GatewayMode.G1, budget)]))
        done[budget] = sum(r.legit_completed for r in recs)
        assert any(r.dropped_entries for r in recs)  # truncation actually happens
    assert len(set(done.values())) >= 2, done
    assert done[450] < done[2600]


def test_attack_denominator_counts_only_checkpoints_with_an_attack_option() -> None:
    from ananke.bench.metrics import summarize

    recs = list(run_matrix(generate(Split.DEV), [Condition(StrategyId.M2, GatewayMode.G1, 1100)]))
    (m,) = summarize(recs, resamples=100).values()
    assert m["attack_adoption_rate"]["den"] == 12
    assert sum(r.attack_option_present for r in recs) == 12
