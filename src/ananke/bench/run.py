"""Execute a benchmark config into a self-describing run directory.

``results/runs/<run_id>/``: ``manifest.json`` (config, config hash, scenario checksums, code
version, environment), ``checkpoints.jsonl`` (one record per checkpoint per condition) and
``metrics.json`` (endpoints with num/den/CI, paired comparisons). ``run_id`` is derived from the
config hash, scenario manifest digest and code version, so the same inputs give the same run id and
byte-identical metrics. Completion is reported separately from whether results are favourable.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

from ananke import __version__
from ananke.bench.config import BenchConfig
from ananke.bench.metrics import compare, summarize
from ananke.bench.runner import run_matrix
from ananke.bench.scenario import Split
from ananke.bench.store import load_split
from ananke.domain import canonical_bytes, digest
from ananke.memory import ESTIMATOR_LABEL

SCOPE = (
    "Offline engineering benchmark with a deterministic belief agent and a declared scripted "
    "summarizer (ADR-0011). It measures what each context makes knowable and what enforcement "
    "prevents. It is NOT evidence about LLM behaviour."
)


def stable_json(value: Any) -> bytes:
    """Deterministic JSON for *results* (floats allowed, NaN/Inf forbidden). This is not the
    authority canonicalization: results are evidence about runs, never authority."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=False
    ).encode("utf-8")


def stable_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(stable_json(value)).hexdigest()


class HoldoutLockedError(RuntimeError):
    """Holdout runs require a FROZEN preregistration (MASTERPLAN section 3)."""


def preregistration_frozen(repo_root: Path) -> bool:
    """True only if the *first* ``Status:`` line of the preregistration is exactly
    ``Status: FROZEN``. Prose that merely mentions the phrase never unlocks the holdout."""
    prereg = repo_root / "research" / "preregistration.md"
    if not prereg.is_file():
        return False
    for line in prereg.read_text(encoding="utf-8").splitlines():
        if line.startswith("Status:"):
            return line.strip() == "Status: FROZEN"
    return False


def execute(
    config: BenchConfig, *, scenarios_root: Path, out_root: Path, repo_root: Path
) -> dict[str, Any]:
    if config.split is Split.HOLDOUT and not preregistration_frozen(repo_root):
        raise HoldoutLockedError("holdout is locked until research/preregistration.md is FROZEN")
    scenarios = load_split(scenarios_root, config.split)
    if config.families:
        scenarios = [s for s in scenarios if s.family in config.families]
    checksums = {s.scenario_id: s.checksum() for s in scenarios}
    identity = {
        "config_hash": config.config_hash(),
        "scenarios": digest(checksums),
        "code_version": __version__,
    }
    run_id = "run-" + digest(identity)[7:19]
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    records = list(run_matrix(scenarios, config.conditions()))
    with (run_dir / "checkpoints.jsonl").open("wb") as fh:
        for r in records:
            fh.write(canonical_bytes(r.as_dict()) + b"\n")
    metrics = {
        "run_id": run_id,
        "scope": SCOPE,
        "split": config.split.value,
        "token_estimator": ESTIMATOR_LABEL,
        "conditions": summarize(
            records, resamples=config.bootstrap_resamples, seed=config.bootstrap_seed
        ),
        "comparisons": [
            row
            for a, b in config.comparisons
            for row in compare(
                records,
                a.value,
                b.value,
                resamples=config.bootstrap_resamples,
                seed=config.bootstrap_seed,
            )
        ],
    }
    (run_dir / "metrics.json").write_bytes(stable_json(metrics) + b"\n")
    manifest = {
        "run_id": run_id,
        **identity,
        "config": config.model_dump(mode="json"),
        "scenario_checksums": checksums,
        "records": len(records),
        "conditions": len(config.conditions()),
        "git_commit": "uncommitted",
        "environment": {"python": sys.version.split()[0], "platform": platform.platform()},
        "metrics_digest": stable_digest(metrics),
        "status": "completed",
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "records": len(records),
        "metrics_digest": manifest["metrics_digest"],
        "status": "completed",
    }
