"""Scenario files and frozen manifests.

Layout: ``scenarios/{dev,holdout}/<scenario_id>.json`` (canonical JSON) and
``scenarios/manifest.json`` (all checksums). ``scenarios/holdout.manifest.json`` is the frozen
holdout manifest. Regenerating different holdout content is an error. The only exception is an
explicit **re-freeze** that carries a written reason (an owner decision). A re-freeze archives the
superseded manifest as ``holdout.manifest.freeze-<n>.json`` and appends an entry to the
append-only ``holdout.freeze-log.json``. Runs load scenarios from files and verify checksums. They
never regenerate.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ananke.bench.generator import (
    FAMILIES,
    GENERATOR_VERSION,
    SPLIT_VARIANTS,
    generate,
    seed_offset,
)
from ananke.bench.scenario import Scenario, Split
from ananke.domain import canonical_bytes, digest

MANIFEST = "manifest.json"
HOLDOUT_FROZEN = "holdout.manifest.json"
FREEZE_LOG = "holdout.freeze-log.json"


class ScenarioStoreError(RuntimeError):
    pass


def _manifest(scenarios: list[Scenario]) -> dict[str, Any]:
    entries = [
        {
            "scenario_id": s.scenario_id,
            "family": s.family,
            "split": s.split.value,
            "template": s.template,
            "variant": s.variant,
            "sha256": s.checksum(),
        }
        for s in sorted(scenarios, key=lambda s: s.scenario_id)
    ]
    return {
        "schema_version": "ananke.scenario-manifest/0",
        "families": list(FAMILIES),
        "count": len(entries),
        "entries": entries,
        "manifest_digest": digest(entries),
    }


def _freeze_entry(
    n: int,
    manifest: dict[str, Any],
    *,
    reason: str,
    generator: str,
    variants: int | None,
    seeds: str,
    superseded: str | None,
) -> dict[str, Any]:
    return {
        "freeze": n,
        "manifest_digest": manifest["manifest_digest"],
        "count": manifest["count"],
        "generator": generator,
        "variants_per_family": variants,
        "seed_space": seeds,
        "reason": reason,
        "superseded_digest": superseded,
        "recorded_at": datetime.now(UTC).strftime("%Y-%m-%d"),
    }


def write_scenarios(
    root: Path, variants: int | None = None, *, refreeze_holdout_reason: str | None = None
) -> dict[str, Any]:
    """Write both splits. The holdout may change only with ``refreeze_holdout_reason``."""
    dev, holdout = generate(Split.DEV, variants), generate(Split.HOLDOUT, variants)
    frozen_path, log_path = root / HOLDOUT_FROZEN, root / FREEZE_LOG
    hold_manifest = _manifest(holdout)
    refrozen = False
    if frozen_path.exists():
        frozen = json.loads(frozen_path.read_text(encoding="utf-8"))
        if frozen.get("manifest_digest") != hold_manifest["manifest_digest"]:
            if not refreeze_holdout_reason or not refreeze_holdout_reason.strip():
                raise ScenarioStoreError("holdout is frozen and the generator would change it")
            log = json.loads(log_path.read_text(encoding="utf-8")) if log_path.exists() else []
            if not log:  # the original freeze predates the log: record it as freeze 1
                log.append(
                    _freeze_entry(
                        1,
                        frozen,
                        reason="initial freeze",
                        generator="v1",
                        variants=None,
                        seeds="offset 10000",
                        superseded=None,
                    )
                    | {"recorded_at": None}
                )
            n = log[-1]["freeze"]
            (root / f"holdout.manifest.freeze-{n}.json").write_bytes(
                frozen_path.read_bytes()
            )  # archive the superseded manifest unchanged
            ver = GENERATOR_VERSION[Split.HOLDOUT]
            log.append(
                _freeze_entry(
                    n + 1,
                    hold_manifest,
                    reason=refreeze_holdout_reason.strip(),
                    generator=f"v{ver}",
                    variants=variants if variants is not None else SPLIT_VARIANTS[Split.HOLDOUT],
                    seeds=f"offset {seed_offset(Split.HOLDOUT, ver)}",
                    superseded=frozen["manifest_digest"],
                )
            )
            log_path.write_text(json.dumps(log, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            frozen_path.write_bytes(canonical_bytes(hold_manifest) + b"\n")
            refrozen = True
    elif refreeze_holdout_reason:
        raise ScenarioStoreError("nothing to re-freeze: no frozen holdout manifest exists")
    for split, items in ((Split.DEV, dev), (Split.HOLDOUT, holdout)):
        d = root / split.value
        d.mkdir(parents=True, exist_ok=True)
        keep = {f"{s.scenario_id}.json" for s in items}
        for stale in d.glob("*.json"):  # files of a superseded generation must not linger
            if stale.name not in keep:
                stale.unlink()
        for s in items:
            (d / f"{s.scenario_id}.json").write_bytes(s.canonical_json() + b"\n")
    manifest = _manifest(dev + holdout)
    (root / MANIFEST).write_bytes(canonical_bytes(manifest) + b"\n")
    if not frozen_path.exists():
        frozen_path.write_bytes(canonical_bytes(hold_manifest) + b"\n")
    return {
        "dev": len(dev),
        "holdout": len(holdout),
        "manifest_digest": manifest["manifest_digest"],
        "holdout_digest": hold_manifest["manifest_digest"],
        "holdout_refrozen": refrozen,
    }


def load_split(root: Path, split: Split) -> list[Scenario]:
    """Load and checksum-verify one split from disk (fail closed on any mismatch)."""
    manifest_path = root / MANIFEST
    if not manifest_path.is_file():
        raise ScenarioStoreError("scenario manifest not found; run `ananke bench generate`")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if digest(manifest["entries"]) != manifest["manifest_digest"]:
        raise ScenarioStoreError("manifest digest mismatch")
    if split is Split.HOLDOUT:
        frozen = json.loads((root / HOLDOUT_FROZEN).read_text(encoding="utf-8"))
        held = [e for e in manifest["entries"] if e["split"] == "holdout"]
        if digest(held) != frozen["manifest_digest"]:
            raise ScenarioStoreError("holdout content differs from the frozen holdout manifest")
    out = []
    for e in manifest["entries"]:
        if e["split"] != split.value:
            continue
        raw = (root / split.value / f"{e['scenario_id']}.json").read_bytes()
        scn = Scenario.model_validate_json(raw)
        if scn.checksum() != e["sha256"] or scn.canonical_json() + b"\n" != raw:
            raise ScenarioStoreError(f"checksum mismatch for {e['scenario_id']}")
        out.append(scn)
    return out
