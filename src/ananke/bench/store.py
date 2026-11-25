"""Scenario files and frozen manifests.

Layout: ``scenarios/{dev,holdout}/<scenario_id>.json`` (canonical JSON) and
``scenarios/manifest.json`` (all checksums). ``scenarios/holdout.manifest.json`` is written
**once** and never overwritten. Regenerating different holdout content is an error (the holdout is
frozen). Runs load scenarios from files and verify checksums. They never regenerate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ananke.bench.generator import FAMILIES, generate
from ananke.bench.scenario import Scenario, Split
from ananke.domain import canonical_bytes, digest

MANIFEST = "manifest.json"
HOLDOUT_FROZEN = "holdout.manifest.json"


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


def write_scenarios(root: Path, variants: int = 4) -> dict[str, Any]:
    dev, holdout = generate(Split.DEV, variants), generate(Split.HOLDOUT, variants)
    frozen_path = root / HOLDOUT_FROZEN
    hold_manifest = _manifest(holdout)
    if frozen_path.exists():
        frozen = json.loads(frozen_path.read_text(encoding="utf-8"))
        if frozen.get("manifest_digest") != hold_manifest["manifest_digest"]:
            raise ScenarioStoreError("holdout is frozen and the generator would change it")
    for split, items in ((Split.DEV, dev), (Split.HOLDOUT, holdout)):
        d = root / split.value
        d.mkdir(parents=True, exist_ok=True)
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
