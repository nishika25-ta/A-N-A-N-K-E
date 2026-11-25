"""Render a markdown report from a run's metrics.json (no hand-typed numbers).

Run: uv run python research/experiments/render_report.py results/sample-dev-pilot/metrics.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def fmt(e: dict) -> str:  # type: ignore[type-arg]
    ci = e["ci95"]
    w = e["wilson95"]
    rate = "n/a" if e["rate"] is None else f"{e['rate']:.3f}"
    if e["num"] == 0 and e["den"]:
        return f"{e['num']}/{e['den']} ({rate}; Wilson ≤{w[1]:.3f})"
    if ci[0] is None:
        return f"{e['num']}/{e['den']}"
    return f"{e['num']}/{e['den']} ({rate} [{ci[0]:.3f}, {ci[1]:.3f}])"


def main(path: str) -> str:
    m = json.loads(Path(path).read_text(encoding="utf-8"))
    out = [
        f"# Pilot report: {m['run_id']} (split: {m['split']})",
        "",
        f"> {m['scope']}",
        "",
        f"Token estimator: {m['token_estimator']}.",
        "",
        "Rates are num/den (point [cluster-bootstrap 95% CI by scenario]). For zero counts the "
        "Wilson upper bound is shown, because the bootstrap interval degenerates.",
        "",
    ]
    for gw in ("G1_ENFORCED", "G0_UNENFORCED_LAB_ONLY"):
        out += [
            f"## Gateway {gw}",
            "",
            "| strategy | budget | respects quarantine | unauthorized proposals (primary) | "
            "unauthorized effects | stale (post-transition) | attack adoption | "
            "legit completion | budget exceeded | oracle≠gateway | mean ctx tokens |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        rows = [v for v in m["conditions"].values() if v["factors"]["gateway"] == gw]
        rows.sort(
            key=lambda v: (
                v["factors"]["strategy"],
                v["factors"]["budget"],
                not v["factors"]["respects_quarantine"],
            )
        )
        for v in rows:
            f = v["factors"]
            out.append(
                f"| {f['strategy']} | {f['budget']} | {f['respects_quarantine']} | "
                f"{fmt(v['unauthorized_proposal_rate'])} | {fmt(v['unauthorized_effect_rate'])} | "
                f"{fmt(v['stale_proposal_rate_post_transition'])} | "
                f"{fmt(v['attack_adoption_rate'])} | {fmt(v['legit_completion_rate'])} | "
                f"{fmt(v['budget_exceeded_rate'])} | "
                f"{v['oracle_gateway_disagreement_rate']['num']} | "
                f"{v['mean_context_tokens_est']} |"
            )
        out.append("")
    out += [
        "## Paired comparisons (primary endpoint, eligible checkpoints)",
        "",
        "| A | B | gateway | budget | quarantine | pairs | A-only | B-only | "
        "diff A-B [95% CI] | exact McNemar p |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for c in m["comparisons"]:
        out.append(
            f"| {c['a']} | {c['b']} | {c['gateway']} | {c['budget']} | "
            f"{c['respects_quarantine']} | {c['pairs']} | {c['a_only']} | {c['b_only']} | "
            f"{c['rate_diff_a_minus_b']} {c['ci95']} | {c['mcnemar_exact_p']} |"
        )
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    sys.stdout.write(main(sys.argv[1]))
