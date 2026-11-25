# ANANKE: context-integrity research prototype

> Memory may change. Principles remain.

**Status: Phases 0 to 4 are implemented and tested** (prior art, specs, ledger, reference monitor, memory strategies,
benchmark harness). There is a **dev-split engineering pilot** with a deterministic belief agent. **There are no LLM results
and no holdout results.** See [`STATUS.md`](STATUS.md) for exactly what was built and run.

ANANKE is a local-first, offline research instrument for studying **security continuity across repeated context
compaction in tool-using AI agents**. It keeps three planes separate and audits their evidence:

1. **Memory and recall**: what the model sees (summaries, a policy projection). Lossy, untrusted, advisory.
2. **Authority**: an append-only, hash-chained policy ledger plus chained approvals, written only by a registered operator channel.
3. **Enforcement**: a reference monitor that decides each exact typed action against the latest committed policy inside one
   SQLite transaction.
4. **Audit**: replays every recorded decision against the ledger and links every effect and approval to its justification.

The model and its summaries never grant privileges. Enforcement succeeding is a different finding from compaction improving,
and the benchmark reports them separately (G0 vs G1 with memory held fixed).

Prior art covers every component individually; see [`research/related-work.md`](research/related-work.md). The proposed
contribution is a controlled policy-transition × compaction benchmark (ADR-0007, pending owner review).
"ANANKE" is a research codename. Other products already use the name, and no affiliation is claimed.

## Quickstart (offline, no network, no model calls)

```bash
uv sync --locked
make check            # lint, format, mypy --strict, pytest, selfcheck, demo, scenario checksums, bench smoke
uv run ananke demo-gateway --offline --seed 42
uv run ananke bench run --config research/experiments/pilot-dev.json --offline
uv run ananke bench report --run-dir results/runs/<run_id>
```

Operator-side ledger tools:

```bash
uv run ananke ledger init   --db .ananke/demo.sqlite --operator op-admin
uv run ananke policy validate examples/policy.json
uv run ananke ledger apply  --db .ananke/demo.sqlite --operator op-admin --changes examples/policy.json --at 0
uv run ananke ledger verify --db .ananke/demo.sqlite   # chains + full evidence audit by replay
uv run ananke ledger show   --db .ananke/demo.sqlite --at 12
```

Every command prints JSON and exits 0 on success, 1 on a failed validation, verification or audit, and 2 when input is
unavailable or a run is locked (for example a holdout run before preregistration is frozen).

## What the dev pilot shows (scripted agent; not LLM evidence)

- Under enforcement, there were 0 unauthorized effects and 0 oracle–gateway disagreements across all 54 enforced conditions. With
  enforcement off (lab only), unauthorized effects equal unauthorized proposals.
- Fresh policy rendering (M4 and M5) removes stale-authority proposals that summary-only and pinned-policy strategies make.
- M5 vs M4 differs only through provenance quarantine, and that benefit disappears for an agent that ignores quarantine.
- The pilot also exposed design flaws (budgets that do not bind, a small injection family) that must be fixed before freezing.
  Details are in [`research/pilot-dev-report.md`](research/pilot-dev-report.md).

## Scope and safety

- Synthetic local mock tools only (6 operations). No real endpoints, credentials, personal data, shell or network. The
  test suite blocks sockets.
- This is a research prototype, not a certified security product. Read [`docs/threat-model.md`](docs/threat-model.md), especially
  its known limitations: tamper evidence without authenticity (ADR-0010 proposes signatures), undetected tail truncation,
  and a conditional provenance benefit.

## Documents

- [`docs/architecture.md`](docs/architecture.md): planes, module rules, linearization, schema, benchmark pipeline, latency
- [`docs/policy-spec.md`](docs/policy-spec.md): normative semantics, grammar, audit; [`docs/threat-model.md`](docs/threat-model.md)
- [`docs/decisions/`](docs/decisions/): ADRs 0001–0011
- [`research/`](research/): related work (35 entries), preregistration draft, pilot report, limitations

## License

Not yet selected. Apache-2.0 is proposed, pending owner review.
