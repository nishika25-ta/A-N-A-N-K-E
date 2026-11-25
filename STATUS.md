# STATUS

**Last updated:** 2026-11-25 (session 3) · **Engineering gates complete:** Phases 0, 1, 2, 3, 4.
**Owner decisions pending:** ADR-0007 (positioning), ADR-0010 (operator signatures: a threat-model change), license,
the real-model arm (cost), commit/push approval.
**Scientific results:** none. There is a **dev-split engineering pilot** with a deterministic belief agent
(`research/pilot-dev-report.md`). The holdout is locked, and a preregistration is not frozen.

## Gate summary

| Phase | Exit criteria | State |
|---|---|---|
| 0 | Prior art, threat model, spec, ADRs, prereg draft, skeleton | Done (secondary sources only; primary texts unreachable) |
| 1 | Schemas, ledger, reducer, migrations, tamper detection, CLI | Done |
| 2 | Evaluator, single-transaction gateway, approvals, idempotency, tools, differential test | Done |
| 3 | Memory entries + conservative labels; token estimator; budgeted assembler (`BUDGET_EXCEEDED`, never truncate policy); M0–M5 + 3 ablations; projection; belief agent; recall harness | **Done (session 3)** |
| 4 | Scenario DSL; ≥30 dev + ≥30 holdout fixtures by family with a frozen checksummed manifest; independent oracle; runner (G0/G1); metrics with num/den + clustered CIs; deterministic runs; bench CLI | **Done (session 3)**: 36 + 36 fixtures; "dry-run budget" is N/A until a paid provider exists |
| 5 | Strong comparator, pilot, preregistration freeze, optional model runs | **Not started.** The pilot exists, but freezing needs owner decisions and the design fixes listed below |

## Session 3 work

1. **Code review** (`/code-review high src/ananke`) found 7 issues. All are fixed, each pinned by a regression test in
   `tests/integration/test_review_fixes.py`:
   - URI-unsafe characters in ledger paths opened the wrong file. Fixed by a percent-encoded URI and exclusive (`O_EXCL`) creation.
   - Dropped or replaced triggers went unnoticed by a live gateway. Fixed by a **schema fingerprint checked in every decision
     transaction**.
   - Forged approvals passed verification. Approvals are now an **insert-only hash chain** with a separate
     single-use consumption table, and there is a new **evidence audit**.
   - CLI tracebacks are now structured JSON errors with the documented exit codes.
   - I/O failures are now `LEDGER_UNAVAILABLE` instead of `INTERNAL_ERROR`.
   - `approval_id` is recorded only when the approval was actually evaluated.
   - A failed init now cleans up after itself.
2. **The security-review skill could not run.** It needs a git base ref and nothing is committed. Instead, a manual pass
   covered SQL parameterization, identity binding, fail-open paths, cache rewrites and disclosure in errors. It found nothing new.
3. **`audit/`, a new package:** it replays every policy-derived decision with the evaluator at its own epoch and tick, and
   cross-links effects, approval consumptions and idempotency rows in both directions. It runs inside `ledger verify`, inside
   the differential property test, and after **every** enforced benchmark run.
4. **Phase 3**: `memory/` (entries, labels, grammar, projection, summarizer, assembler, strategies) and
   `providers/belief.py` (an independent grammar parser; may not import `memory`).
5. **Phase 4**: `bench/` (scenario, generator, oracle, runner, stats, metrics, config, store, run), the CLI
   `bench generate|verify-scenarios|run|report`, `scenarios/` (72 files + manifests), `research/experiments/*.json`, and
   `research/experiments/render_report.py`.
6. **Design:** a read-only Studio preview built from the real pilot and demo data:
   https://claude.ai/artifact/8eWLFyMnx4PctdNGToMvUa (private).
7. **Docs:** architecture rewritten; policy-spec sections 8 to 10; threat model A8 to A11 and SI-8; ADR-0010 (proposed) and
   ADR-0011; preregistration draft with the changes the pilot requires; README.

### Incident: holdout guard bug (found and fixed this session)
`preregistration_frozen()` tested whether the file *contained* `Status: FROZEN`. The new prereg draft mentions that phrase in
prose, so during one `make check` the CLI contract test **executed the holdout config into a pytest temp directory**. Those
outputs were **deleted without being read**, and nothing in `results/` comes from the holdout. The fix requires the *first*
`Status:` line to equal `Status: FROZEN` exactly. Eight tests pin this, including one asserting that the repository's
prereg is not frozen. Recommendation: regenerate the holdout (new seeds) before freezing, for full confidence.

## Commands actually executed (this container)

Environment: Linux x86_64, Python 3.13.18 via uv 0.11.32, SQLite 3.53.1, Node 22 (used only to syntax-check page scripts).

| Command | Actual result |
|---|---|
| `make check` (with `pipefail`) | **exit 0** |
| ↳ ruff check / ruff format --check | `All checks passed!` / `81 files already formatted` |
| ↳ `uv run mypy` (strict) | `Success: no issues found in 48 source files` |
| ↳ `uv run pytest` | **`581 passed in 82.34s`** |
| ↳ selfcheck, demo-gateway | `pass`; `all_outcomes_as_expected: true` |
| ↳ `bench verify-scenarios` | dev 36, holdout 36 verified against the manifest and the frozen holdout manifest |
| ↳ `bench run --config research/experiments/smoke.json` | `status: completed`; metrics digest reproducible (tested) |
| `bench run --config research/experiments/pilot-dev.json` | 6,480 records, 108 conditions, about 2 min 20 s; `run-726411f5f841` |
| Pilot re-run after all later session-3 changes, into a fresh output dir | metrics digest `sha256:57d2e5c3…146fbb` **identical** to the saved sample |
| `bench run` holdout config (CLI) | exit 2, `HOLDOUT_LOCKED` |
| `gateway_latency.py --rules 1000 --requests 1000` (with per-transaction schema fingerprint) | p50 0.90 ms, p95 1.35 ms, p99 2.74 ms (a second run: p95 1.33 ms) |

### Coverage highlights (581 tests)
- Differential: the gateway matches the independent reference model over 150 random programs, and every program's evidence
  replays cleanly through the audit.
- Benchmark invariants: G1 over all dev scenarios × 9 strategies × 2 budgets × 2 agent variants (2,160 records) has
  0 oracle–gateway disagreements, 0 unauthorized effects and 0 false denials. G0 vs G1 with memory fixed gives identical proposals,
  and unauthorized effects equal unauthorized proposals only in G0.
- Memory properties: never over budget; the policy section is never truncated or reordered; summaries never promote labels or
  invent lines; label derivation is monotone.
- Strategy behaviour under declared mechanisms: stale proposals from M2/M3, fresh M4/M5, forged-grant adoption except
  under quarantine, the quarantine sensitivity variant, and M4 `BUDGET_EXCEEDED` where M5 fits.
- Review-fix regressions, oracle unit tests, statistics against known values (exact McNemar, Wilson), and the holdout lock.

## Limitations and open issues
1. **The primary literature is still unread** (arXiv and IETF are unreachable from this environment). Owner action: allow the hosts or supply the PDFs.
2. **No authenticity without signatures.** A consistent forgery under a registered operator passes the verifier and the audit (tested).
   ADR-0010 proposes Ed25519 operator keys. This is a threat-model change, so it needs the owner.
3. **The pilot has design flaws:** the budgets do not bind, the injection family is small (n = 4), and the sample size is unestimated. All must be fixed on dev before freezing.
4. **The agent model is an assumption** (ADR-0011): results show what contexts make knowable. The provenance benefit is
   conditional on the agent honouring quarantine.
5. The oracle, the reference model and the evaluator share an author, so an independent review is required.
6. **The Studio preview has not yet been judged in a live view**: no page-check report exists because nobody has opened it.
   Its calcs were verified offline in Node against the uploaded CSVs. It is private until shared from its Share menu.
7. The CI workflow was never executed (nothing pushed). Windows is untested. The license is unselected.
   **All work is uncommitted, and this container is ephemeral.**

## Next task (Phase 5 prep; dev split only, no owner decision needed)
1. Recalibrate the budgets so they bind (longer filler or lower budgets). Exit criterion: on dev, M1 completion varies across ≥2 budget levels.
2. Expand the untrusted-claim family to ≥12 checkpoints, with varied forgery formats (wrong epoch, wrong principal, prose claims).
3. Add a power estimate from pilot variance to the preregistration draft.
4. Then **stop for the owner**: ADR-0007, ADR-0010, holdout regeneration, the real-model arm and its budget, and the freeze.
