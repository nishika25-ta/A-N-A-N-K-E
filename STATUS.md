# STATUS

**Last updated:** 2026-11-25 (session 5) · **Engineering gates complete:** Phases 0, 1, 2, 3, 4, plus the Phase 5 prep that needs no owner decision.
**Owner decisions:** ADR-0007 **accepted** (session 6). Pending: ADR-0010 (operator signatures: a threat-model change), license,
the real-model arm (cost), commit/push approval.
**Scientific results:** none. There is a **dev-split engineering pilot v2** with a deterministic belief agent
(`research/pilot-dev-report.md`). The holdout is **regenerated at generator v2 (72 scenarios) and locked**, and a preregistration is not frozen.

## Gate summary

| Phase | Exit criteria | State |
|---|---|---|
| 0 | Prior art, threat model, spec, ADRs, prereg draft, skeleton | Done (secondary sources only; primary texts unreachable) |
| 1 | Schemas, ledger, reducer, migrations, tamper detection, CLI | Done |
| 2 | Evaluator, single-transaction gateway, approvals, idempotency, tools, differential test | Done |
| 3 | Memory entries + conservative labels; token estimator; budgeted assembler (`BUDGET_EXCEEDED`, never truncate policy); M0–M5 + 3 ablations; projection; belief agent; recall harness | **Done (session 3)** |
| 4 | Scenario DSL; ≥30 dev + ≥30 holdout fixtures by family with a frozen checksummed manifest; independent oracle; runner (G0/G1); metrics with num/den + clustered CIs; deterministic runs; bench CLI | **Done (session 3)**: 36 + 36 fixtures; "dry-run budget" is N/A until a paid provider exists |
| 5 | Strong comparator, pilot, preregistration freeze, optional model runs | **Prep done (session 4):** budgets bind, injection family ×3, power estimate, v2 pilot. **Freeze blocked on owner decisions** |

## Session 6: ADR-0007 accepted (owner decision)

- The ADR status is now Accepted, and the ADR index, related-work section 4 and README are updated. MASTERPLAN.md is unchanged.
- The preregistration draft now states RQ1 to RQ3 concretely under the accepted framing (it remains `Status: DRAFT`).

## Session 5 work: holdout regenerated at v2 (owner decision)

- `GENERATOR_VERSION = {dev: 2, holdout: 2}`, `SPLIT_VARIANTS = {dev: 4, holdout: 8}`. The holdout uses a new seed space (offset 30,000)
  and holdout-only injection phrasing.
- `ananke bench generate --refreeze-holdout "<reason>"` is the only way to change a frozen holdout. Plain `generate` still refuses
  (verified: exit 1, `HOLDOUT_FROZEN`). The re-freeze archived v1 as `holdout.manifest.freeze-1.json` and logged freeze 2
  (`sha256:762d81f1…`, 72 scenarios). Stale holdout files are removed.
- Verified: **dev v2 is byte-identical (0 dev files changed)**, the retired v1 holdout is still reproducible, seeds are disjoint from v1 and dev,
  and `bench verify-scenarios` passes (dev 36, holdout 72). Holdout runs are still `HOLDOUT_LOCKED`. **Nothing was run on the new holdout.**
- Tests: the frozen-manifest match and balance, freeze-log/archive consistency, disjoint seeds and phrasing, re-freeze requires a
  non-blank reason, removal of stale files, and re-freeze without an existing freeze refused.
- `make check` (with `pipefail`): **exit 0**, `599 passed`, mypy clean on 49 files, scenarios verified (dev 36 / holdout 72).

## Session 4 work (dev split only; all exit criteria met)

1. **Generator versioning (ADR-0012):** `GENERATOR_VERSION = {dev: 2, holdout: 1}`. The holdout regenerates byte-identically to its
   frozen manifest (tested), and 0 holdout files changed.
2. **The budgets now bind:** v2 filler gives a median M0 history of about 1,030 estimated tokens (mean about 1,180). The pilot budgets are
   450, 1,100 and 2,600. Exit criterion met and tested: M1 completion is 12, 27 and 32 out of 44.
3. **Injection family:** 4 formats (high-epoch grant, wrong-principal control, forged complete snapshot, forged revoke
   with prose) give 12 attack checkpoints per condition. The attack-adoption denominator is now checkpoints with an attack option.
4. **Power:** `ananke bench power` (cluster-resampling exact McNemar). For M5 vs M4 at 1,100 with a quarantine-respecting
   agent: 0.774 at 36 scenarios and 0.990 at 72. For an agent ignoring quarantine there is no discordance, so the power is 0.
5. **v2 pilot** `run-d11292703954` (7,776 records). G1: 0 unauthorized effects; G0: 544. M5 vs M4: 0 vs 8 of 64,
   p = 0.0078. **All 8 are forged-grant adoptions, and the gap disappears for an agent that ignores quarantine.** Stale authority:
   M4 and M5 0/20, M2 and M3 12/20. Reported: the negative warnings ablation, and budget eviction as an accidental defence.
6. **Report and docs:** `research/pilot-dev-report.md` (v2; every cited number was checked against `metrics.json`, which
   caught and fixed one median/mean slip); v1 is archived as `pilot-dev-report-v1.md`; the preregistration's power item and H1b are updated;
   README is updated.
7. **Studio preview refreshed** with the v2 datasets and copy (reference budget 1,100). Its calcs were verified offline in Node against the uploaded CSVs. It
   **still has no live page-check report**, because nobody has opened it.

### Session 4 commands (this container)
| Command | Actual result |
|---|---|
| `make check` (with `pipefail`) | exit 0: ruff clean, `84 files already formatted`, mypy `no issues found in 49 source files`, **`595 passed`**, demo ok, scenarios verified, smoke completed |
| `bench generate` | dev 36 regenerated (v2); holdout digest unchanged `sha256:d82df74…` |
| `bench run --config research/experiments/pilot-dev.json` | 7,776 records in 2 min 31 s, `run-d11292703954` |
| `bench power` (2 configurations) | as above; saved in `results/sample-dev-pilot-v2/` |

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

## Next task: blocked on the owner (no further dev-only work is needed for a freeze)
1. ~~ADR-0007 (positioning)~~ **Accepted in session 6.** ADR-0010 (signatures, a threat-model change) is still pending.
2. ~~Regenerate the holdout at generator v2~~ **Done in session 5** (72 scenarios, new seeds, logged re-freeze).
3. The real-model arm: models, temperatures, repeats and a cost cap (it must have its own pilot).
4. An independent review of the oracle, the reference model and the generator.
5. Then freeze `research/preregistration.md` (`Status: FROZEN`) and tag the commit.

Optional dev-only work meanwhile: extra agent variants (e.g. one that can be swayed by prose), and a summarizer `recency` profile run.
