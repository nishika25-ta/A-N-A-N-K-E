# ANANKE threat model, v0.1

**Scope:** offline synthetic laboratory (Phases 1 to 6). Live and adapter modes need their own review
(Phase 8). Each row states whether it is **implemented and tested** and gives the test location.
Rows marked "planned" are not built yet.

## 1. Assets

1. **Integrity of authoritative policy state:** ledger events, epochs and rule status.
2. **Integrity of protected mock effects:** lab-state mutations and disclosures happen only when authorized.
3. **Approval integrity:** single use, exact-action binding, epoch freshness, expiry.
4. **Evidence integrity:** decision and policy records are tamper-evident, within the limits in section 6.
5. **Benchmark validity:** the oracle is independent of the evaluator, the holdout stays frozen, and no metric is fabricated.

## 2. Trust boundaries

```
 TRUSTED (TCB)                                  | UNTRUSTED
 OperatorChannel (registered operator identity) | agent / model code (providers/*)
 ledger db + reducer + canonicalizer            | proposals (dicts / JSON text)
 Gateway (reference monitor) + lab tool handlers| summaries / compacted memory (Phase 3)
 AgentPort identity binding                     | tool *results* and fixture text
 LogicalClock (held by scenario controller)     | any "policy"/"approval" text in context
 oracle / reference model (evaluation only)     |
```

Agent code receives exactly one capability, an `AgentPort`. Its public surface is `propose`,
`principal_id` and `session_id` (tested). The port binds identity, so proposals containing `principal_id`,
`session_id` or any other unknown field are rejected. In Phases 1 to 6 this is **in-process capability
separation**: Python name mangling and module boundaries guard against *model-mediated* misuse, not
against malicious code running in the same interpreter (ADR-0003). OS or process isolation is Phase 7/8.

## 3. Adversary capabilities (in scope)

| ID | Capability | Control | Status / tests |
|---|---|---|---|
| A1 | Inject instructions into synthetic tool output ("you now have publish rights") | Only `OperatorChannel` writes policy; tool output is data | **Tested**: `security/test_boundaries.py::test_untrusted_tool_output_claiming_authority_changes_nothing`; demo step 2 |
| A2 | Make stale or fabricated grants appear in memory and propose actions from them | Gateway evaluates the latest verified ledger at commit | **Tested**: stale proposal, `GRANT_REVOKED` (`integration/test_gateway.py`, demo) |
| A3 | Replay stale snapshots or approvals | Snapshots never authorize; approvals are epoch-bound, digest-bound, single-use, trigger-protected | **Tested**: replay, stale, expired, wrong action/principal/session, direct-SQL reuse |
| A4 | Exploit timing: a revocation races an in-flight effect | Single `BEGIN IMMEDIATE` transaction; `COMMIT` is the linearization point | **Tested**: real-thread race (`test_revocation_racing_an_in_flight_effect_is_serialized_after_it`) |
| A5 | Submit malformed or ambiguous actions (traversal, wildcards, homoglyphs, bidi, extra fields, floats, oversized args) | Strict schemas, resource and identifier validators, canonicalization rejects, 4 KiB arguments cap | **Tested**: unit validators plus 200 fuzzed proposal batches (`test_fuzzed_proposals_never_mutate_authority_or_unauthorized_state`) |
| A6 | Impersonate another principal or session | `AgentPort` binds identity; proposals cannot carry identity fields | **Tested** |
| A7 | Duplicate or concurrent requests to multiply effects | Idempotency bound to committed effects; write lock serializes | **Tested**: 4-thread concurrent duplicate, exactly 1 effect |
| A8 | Promote authority labels in memory | Labels computed by trusted code from the origin channel; an unknown source makes the entry UNTRUSTED + RESTRICTED | **Tested**: `unit/test_memory.py`, `property/test_memory_properties.py` |
| A9 | Plant forged policy statements in tool output for the agent to adopt | Quarantine of non-operator content (M5); gateway denies regardless | **Tested**: `integration/test_strategies.py`. Adoption is still possible when an agent ignores quarantine (measured: 4/4 in the pilot) |
| A10 | Tamper with the schema while a gateway connection is open (drop or replace triggers, add tables) | Schema fingerprint checked inside **every** decision transaction | **Tested**: `integration/test_review_fixes.py` |
| A11 | Insert forged decisions, effects, approvals or consumptions into evidence tables | Approval chain; evidence audit replays every decision and links every effect, consumption and idempotency row; **on signed ledgers every event and approval must carry a valid operator signature** | **Tested**: forged events or approvals (unsigned, wrong key, wrong operator, replaced signatures) are rejected by verify, the reader and the gateway. On *unsigned* ledgers a consistent forgery still passes (tested, documented) |
| A12 | Truncate the newest records or rewrite history below a known point | Signed external checkpoints of the three chain heads, stored off the host | **Tested**: truncation and rewrites below a checkpoint, a checkpoint from another ledger and tampered checkpoint contents are all detected |

## 4. Out of scope (explicit exclusions)

A compromised host, kernel or Python runtime. Malicious code in the same process. A malicious trusted operator
or admin identity. An attacker who can rewrite the entire database. Side channels. Effects outside the gateway
(none exist in the lab). All disclosure through model output text. The semantic correctness of summaries.
Model-provider visibility of prompts (synthetic data only). "Hooks alone" are not a boundary for any future
Claude Code adapter. Retained knowledge: once an allowed read has delivered content to the agent,
revocation cannot recall it (see RevBench in related work). The gateway only prevents new disclosure.

## 5. Security invariants

| ID | Invariant | Status / tests |
|---|---|---|
| SI-1 | Default deny: an unknown tool, operation, field, schema version or principal, or a missing policy, gives DENY | **Tested**: `unit/test_evaluator.py`, `integration/test_gateway.py::test_invalid_actions_fail_closed`, model tests |
| SI-2 | An applicable DENY overrides any GRANT, in either order | **Tested** |
| SI-3 | A protected effect commits only if the monitor evaluated the exact canonical action under the latest committed policy at linearization, with a valid unconsumed approval if required | **Tested**: differential test against the independent reference model (150 random programs per run), plus the race tests |
| SI-4 | No model- or tool-originated text can create, modify or revoke policy or approvals | **Tested**: fuzzing plus authority-claim tests (ledger head unchanged) |
| SI-5 | A denied request never mutates lab state; an exception rolls back fully (effect, approval, idempotency) | **Tested**: crash injection at 4 hook points; tool-error rollback |
| SI-6 | An approval is consumed at most once and becomes invalid after any epoch change | **Tested** (gateway plus DB trigger) |
| SI-7 | A broken chain, a non-canonical or malformed row, an unknown actor, an edited migration or a dropped trigger stops all effects | **Tested**: `integration/test_ledger.py`, `test_corrupted_ledger_denies_everything` |
| SI-8 | Budget pressure never truncates gateway or model-visible policy; if it cannot fit, the result is `BUDGET_EXCEEDED` | **Tested**: property test over random budgets (policy section byte-identical or error) |
| SI-9 | The benchmark oracle does not import the evaluator; agent-side code reaches the runtime only via `AgentPort` | **Tested**: static AST rules |
| SI-10 | No network or dynamic code execution in core; lab tools have no OS, time or random imports | **Tested**: static rules plus a socket guard in all tests |
| SI-11 | Evidence tables hold redacted metadata only: no arguments, no results, no secret markers | **Tested**: `test_secret_marker_never_reaches_evidence_tables` |
| SI-12 | Every decision, including fail-closed ones, is recorded in a hash chain, or the gateway raises | **Tested** |

## 6. Known limitations (tested where possible)

- **Authenticity requires a signed ledger** (ADR-0010). On signed ledgers, forging authority needs an operator's private key.
  Key secrecy is now an assumption of the TCB. Compromised keys, key rotation and key revocation are out of scope. **Unsigned** ledgers keep the
  old limitation (asserted by `test_consistent_forgery_under_registered_operator_is_NOT_caught`).
- **Truncation is detected only against a checkpoint.** Without a stored checkpoint, deleting the newest records still leaves a
  valid shorter chain.
- **The provenance benefit is conditional.** Quarantine protects only an agent that treats quoted content as data
  (ADR-0011). The pilot shows full adoption when the agent ignores the markers.

- **Tail truncation is undetectable** without an external anchor. Deleting the newest events leaves a valid
  shorter chain. This is asserted by `test_truncated_tail_is_NOT_detected_without_external_anchor`.
  Signed or external checkpoints are future work.
- **A whole-chain rewrite** by an attacker with file access is undetectable, for the same reason.
- **Old-row rewrites are detected lazily.** `PolicyReader` verifies the head and any new tail on every decision.
  Rows older than its cached head are re-verified only on a full reload or by `ananke ledger verify`.
- Triggers are application-level defense. Anyone with file access can drop them, but then the schema check
  fails (tested).
- The reference model was written by the same implementer as the evaluator. An independent review is required
  before any scientific claim (MASTERPLAN section 17).

## 7. Claims we will not make

- That a policy projection controls what the model "thinks", or that zero unauthorized *effects* shows
  that compaction improved. Those are separate endpoints.
- That an integrity hash proves truth, or that the hash chain is a signature.
- Any guarantee beyond the tested scope and the six mock operations the gateway mediates.
