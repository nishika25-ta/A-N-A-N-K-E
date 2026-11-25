# CLAUDE.md: ANANKE working rules

Read `MASTERPLAN.md` (source of truth) and `STATUS.md` (current state) at the start of every session.

## Non-negotiables
- Three planes stay separate: lossy model memory, the authoritative ledger, and deterministic gateway authorization. Models and summaries never grant authority.
- Default deny; fail closed. Policy changes happen only through the operator channel.
- Synthetic local mock tools only. No real endpoints, credentials, personal data, network, shell or destructive operations.
- No paid API calls, model downloads, global installs or settings edits, push, publish or deploy without explicit owner approval.
- The benchmark oracle (`ananke/bench/oracle*`) must not import `ananke.policy`, `ananke.runtime` or `ananke.memory`.
- Never weaken tests, tune on the holdout, cherry-pick results or fabricate metrics. Report enforcement and compaction effects separately.
- Only expose CLI commands and endpoints that are implemented. No placeholders presented as features.

## Workflow
- Work one gated phase at a time. Write exit criteria before coding. Make small, tested increments.
- Checks (all must pass): `make check` = ruff check, ruff format --check, mypy (strict), pytest, selfcheck, demo-gateway.
- Security code never relies on `assert`, which is stripped under `-O`. Invariants raise explicit errors.
- Generators in property tests must be shown to be non-vacuous (measure outcome coverage; use `hypothesis.event`).
- Update `STATUS.md` at the end of every session: the exact commands and actual outputs, plus limitations and the next task.
- Record significant design choices as ADRs in `docs/decisions/`. Semantics live in `docs/policy-spec.md`.
- Ask the owner before any change to scientific scope, threat model or cost.

## Layout
`src/ananke/{domain,ledger,policy,memory,runtime,providers,lab,bench,audit,api}` (dependencies flow inward, enforced by `tests/security/test_architecture.py`; agent-side code may use only `ananke.runtime.port`). See `docs/architecture.md`. Research docs are in `research/`, specs and ADRs in `docs/`.
