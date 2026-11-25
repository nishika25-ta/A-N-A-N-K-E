# ADR-0009: Idempotency binds only committed effects; failures are recorded or raised

**Decision.**
1. An idempotency key is bound only when an effect commits. Denied and needs-approval requests do not
   consume the key, so a legitimate retry after a regrant or an approval works.
2. A repeated key with the same action digest returns `ALLOW` + `DUPLICATE_REQUEST`, `duplicate_of`,
   no effect and **no content**, even after a revocation. A repeated key with a different digest returns `IDEMPOTENCY_CONFLICT`.
3. Any exception inside the decision transaction rolls everything back, and a DENY is then recorded in a
   fresh transaction (`POLICY_INVALID` / `LEDGER_UNAVAILABLE` / `INVALID_ARGUMENTS` / `INTERNAL_ERROR`).
   If even that cannot be recorded, `GatewayUnavailableError` is raised. Errors are never swallowed.
4. Two extension reason codes, `APPROVAL_INVALID` and `INTERNAL_ERROR`, were added beyond MASTERPLAN
   section 8 to keep causes distinguishable.

**Consequences.** Effect counts for metrics must come from `lab_effects`, not from ALLOW decisions, because
duplicates are ALLOW decisions without effects.
