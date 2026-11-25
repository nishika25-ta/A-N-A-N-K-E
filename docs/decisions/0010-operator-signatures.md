# ADR-0010: Operator signatures for policy events and approvals (PROPOSED)

**Status.** Proposed. **This is a threat-model change, so it needs an owner decision.** Not implemented.

**Context.** Session-3 review: an attacker with database write access can append chain-consistent
policy events or approvals under a *registered* operator identity, and verification plus the evidence
audit will accept them. The test `test_consistent_forgery_under_registered_operator_is_NOT_caught`
asserts this. Hash chains give tamper *evidence* against partial edits, not *authenticity*.

**Proposal.** Each operator holds an Ed25519 key outside the database (a file with 0600 permissions, or an OS keystore).
`operators` stores public keys. `OperatorChannel` signs the canonical bytes of each event and approval.
`verify`, `PolicyReader` and the audit reject unsigned or invalid signatures. External checkpoints of the
chain head, signed and stored elsewhere, would also detect tail truncation and whole-chain rewrites.

**Costs.** A new dependency (`cryptography`), key management, and per-event verification (roughly 0.1 ms
each to measure). Recovery is harder if a key is lost.

**Alternatives.** Keep the present state, with the exclusion documented (the attacker controls storage).
HMAC with a shared secret (weaker: the verifier can forge).
