# ADR-0002: Effect linearization in a single SQLite transaction

**Context.** A revocation that commits between proposal and effect must win (TOCTOU). Prior work (CommitGuard, arXiv 2607.10487, secondary source only) frames this as commit-time authorization.

**Decision.** For mock tools, the gateway runs everything in one transaction, opened with `BEGIN IMMEDIATE` on the SQLite WAL database (a single writer). Inside it, the gateway:

1. reads the latest ledger head and verifies the chain head;
2. evaluates the canonical action;
3. checks and consumes the approval;
4. applies the mock effect;
5. appends the decision;
6. commits.

The linearization point is the `COMMIT`. Policy events also take the write lock, so the ledger and the effects are totally ordered. No network or model calls happen inside the transaction. Any exception rolls back, and the request is denied.

**Consequences.** This gives strong, testable atomicity in the lab, with throughput limited to one writer. That is acceptable for the research workload, and the p95 overhead will be measured. Remote effects would need fencing tokens and idempotency at the downstream service. Atomicity is **not** claimed for remote effects.
