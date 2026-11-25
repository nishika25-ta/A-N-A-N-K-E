# ADR-0010: Operator signatures for policy events and approvals (ACCEPTED, IMPLEMENTED)

**Status.** **Accepted by the owner** (2026-11-25, session 7) and **implemented**: `ledger/signing.py`,
`ledger/checkpoint.py`, migration 3, and `tests/integration/test_signatures.py`.

**As implemented.**
- `init_ledger(..., public_keys={op: hex})` (CLI: `ledger keygen`, `ledger init --pubkey`) creates a **signed** ledger
  (`ledger_config.signing = required`). There must be a key for every operator.
- `OperatorChannel` on a signed ledger requires the operator's private key, which must match the registered key, and signs every
  event and approval in the same transaction as the record. A key is refused on an unsigned ledger.
- Signature: Ed25519 over `ananke-sig-1\n<kind>\n<record_hash>` (domain-separated kinds: policy-event, approval,
  checkpoint), stored in the append-only `record_signatures` table.
- Fail closed on signed ledgers: `ledger verify` (`SIGNATURE_INVALID`, `APPROVAL_LOG_INVALID`), the per-decision
  `PolicyReader` (→ `POLICY_INVALID`), and the gateway's approval check (an unsigned or forged approval → `APPROVAL_INVALID`).
  A missing signing mode fails closed.
- Private keys: file created exclusively (`O_EXCL`) with mode 0600; loading refuses group- or world-readable files.
- Signed **external checkpoints** (`ledger checkpoint`, `ledger verify --checkpoint`) detect tail truncation and rewrites below the
  checkpointed heads of all three chains.
- Unsigned ledgers still work, and every report carries `authenticity: unsigned`.
- The bench runner and the demo now use signed ledgers with ephemeral keys. Decisions are unchanged (tested; the pilot
  metrics digest is reproduced on signed ledgers).
- Measured: p95 decision latency about 1.5 ms (in the noise of unsigned); signing and appending 1,000 events in one batch about 230 ms; a cold
  full verify of 1,000 signed events about 265 ms (about 65 ms unsigned).

**Not implemented (still out of scope):** key rotation or revocation of operator keys, passphrase- or hardware-protected key storage,
multi-party approval, and automatic checkpoint publication. A compromised operator key can sign anything.

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
