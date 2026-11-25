# Known limitations (living document)

- **Prior-art review is secondary-source only** (Phase 0). arXiv and IETF hosts were unreachable from this environment. See related-work.md section 1.
- Two citations in MASTERPLAN (arXiv 2611.25673, 2610.31710) and the IETF draft `draft-durga-agent-ephemeral-lineage-01` could not be confirmed.
- Scripted agents test logic, not LLM behavior. Any claim about LLM behavior needs real-model runs (opt-in, consented).
- In-process capability separation is not OS isolation (ADR-0003).
- The hash chain gives tamper evidence against partial modification only. There is no signature or external anchor.
- Provenance labels are coarse and do not prove that summaries are semantically accurate.
- Tail truncation and whole-chain rewrites of the ledger are undetectable without an external anchor (tested limitation).
- `PolicyReader` re-verifies old rows lazily (on a full reload or `ledger verify`), not on every decision.
- The differential reference model and the evaluator share an author. An independent review is needed.
- The latency figures (p95 1.11 ms at 1,000 rules) are specific to one container and workload, and are not a general claim.
- Once content has been disclosed by an allowed read, revocation cannot recall it. The gateway prevents only new disclosure.
- Offline benchmark results come from a deterministic belief agent and a declared scripted summarizer (ADR-0011). They measure what contexts make knowable, not LLM behaviour.
- The provenance (quarantine) benefit holds only for an agent that treats quoted content as data. It vanishes otherwise (pilot: 4/4 adoption).
- In the dev pilot the budgets do not bind, and the injection family is small. Both need recalibration before preregistration.
- There is no authenticity of authority records without operator signatures (ADR-0010, proposed). Consistent forgery under a registered operator passes the audit.
