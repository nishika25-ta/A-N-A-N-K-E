# ADR-0007: Reposition as a policy-transition × compaction benchmark (PROPOSED)

**Status.** Proposed. It needs an owner decision before preregistration (Phase 5). It does **not** block Phases 1 to 4.

**Context.** The Phase 0 search (research/related-work.md; secondary evidence only, as primary texts were unreachable) found prior art for every ANANKE component:
- compaction erodes rules: Compaction Cliff 2608.22752, Governance Decay 2606.22528, ARCBench (Nov 2026), Ghost in the Context 2605.12535;
- re-injecting or pinning policy: Governance Decay's Constraint Pinning;
- commit-time authorization: CommitGuard 2607.10487, CONTINUITY 2609.05269;
- authority laundering through memory: TMA-NM 2606.24322, 2609.01836;
- receipts: several IETF drafts.

**Update (second search round, same day).** Further close prior art was found: RevBench (Zenodo
23854360: mid-task revocation timing, 6 models, 6,048 runs, released code), TaskFence (commit-time
authorization in the application's DB transaction, i.e. this project's ADR-0002), Lingering Authority
(arXiv 2606.22504: interface removal vs execution invalidation), and "Revocation Is Not Complete at Receipt"
(arXiv 2610.15991). The remaining candidate gap is therefore **narrower**. It is specifically the *crossing* of
policy transitions with a *compaction schedule* at matched budgets, plus a possible
**revocation-aware compaction** mechanism that uses provenance to purge memory derived from revoked
resources. Both are unconfirmed until the primary texts are read.

**Decision (proposed).** Make the primary contribution a controlled benchmark and comparative study: policy transitions {revoke, expire, supersede or narrow, regrant} × timing relative to compaction × compaction count × matched budget. It keeps three endpoints separate: recall, proposal and committed effect. M4 is labelled a Constraint-Pinning-style baseline, and G1 a CommitGuard-style monitor (approximate reimplementations, not official). M5 is one candidate under test, and a null result is publishable.

**Alternatives.** (a) Keep the original "novel runtime" framing. This is not supportable given the prior art. (b) Pure reproduction of ARCBench or Governance Decay. This is feasible as a component, but needs their code and licenses.

**Consequences.** Build order is unchanged. The preregistration endpoints and baselines change. Primary texts must be verified, and the strongest comparator reproduced if feasible.
